"""`mulebench doctor --provider openrouter`: is a hosted model ready for a run?

Checks, in order:
1. key: MB_OPENROUTER_API_KEY is set (presence only; the value is never shown);
2. endpoints: the model's host providers, from OpenRouter's public
   `GET /models/{id}/endpoints` (no key sent), with price per million tokens,
   quantization, context length and support for tools, seed and temperature;
3. host: the eligible endpoints of --openrouter-host (with the quantization of
   --openrouter-quantization, if given): those with tools, seed and
   temperature, the only ones require_parameters lets serve. A host may list
   several; any of them may serve, so each must have a context of at least
   MIN_CONTEXT tokens, and eligible endpoints in more than one quantization
   need --openrouter-quantization;
4. price: the local price table has (model, host) at no less than the highest
   price of the eligible endpoints (the cap must never underestimate);
5. tool calling and tool calling after a tool result: two probe chat calls,
   pinned to the host (and quantization), only with MB_LIVE=1. Each response must
   come from the requested model and the pinned host, and must not report another
   quantization; the quantization the responses report is shown (warn if none).

All network calls need --allow-remote. No model text or header is printed.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from mulebench.agents.llm.model import ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.openai_compat import ResponseShapeError, parse_completion
from mulebench.agents.llm.openrouter import (
    KEY_ENV,
    OPENROUTER_BASE_URL,
    OpenRouterTransport,
    RoutingMismatch,
    check_routing,
    routing,
)
from mulebench.agents.llm.pricing_file import PriceFileError, load_price_table
from mulebench.agents.llm.transport import LIVE_ENV, LiveCallsDisabled, TransportResponse
from mulebench.doctor import (
    MIN_NUM_CTX,
    PROBE_MAX_TOKENS,
    PROBE_TOOL,
    Check,
    _call_check,
    _second_turn,
)

REQUIRED_PARAMETERS = ("tools", "seed", "temperature")
# Prompt of the largest pilot call (about 1.2k tokens) plus max_tokens 4096 fits.
MIN_CONTEXT = MIN_NUM_CTX


def endpoints(model: str, client: httpx.Client) -> list[dict[str, Any]] | None:
    """The model's endpoints, or None if OpenRouter does not know the model."""
    url = f"{OPENROUTER_BASE_URL}/models/{quote(model, safe='/')}/endpoints"
    try:
        response = client.get(url)
    except httpx.TransportError as exc:
        raise ModelCallError("connection", type(exc).__name__) from None
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        raise ModelCallError(f"http_{response.status_code}", "endpoint listing failed")
    data = response.json().get("data") if isinstance(response.json(), dict) else None
    items = data.get("endpoints") if isinstance(data, dict) else None
    return [e for e in items if isinstance(e, dict)] if isinstance(items, list) else None


def per_mtok(value: object) -> float | None:
    try:
        return float(str(value)) * 1_000_000
    except ValueError:
        return None


def missing_parameters(endpoint: dict[str, Any]) -> list[str]:
    supported = set(endpoint.get("supported_parameters") or [])
    return [p for p in REQUIRED_PARAMETERS if p not in supported]


def describe(endpoint: dict[str, Any]) -> str:
    pricing = endpoint.get("pricing") or {}
    pin, pout = per_mtok(pricing.get("prompt")), per_mtok(pricing.get("completion"))
    price = "?" if pin is None or pout is None else f"${pin:.3f}/${pout:.3f} per 1M in/out"
    missing = missing_parameters(endpoint)
    return (
        f"{_tag(endpoint)} ({endpoint.get('provider_name')}): {price}, quantization="
        f"{endpoint.get('quantization') or '?'}, context={endpoint.get('context_length') or '?'}, "
        + ("tools/seed/temperature ok" if not missing else f"missing {', '.join(missing)}")
    )


class _CheckedTransport:
    """Live transport whose responses must come from the pinned model, host and
    quantization. Keeps the quantization each response reported (None if none)."""

    def __init__(
        self, inner: OpenRouterTransport, model: str, host: str, quantization: str | None
    ) -> None:
        self.inner, self.model, self.host, self.quantization = inner, model, host, quantization
        self.served_quantizations: list[str | None] = []

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        response = self.inner.send(params, trial_key)
        try:
            _, _, quant = check_routing(response.body, self.model, self.host, self.quantization)
        except RoutingMismatch as exc:
            raise ModelCallError("routing", str(exc)) from None
        self.served_quantizations.append(quant)
        return response


def same_quantization(endpoint: dict[str, Any], quantization: str) -> bool:
    return str(endpoint.get("quantization") or "").casefold() == quantization.casefold()


def run_openrouter_doctor(
    model: str,
    *,
    host: str | None,
    pricing: Path,
    allow_remote: bool,
    quantization: str | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Check]:
    if not allow_remote:
        return [Check("fail", "remote", "openrouter is a remote host: pass --allow-remote")]
    client = client or httpx.Client(timeout=120.0)
    has_key = bool(os.environ.get(KEY_ENV))
    checks = [
        Check(
            "ok" if has_key else "fail",
            "key",
            f"{KEY_ENV} is set" if has_key else f"{KEY_ENV} is not set",
        )
    ]
    try:
        listed = endpoints(model, client)
    except (ModelCallError, ValueError) as exc:
        return [*checks, Check("fail", "endpoints", f"listing failed: {exc}")]
    if not listed:
        return [*checks, Check("fail", "endpoints", f"{model!r} is not available on OpenRouter")]
    usable = [e for e in listed if not missing_parameters(e)]
    checks += [Check("ok" if e in usable else "warn", "endpoint", describe(e)) for e in listed]
    if not usable:
        return [*checks, Check("fail", "endpoints", "no host supports tools, seed and temperature")]

    if not host:
        names = ", ".join(sorted({str(e.get("provider_name")) for e in usable}))
        return [
            *checks,
            Check("warn", "host", f"none pinned; pass --openrouter-host with one of: {names}"),
        ]
    at_host = [e for e in listed if str(e.get("provider_name", "")).casefold() == host.casefold()]
    if not at_host:
        return [*checks, Check("fail", "host", f"{host!r} does not serve {model}")]
    candidates = (
        [e for e in at_host if same_quantization(e, quantization)] if quantization else at_host
    )
    if not candidates:
        return [
            *checks,
            Check("fail", "host", f"{host!r} lists no {quantization} endpoint of {model}"),
        ]
    # What require_parameters enforces: only these endpoints can serve a request.
    eligible = [e for e in candidates if not missing_parameters(e)]
    if not eligible:
        return [
            *checks,
            Check("fail", "host", f"{host!r}: no endpoint with tools, seed and temperature"),
        ]
    quants = sorted({str(e.get("quantization") or "?") for e in eligible})
    if not quantization and len(quants) > 1:
        return [
            *checks,
            Check(
                "fail",
                "host",
                f"{host!r} serves {model} in {', '.join(quants)}; "
                "pin one with --openrouter-quantization",
            ),
        ]
    short = [
        e
        for e in eligible
        if isinstance(e.get("context_length"), int) and e["context_length"] < MIN_CONTEXT
    ]
    if short:
        return [
            *checks,
            Check(
                "fail",
                "host",
                f"{len(short)} eligible endpoint(s) have context below {MIN_CONTEXT} tokens "
                f"(prompt plus max_tokens of a trial): {', '.join(_tag(e) for e in short)}",
            ),
        ]
    pinned = f" {quantization}" if quantization else ""
    checks.append(
        Check(
            "ok",
            "host",
            f"{len(eligible)} eligible {host}{pinned} endpoint(s) with tools, seed and "
            f"temperature ({', '.join(_tag(e) for e in eligible)}); any of them may serve",
        )
    )
    checks.append(_price_check(model, host, eligible, pricing))
    return checks + _probes(model, host, quantization, client, sleep)


def _tag(endpoint: dict[str, Any]) -> str:
    return str(endpoint.get("tag") or endpoint.get("name") or endpoint.get("provider_name"))


def _price_check(model: str, host: str, eligible: list[dict[str, Any]], pricing: Path) -> Check:
    """The table price must be at least the highest price of every endpoint that
    may serve the run, so the cost cap never underestimates."""
    try:
        price = load_price_table(pricing).price(model, host)
    except PriceFileError as exc:
        return Check("fail", "price", str(exc))
    if price is None:
        return Check("fail", "price", f"no entry for ({model}, {host}) in {pricing}; add it")
    listed = [
        (
            per_mtok((e.get("pricing") or {}).get("prompt")),
            per_mtok((e.get("pricing") or {}).get("completion")),
        )
        for e in eligible
    ]
    if any(pin is None or pout is None for pin, pout in listed):
        return Check("fail", "price", "an eligible endpoint lists no price")
    top_in = max(p[0] for p in listed if p[0] is not None)
    top_out = max(p[1] for p in listed if p[1] is not None)
    tin, tout = price.input_per_mtok, price.output_per_mtok
    if tin + 1e-9 < top_in or tout + 1e-9 < top_out:
        return Check(
            "fail",
            "price",
            f"table ${tin:g}/${tout:g} is below the highest eligible endpoint price "
            f"${top_in:.6g}/${top_out:.6g} per 1M in/out: the cost cap would underestimate; "
            f"update {pricing}",
        )
    return Check(
        "ok",
        "price",
        f"table ${tin:g}/${tout:g} >= highest eligible endpoint price "
        f"${top_in:.6g}/${top_out:.6g} per 1M in/out",
    )


def _probes(
    model: str,
    host: str,
    quantization: str | None,
    client: httpx.Client,
    sleep: Callable[[float], None],
) -> list[Check]:
    """Probe calls retry 429 and 5xx like run calls (retry.py) before failing."""
    if os.environ.get(LIVE_ENV) != "1":
        return [Check("skip", "tool calling", f"probe needs {LIVE_ENV}=1 (two chat calls)")]
    try:
        transport = _CheckedTransport(
            OpenRouterTransport(allow_remote=True, client=client, sleep=sleep),
            model,
            host,
            quantization,
        )
    except LiveCallsDisabled as exc:  # missing key
        return [Check("fail", "tool calling", str(exc))]
    params: dict[str, object] = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a health check. Use the ping tool."},
            {
                "role": "user",
                "content": "Call ping with token 'mb-probe'. When you get its result, "
                "call ping again with token 'mb-probe-2'.",
            },
        ],
        "tools": [PROBE_TOOL],
        "tool_choice": "auto",
        "temperature": 0.0,
        "seed": 0,
        "max_tokens": PROBE_MAX_TOKENS,
        "stream": False,
        "provider": routing(host, quantization),
    }
    try:
        first = parse_completion(transport.send(params, "doctor/probe").body)
    except (ModelCallError, ModelRequestInvalid, ResponseShapeError) as exc:
        return [Check("fail", "tool calling", f"probe failed: {exc}")]
    check = _call_check("tool calling", first)
    if check.level != "ok":
        return [check]
    checks = [check, _second_turn(transport, params, first)]
    return [*checks, _served_quantization_check(transport.served_quantizations, quantization)]


def _served_quantization_check(served: list[str | None], pinned: str | None) -> Check:
    reported = sorted({q for q in served if q is not None})
    if not reported:
        return Check(
            "warn",
            "served quantization",
            "the responses report no quantization: it cannot be checked per call; "
            "only the request pin" + (f" ({pinned})" if pinned else "") + " applies",
        )
    return Check("ok", "served quantization", ", ".join(reported))
