"""`mulebench doctor --provider openrouter`: is a hosted model ready for a run?

Checks, in order:
1. key: MB_OPENROUTER_API_KEY is set (presence only; the value is never shown);
2. endpoints: the model's host providers, from OpenRouter's public
   `GET /models/{id}/endpoints` (no key sent), with price per million tokens,
   quantization, context length and support for tools, seed and temperature;
3. host: the host given with --openrouter-host is listed and supports them;
4. price: the local price table has (model, host); warns if its price differs
   from the endpoint's;
5. tool calling and tool calling after a tool result: two probe chat calls,
   pinned to the host, only with MB_LIVE=1. Each response must come from the
   requested model and the pinned host.

All network calls need --allow-remote. No model text or header is printed.
"""

from __future__ import annotations

import os
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
    PROBE_MAX_TOKENS,
    PROBE_TOOL,
    Check,
    _call_check,
    _second_turn,
)

REQUIRED_PARAMETERS = ("tools", "seed", "temperature")


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
        f"{endpoint.get('provider_name')}: {price}, quantization="
        f"{endpoint.get('quantization') or '?'}, context={endpoint.get('context_length') or '?'}, "
        + ("tools/seed/temperature ok" if not missing else f"missing {', '.join(missing)}")
    )


class _CheckedTransport:
    """Live transport whose responses must come from the model and pinned host."""

    def __init__(self, inner: OpenRouterTransport, model: str, host: str) -> None:
        self.inner, self.model, self.host = inner, model, host

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        response = self.inner.send(params, trial_key)
        try:
            check_routing(response.body, self.model, self.host)
        except RoutingMismatch as exc:
            raise ModelCallError("routing", str(exc)) from None
        return response


def run_openrouter_doctor(
    model: str,
    *,
    host: str | None,
    pricing: Path,
    allow_remote: bool,
    client: httpx.Client | None = None,
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
        names = ", ".join(str(e.get("provider_name")) for e in usable)
        return [
            *checks,
            Check("warn", "host", f"none pinned; pass --openrouter-host with one of: {names}"),
        ]
    chosen = next(
        (e for e in listed if str(e.get("provider_name", "")).casefold() == host.casefold()),
        None,
    )
    if chosen is None:
        return [*checks, Check("fail", "host", f"{host!r} does not serve {model}")]
    if missing_parameters(chosen):
        return [*checks, Check("fail", "host", f"{host!r}: {describe(chosen)}")]
    checks.append(Check("ok", "host", f"{host} serves {model} with tools, seed, temperature"))
    checks.append(_price_check(model, host, chosen, pricing))
    return checks + _probes(model, host, client)


def _price_check(model: str, host: str, endpoint: dict[str, Any], pricing: Path) -> Check:
    try:
        price = load_price_table(pricing).price(model, host)
    except PriceFileError as exc:
        return Check("fail", "price", str(exc))
    if price is None:
        return Check("fail", "price", f"no entry for ({model}, {host}) in {pricing}; add it")
    listed = endpoint.get("pricing") or {}
    pin, pout = per_mtok(listed.get("prompt")), per_mtok(listed.get("completion"))
    table = (price.input_per_mtok, price.output_per_mtok)
    if pin is None or pout is None:
        return Check("warn", "price", "the endpoint lists no price; table price used")
    if abs(pin - table[0]) > 1e-9 or abs(pout - table[1]) > 1e-9:
        return Check(
            "warn",
            "price",
            f"table ${table[0]:g}/${table[1]:g} differs from endpoint ${pin:g}/${pout:g} "
            f"per 1M in/out; update {pricing}",
        )
    return Check("ok", "price", f"table matches the endpoint: ${pin:g}/${pout:g} per 1M in/out")


def _probes(model: str, host: str, client: httpx.Client) -> list[Check]:
    if os.environ.get(LIVE_ENV) != "1":
        return [Check("skip", "tool calling", f"probe needs {LIVE_ENV}=1 (two chat calls)")]
    try:
        transport = _CheckedTransport(
            OpenRouterTransport(allow_remote=True, client=client), model, host
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
        "provider": routing(host),
    }
    try:
        first = parse_completion(transport.send(params, "doctor/probe").body)
    except (ModelCallError, ModelRequestInvalid, ResponseShapeError) as exc:
        return [Check("fail", "tool calling", f"probe failed: {exc}")]
    check = _call_check("tool calling", first)
    if check.level != "ok":
        return [check]
    return [check, _second_turn(transport, params, first)]
