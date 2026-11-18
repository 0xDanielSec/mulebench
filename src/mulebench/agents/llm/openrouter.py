"""OpenRouter: hosted models through the OpenAI-compatible adapter.

- Base URL fixed to OPENROUTER_BASE_URL; live calls need MB_LIVE=1, the
  explicit `allow_remote` (CLI `--allow-remote`) and MB_OPENROUTER_API_KEY.
- The key goes only into the Authorization header. Headers are never logged,
  stored or put into error messages; cassettes hold bodies only.
- Routing is pinned on every request: one host provider (`order: [P]`), and
  optionally one quantization (`quantizations: [Q]`, since one host can list
  several endpoints of a model), no fallbacks, only endpoints that accept
  every parameter sent, no data collection. No `models` list is sent, so
  OpenRouter cannot switch model.
- Every response (live or replayed) must name the requested model and the
  pinned provider, and must not report another quantization. Anything else
  stops the whole run (RoutingMismatch): a silent fallback would change the
  system under test.
- The served model and provider, and OpenRouter's own `usage.cost` when
  present, are kept on each model call record. Cost caps use the local price
  table (pricing_file.py), not `usage.cost`.
"""

from __future__ import annotations

import os
import random
import re
import time
from collections.abc import Callable
from typing import Any

import httpx

from mulebench.agents.base import RunAborted
from mulebench.agents.llm.http_transport import OpenAICompatTransport
from mulebench.agents.llm.model import (
    ChatRequest,
    ChatResponse,
    ModelCallError,
    ModelRequestInvalid,
)
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel, parse_completion
from mulebench.agents.llm.retry import RetryPolicy, exhausted_kind, is_transient
from mulebench.agents.llm.transport import (
    LIVE_ENV,
    LiveCallsDisabled,
    Transport,
    TransportResponse,
)

PROVIDER = "openrouter"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
KEY_ENV = "MB_OPENROUTER_API_KEY"
DEFAULT_TIMEOUT_S = 120.0
# OpenRouter canonical slugs append a release date: "<id>-YYYYMMDD".
_DATED = re.compile(r"-\d{8}$")


class RoutingMismatch(RunAborted):
    """A response came from another model or host provider than the pinned one."""

    run_status = "aborted_routing"


def routing(host: str, quantization: str | None = None) -> dict[str, Any]:
    """The provider-routing block sent with every request.

    One host may list several endpoints of a model (different quantization,
    price and capabilities); `quantization` narrows routing to that endpoint.
    """
    block: dict[str, Any] = {
        "order": [host],
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
    }
    if quantization:
        block["quantizations"] = [quantization]
    return block


def served_quantization(body: dict[str, Any]) -> str | None:
    """The quantization a response reports for its endpoint, if any."""
    value = body.get("quantization")
    return value if isinstance(value, str) and value else None


def same_served_model(requested: str, served: str) -> bool:
    """Exactly the requested id, or its dated canonical slug."""
    return served == requested or (
        served.startswith(requested) and bool(_DATED.fullmatch(served[len(requested) :]))
    )


def check_routing(
    body: dict[str, Any], requested: str, host: str, quantization: str | None = None
) -> tuple[str, str, str | None]:
    """(served model, served provider, served quantization or None).

    Raises RoutingMismatch for another model, another host, or a reported
    quantization other than the pinned one. A response that reports no
    quantization is accepted (recorded as None): the request pin is then
    the only guarantee, and `doctor` says so.
    """
    served = str(body.get("model") or "")
    provider = str(body.get("provider") or "")
    if not same_served_model(requested, served):
        raise RoutingMismatch(
            f"served_model_mismatch: requested {requested!r}, served {served or 'none'!r}"
        )
    if provider.casefold() != host.casefold():
        raise RoutingMismatch(
            f"provider_mismatch: pinned {host!r}, served by {provider or 'none'!r}"
        )
    quant = served_quantization(body)
    if quantization and quant is not None and quant.casefold() != quantization.casefold():
        raise RoutingMismatch(f"quantization_mismatch: pinned {quantization!r}, served {quant!r}")
    return served, provider, quant


class OpenRouterChatModel(OpenAICompatChatModel):
    """`send_seed` / `send_temperature` False (CLI `--allow-no-seed`,
    `--allow-no-temperature`) leave that field out of every request, for hosts
    whose endpoints do not accept it (require_parameters would otherwise find no
    endpoint). The defaults send both, so requests are unchanged."""

    provider = PROVIDER

    def __init__(
        self,
        transport: Transport,
        host: str,
        quantization: str | None = None,
        *,
        send_seed: bool = True,
        send_temperature: bool = True,
    ) -> None:
        super().__init__(transport, None)
        if not host:
            raise ValueError("openrouter needs a pinned host provider")
        self.host = host
        self.quantization = quantization
        self.send_seed = send_seed
        self.send_temperature = send_temperature

    def build_params(self, request: ChatRequest) -> dict[str, Any]:
        params = super().build_params(request)
        if not self.send_seed:
            params.pop("seed", None)
        if not self.send_temperature:
            params.pop("temperature", None)
        params["provider"] = routing(self.host, self.quantization)
        params["usage"] = {"include": True}  # OpenRouter reports usage.cost
        return params

    def complete(self, request: ChatRequest) -> ChatResponse:
        response = self.transport.send(self.build_params(request), request.trial_key)
        body = response.body
        error = body.get("error")
        if error is not None:  # OpenRouter can return an error with HTTP 200
            code = error.get("code") if isinstance(error, dict) else None
            raise ModelCallError(f"provider_error_{code or 'unknown'}", "error body")
        served, provider, quant = check_routing(body, request.model, self.host, self.quantization)
        parsed = parse_completion(body, response.request_id)
        cost = (body.get("usage") or {}).get("cost")
        return parsed.model_copy(
            update={
                "served_model": served,
                "served_provider": provider,
                "served_quantization": quant,
                "requested_model": request.model,
                "provider_cost_usd": float(cost) if isinstance(cost, int | float) else None,
                "retries": response.retries,
            }
        )


def _effective_status(response: httpx.Response) -> int:
    """The HTTP status, or the code of an error body sent with HTTP 200
    (OpenRouter reports some upstream failures that way)."""
    if response.status_code != 200:
        return response.status_code
    try:
        body = response.json()
    except ValueError:
        return 200
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, int) and is_transient(code) else 200


class OpenRouterTransport(OpenAICompatTransport):
    """POST https://openrouter.ai/api/v1/chat/completions with the key header.

    HTTP 429 and 5xx are retried with the same body (retry.py); the number of
    retries is returned with the response and stored in the cassette.
    """

    def __init__(
        self,
        *,
        allow_remote: bool = False,
        client: httpx.Client | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if os.environ.get(LIVE_ENV) != "1":
            raise LiveCallsDisabled(f"live calls need {LIVE_ENV}=1")
        if not allow_remote:
            raise LiveCallsDisabled("openrouter is a remote host: pass --allow-remote")
        if not os.environ.get(KEY_ENV):
            raise LiveCallsDisabled(f"openrouter needs {KEY_ENV} set")
        super().__init__(OPENROUTER_BASE_URL, allow_remote=True, client=client, timeout_s=timeout_s)
        self.policy = policy or RetryPolicy()
        self._sleep = sleep
        # jitter only; never touches the request
        self._rng = rng or random.Random()  # noqa: S311 - not security sensitive

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {os.environ.get(KEY_ENV, '')}"}

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        url = f"{self.base_url}/chat/completions"
        for attempt in range(1, self.policy.max_attempts + 1):
            try:
                response = self._client.post(url, json=params, headers=self.headers())
            except httpx.TimeoutException:
                raise ModelCallError("timeout", "request timed out") from None
            except httpx.TransportError as exc:
                raise ModelCallError("connection", type(exc).__name__) from None
            status = _effective_status(response)
            if is_transient(status):
                if attempt == self.policy.max_attempts:
                    raise ModelCallError(
                        exhausted_kind(status),
                        f"HTTP {status} after {attempt} attempts",
                    )
                self._sleep(
                    self.policy.delay(attempt, response.headers.get("retry-after"), self._rng)
                )
                continue
            if status >= 400:
                raise ModelRequestInvalid(f"HTTP {status}: {response.text[:200]}")
            try:
                body = response.json()
            except ValueError:
                raise ModelCallError("bad_body", "response is not JSON") from None
            if not isinstance(body, dict):
                raise ModelCallError("bad_body", "response is not a JSON object")
            return TransportResponse(body=body, request_id=body.get("id"), retries=attempt - 1)
        raise AssertionError("unreachable")  # pragma: no cover
