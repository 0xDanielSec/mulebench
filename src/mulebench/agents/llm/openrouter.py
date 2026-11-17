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
import re
from typing import Any

import httpx

from mulebench.agents.base import RunAborted
from mulebench.agents.llm.http_transport import OpenAICompatTransport
from mulebench.agents.llm.model import ChatRequest, ChatResponse, ModelCallError
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel, parse_completion
from mulebench.agents.llm.transport import LIVE_ENV, LiveCallsDisabled, Transport

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
    provider = PROVIDER

    def __init__(self, transport: Transport, host: str, quantization: str | None = None) -> None:
        super().__init__(transport, None)
        if not host:
            raise ValueError("openrouter needs a pinned host provider")
        self.host = host
        self.quantization = quantization

    def build_params(self, request: ChatRequest) -> dict[str, Any]:
        params = super().build_params(request)
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
            }
        )


class OpenRouterTransport(OpenAICompatTransport):
    """POST https://openrouter.ai/api/v1/chat/completions with the key header."""

    def __init__(
        self,
        *,
        allow_remote: bool = False,
        client: httpx.Client | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if os.environ.get(LIVE_ENV) != "1":
            raise LiveCallsDisabled(f"live calls need {LIVE_ENV}=1")
        if not allow_remote:
            raise LiveCallsDisabled("openrouter is a remote host: pass --allow-remote")
        if not os.environ.get(KEY_ENV):
            raise LiveCallsDisabled(f"openrouter needs {KEY_ENV} set")
        super().__init__(OPENROUTER_BASE_URL, allow_remote=True, client=client, timeout_s=timeout_s)

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {os.environ.get(KEY_ENV, '')}"}
