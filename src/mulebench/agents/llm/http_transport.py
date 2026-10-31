"""HTTP access to OpenAI-compatible local servers (needs the `local` extra: httpx).

- `check_base_url`: only loopback hosts (`localhost`, 127.0.0.0/8, ::1) unless
  `allow_remote`. The check is on the literal host; no DNS lookup.
- `OpenAICompatTransport`: chat completions. Refuses to exist unless MB_LIVE=1.
- `LocalServerClient`: non-inference metadata (version, pulled models, model
  details). Runs without MB_LIVE; loopback only unless `allow_remote`.

No API key is needed for local servers. An optional key is read from
MB_OPENAI_COMPAT_API_KEY. Request headers are never logged, stored or put into
error messages; cassettes hold bodies only.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from mulebench.agents.base import ServerMeta
from mulebench.agents.llm.model import ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.transport import LIVE_ENV, LiveCallsDisabled, TransportResponse

DEFAULT_BASE_URL = "http://localhost:11434/v1"
API_KEY_ENV = "MB_OPENAI_COMPAT_API_KEY"
DEFAULT_TIMEOUT_S = 300.0  # local models on modest hardware are slow
_ERROR_EXCERPT = 200


class RemoteHostRefused(ValueError):
    pass


def check_base_url(base_url: str, *, allow_remote: bool = False) -> str:
    """Return the normalized base URL, or raise RemoteHostRefused / ValueError."""
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"base URL must be http(s)://host[:port]/path, got {base_url!r}")
    if not allow_remote and not is_loopback(parts.hostname):
        raise RemoteHostRefused(
            f"refusing non-local host {parts.hostname!r}; pass --allow-remote to use it"
        )
    return base_url.rstrip("/")


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def server_root(base_url: str) -> str:
    """Ollama's native API lives next to /v1, at the server root."""
    return re.sub(r"/v1$", "", base_url.rstrip("/"))


def _headers() -> dict[str, str]:
    key = os.environ.get(API_KEY_ENV)
    return {"Authorization": f"Bearer {key}"} if key else {}


def _excerpt(response: httpx.Response) -> str:
    return response.text[:_ERROR_EXCERPT].replace("\n", " ")


class OpenAICompatTransport:
    """POST {base_url}/chat/completions. Only when MB_LIVE=1."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        allow_remote: bool = False,
        client: httpx.Client | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if os.environ.get(LIVE_ENV) != "1":
            raise LiveCallsDisabled(f"live calls need {LIVE_ENV}=1")
        self.base_url = check_base_url(base_url, allow_remote=allow_remote)
        self._client = client or httpx.Client(timeout=timeout_s)

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        try:
            response = self._client.post(
                f"{self.base_url}/chat/completions", json=params, headers=_headers()
            )
        except httpx.TimeoutException:
            raise ModelCallError("timeout", "request timed out") from None
        except httpx.TransportError as exc:
            raise ModelCallError("connection", type(exc).__name__) from None
        status = response.status_code
        if status == 429 or status >= 500:
            raise ModelCallError(f"http_{status}", _excerpt(response))
        if status >= 400:
            raise ModelRequestInvalid(f"HTTP {status}: {_excerpt(response)}")
        try:
            body = response.json()
        except ValueError:
            raise ModelCallError("bad_body", "response is not JSON") from None
        if not isinstance(body, dict):
            raise ModelCallError("bad_body", "response is not a JSON object")
        return TransportResponse(body=body, request_id=body.get("id"))


class ServerUnreachable(RuntimeError):
    pass


class LocalServerClient:
    """Non-inference metadata calls. Ollama endpoints first, /v1 as fallback."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        allow_remote: bool = False,
        client: httpx.Client | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.base_url = check_base_url(base_url, allow_remote=allow_remote)
        self.root = server_root(self.base_url)
        self._client = client or httpx.Client(timeout=timeout_s)

    def _get(self, url: str) -> object:
        return self._request("GET", url, None)

    def _request(self, method: str, url: str, body: dict[str, Any] | None) -> object:
        try:
            response = self._client.request(method, url, json=body, headers=_headers())
        except httpx.TransportError as exc:
            raise ServerUnreachable(f"{url}: {type(exc).__name__}") from None
        if response.status_code >= 400:
            return None
        try:
            data: object = response.json()
        except ValueError:
            return None
        return data

    def version(self) -> str | None:
        """Ollama version, or None for other servers. Raises ServerUnreachable."""
        data = self._get(f"{self.root}/api/version")
        if isinstance(data, dict) and isinstance(data.get("version"), str):
            return str(data["version"])
        if self._get(f"{self.base_url}/models") is None:
            raise ServerUnreachable(f"{self.base_url}: no Ollama or /v1 API answered")
        return None

    def models(self) -> list[str]:
        tags = _entries(self._get(f"{self.root}/api/tags"), "models")
        if tags:
            return sorted(str(m.get("name")) for m in tags)
        return sorted(
            str(m.get("id")) for m in _entries(self._get(f"{self.base_url}/models"), "data")
        )

    def server_meta(self, model: str) -> ServerMeta:
        version = self.version()
        show = self._request("POST", f"{self.root}/api/show", {"model": model})
        digest = quant = None
        num_ctx = context_length = None
        source = None
        if isinstance(show, dict):
            details = show.get("details") or {}
            quant = details.get("quantization_level")
            num_ctx = _num_ctx_from_parameters(show.get("parameters"))
            source = "parameters" if num_ctx is not None else None
            info = show.get("model_info") or {}
            context_length = next(
                (int(v) for k, v in info.items() if k.endswith(".context_length")), None
            )
        if isinstance(show, dict) and isinstance(show.get("digest"), str):
            digest = show["digest"]
        if digest is None:  # /api/show usually has none: fall back to /api/tags
            for m in _entries(self._get(f"{self.root}/api/tags"), "models"):
                if same_model(m, model) and isinstance(m.get("digest"), str):
                    digest = m["digest"]
                    break
        if num_ctx is None:
            for m in _entries(self._get(f"{self.root}/api/ps"), "models"):
                if same_model(m, model) and m.get("context_length"):
                    num_ctx, source = int(m["context_length"]), "ps"
        return ServerMeta(
            model=model,
            digest=digest,
            quantization=quant,
            server_version=version,
            num_ctx=num_ctx,
            num_ctx_source=source,
            context_length=context_length,
        )


def same_model(entry: dict[str, Any], model: str) -> bool:
    """Ollama lists `ollama create my-model` (no tag) as `my-model:latest`."""
    names = {entry.get("name"), entry.get("model")}
    wanted = {model} if ":" in model else {model, f"{model}:latest"}
    return bool(names & wanted)


def _entries(data: object, key: str) -> list[dict[str, Any]]:
    """The object entries of `data[key]`, or [] for any other shape."""
    items = data.get(key) if isinstance(data, dict) else None
    return [m for m in items if isinstance(m, dict)] if isinstance(items, list) else []


def _num_ctx_from_parameters(parameters: object) -> int | None:
    if not isinstance(parameters, str):
        return None
    match = re.search(r"^\s*num_ctx\s+(\d+)\s*$", parameters, re.MULTILINE)
    return int(match.group(1)) if match else None
