"""Transports: how a provider request body becomes a response body.

- FakeTransport: scripted responses for unit tests.
- CassetteTransport: replay (default) or record recorded request/response bodies.
- LiveTransport: real Anthropic API calls; only when MB_LIVE=1 and
  ANTHROPIC_API_KEY are set. The key is read by the SDK from the environment and
  is never passed, stored or logged here. Cassettes hold bodies only, no headers.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from mulebench.agents.llm.model import ModelCallError, ModelRequestInvalid

LIVE_ENV = "MB_LIVE"
KEY_ENV = "ANTHROPIC_API_KEY"


class TransportResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    body: dict[str, Any]
    request_id: str | None = None


class Transport(Protocol):
    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse: ...


def canonical(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_sha(params: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(params).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------- fake


class FakeTransport:
    """Returns responses from a callable (or a list, in order). Records requests."""

    def __init__(
        self,
        responses: list[dict[str, Any]] | Callable[[dict[str, Any], str], dict[str, Any]],
    ) -> None:
        self._responses = responses
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        self.requests.append((trial_key, params))
        if callable(self._responses):
            body = self._responses(params, trial_key)
        else:
            body = self._responses[len(self.requests) - 1]
        return TransportResponse(body=body, request_id=f"req_fake_{len(self.requests):04d}")


# --------------------------------------------------------------- cassette


class CassetteMissing(LookupError):
    def __init__(self, trial_key: str, path: Path) -> None:
        super().__init__(
            f"no recorded response for trial {trial_key!r} in {path}; record it with "
            "--record (requires MB_LIVE=1, ANTHROPIC_API_KEY and --max-cost-usd)"
        )
        self.trial_key = trial_key


def cassette_path(directory: Path, trial_key: str) -> Path:
    digest = hashlib.sha256(trial_key.encode("utf-8")).hexdigest()[:16]
    return directory / f"{digest}.json"


class CassetteTransport:
    """One JSON file per trial: {"trial_key", "interactions": [...]}.

    Each interaction stores the request body, its sha256, the response body and
    the request id. Replay matches on the request sha256 within the trial.
    """

    def __init__(
        self,
        directory: Path,
        mode: Literal["replay", "record"] = "replay",
        upstream: Transport | None = None,
    ) -> None:
        if mode == "record" and upstream is None:
            raise ValueError("record mode needs an upstream transport")
        self.directory = directory
        self.mode = mode
        self.upstream = upstream

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        path = cassette_path(self.directory, trial_key)
        sha = request_sha(params)
        cassette = _read(path, trial_key)
        for entry in cassette["interactions"]:
            if entry["request_sha256"] == sha:
                return TransportResponse(body=entry["response"], request_id=entry["request_id"])
        if self.mode == "replay" or self.upstream is None:
            raise CassetteMissing(trial_key, path)
        response = self.upstream.send(params, trial_key)
        cassette["interactions"].append(
            {
                "request_sha256": sha,
                "request": params,
                "response": response.body,
                "request_id": response.request_id,
            }
        )
        self.directory.mkdir(parents=True, exist_ok=True)
        path.write_bytes((json.dumps(cassette, indent=2, ensure_ascii=False) + "\n").encode())
        return response


def _read(path: Path, trial_key: str) -> dict[str, Any]:
    if not path.exists():
        return {"trial_key": trial_key, "interactions": []}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


# ------------------------------------------------------------------- live


class LiveCallsDisabled(RuntimeError):
    pass


def live_calls_enabled() -> bool:
    return os.environ.get(LIVE_ENV) == "1" and bool(os.environ.get(KEY_ENV))


class LiveTransport:
    """Real Anthropic Messages API calls. Refuses to exist unless explicitly enabled."""

    def __init__(self, max_retries: int = 2) -> None:
        if not live_calls_enabled():
            raise LiveCallsDisabled(f"live calls need {LIVE_ENV}=1 and {KEY_ENV} set")
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on install
            raise LiveCallsDisabled("install the llm extra: pip install mulebench[llm]") from exc
        self._anthropic = anthropic
        # The SDK reads the key from the environment; it is never handled here.
        self._client = anthropic.Anthropic(max_retries=max_retries)

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        a = self._anthropic
        try:
            message = self._client.messages.create(**params)
        except (a.BadRequestError, a.AuthenticationError, a.PermissionDeniedError) as exc:
            raise ModelRequestInvalid(f"{type(exc).__name__}: {exc.message}") from None
        except a.NotFoundError as exc:
            raise ModelRequestInvalid(f"NotFoundError: {exc.message}") from None
        except a.RateLimitError as exc:
            raise ModelCallError("rate_limit", exc.message, _req_id(exc)) from None
        except a.APIStatusError as exc:
            raise ModelCallError(f"http_{exc.status_code}", exc.message, _req_id(exc)) from None
        except a.APIConnectionError as exc:
            raise ModelCallError("connection", str(exc)) from None
        return TransportResponse(body=message.to_dict(), request_id=message._request_id)


def _req_id(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    return None if headers is None else headers.get("request-id")
