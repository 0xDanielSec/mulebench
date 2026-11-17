"""OpenRouter provider: routing pin, served-model check, key handling. Offline only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.model import ChatRequest, ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.openrouter import (
    KEY_ENV,
    OPENROUTER_BASE_URL,
    OpenRouterChatModel,
    OpenRouterTransport,
    RoutingMismatch,
    check_routing,
    routing,
    same_served_model,
)
from mulebench.agents.llm.transport import (
    CassetteTransport,
    FakeTransport,
    LiveCallsDisabled,
)
from mulebench.attacks import load_builtin
from mulebench.harness import run_all

MODEL = "vendor/tiny-model"
HOST = "SyntheticHost"
# Built so that this file is not itself a prepublish finding.
FAKE_KEY = "sk-or-v1-" + "ab" * 32


def body(
    model: str = MODEL, provider: str | None = HOST, cost: float | None = 0.0001
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": "gen-1",
        "model": model,
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
    }
    if provider is not None:
        out["provider"] = provider
    if cost is not None:
        out["usage"]["cost"] = cost
    return out


def request() -> ChatRequest:
    return ChatRequest(
        model=MODEL,
        system="s",
        turns=(),
        tools=(),
        max_tokens=64,
        effort="none",
        trial_key="k",
        temperature=0.7,
        seed=1,
    )


def test_every_request_pins_one_host_without_fallbacks() -> None:
    fake = FakeTransport([body()])
    OpenRouterChatModel(fake, HOST).complete(request())
    ((_, params),) = fake.requests
    assert params["provider"] == {
        "order": [HOST],
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
    }
    assert params["provider"] == routing(HOST)
    assert "models" not in params
    assert "route" not in params
    assert params["model"] == MODEL
    assert params["usage"] == {"include": True}


def test_response_records_requested_and_served_model_provider_and_cost() -> None:
    got = OpenRouterChatModel(FakeTransport([body(MODEL + "-20261101")]), HOST).complete(request())
    assert got.requested_model == MODEL
    assert got.served_model == MODEL + "-20261101"
    assert got.served_provider == HOST
    assert got.provider_cost_usd == 0.0001
    no_cost = OpenRouterChatModel(FakeTransport([body(cost=None)]), HOST).complete(request())
    assert no_cost.provider_cost_usd is None


@pytest.mark.parametrize(
    ("served", "ok"),
    [
        (MODEL, True),
        (MODEL + "-20261101", True),
        (MODEL + "-instruct", False),
        (MODEL + "-2026", False),
        ("vendor/other-model", False),
        ("", False),
    ],
)
def test_served_model_must_be_the_requested_one(served: str, ok: bool) -> None:
    assert same_served_model(MODEL, served) is ok


def test_fallback_to_another_model_or_host_stops_the_run() -> None:
    with pytest.raises(RoutingMismatch, match="served_model_mismatch"):
        check_routing(body("vendor/other-model"), MODEL, HOST)
    with pytest.raises(RoutingMismatch, match="provider_mismatch"):
        check_routing(body(provider="OtherHost"), MODEL, HOST)
    with pytest.raises(RoutingMismatch, match="provider_mismatch"):
        check_routing(body(provider=None), MODEL, HOST)
    assert check_routing(body(provider=HOST.lower()), MODEL, HOST) == (MODEL, HOST.lower())
    assert RoutingMismatch("x").run_status == "aborted_routing"


def test_error_body_with_http_200_is_a_model_call_error() -> None:
    fake = FakeTransport([{"error": {"code": 502, "message": "upstream"}}])
    with pytest.raises(ModelCallError) as info:
        OpenRouterChatModel(fake, HOST).complete(request())
    assert info.value.kind == "provider_error_502"


def test_a_routing_mismatch_aborts_the_run_with_its_own_status() -> None:
    def respond(params: dict[str, Any], trial_key: str) -> dict[str, Any]:
        return body(provider="OtherHost")

    agent = LLMAgent(
        OpenRouterChatModel(FakeTransport(respond), HOST),
        model=MODEL,
        effort="none",
        meter=CostMeter(1.0),
    )
    outcome = run_all(
        [s for s in load_builtin() if s.id == "pix-description-injection-001"],
        agent,
        prompt_variants=("baseline",),
        trials=1,
        presets=("vulnerable",),
    )
    assert outcome.status == "aborted_routing"
    assert "provider_mismatch" in (outcome.abort_reason or "")


def test_replayed_cassettes_are_checked_too(tmp_path: Path) -> None:
    model = OpenRouterChatModel(FakeTransport([body()]), HOST)
    recorder = CassetteTransport(tmp_path, "record", FakeTransport([body(provider="OtherHost")]))
    with pytest.raises(RoutingMismatch):
        OpenRouterChatModel(recorder, HOST).complete(request())
    replay = OpenRouterChatModel(CassetteTransport(tmp_path, "replay"), HOST)
    with pytest.raises(RoutingMismatch):
        replay.complete(request())
    assert model.complete(request()).served_provider == HOST


def test_transport_needs_live_remote_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    monkeypatch.setenv(KEY_ENV, FAKE_KEY)
    with pytest.raises(LiveCallsDisabled, match="MB_LIVE"):
        OpenRouterTransport(allow_remote=True)
    monkeypatch.setenv("MB_LIVE", "1")
    with pytest.raises(LiveCallsDisabled, match="--allow-remote"):
        OpenRouterTransport()
    monkeypatch.delenv(KEY_ENV)
    with pytest.raises(LiveCallsDisabled, match=KEY_ENV):
        OpenRouterTransport(allow_remote=True)


def test_key_only_in_the_header_never_in_bodies_cassettes_or_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setenv(KEY_ENV, FAKE_KEY)
    seen: list[httpx.Request] = []
    replies = [httpx.Response(200, json=body()), httpx.Response(401, text="bad key")]

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return replies[len(seen) - 1]

    client = httpx.Client(transport=httpx.MockTransport(handler))
    upstream = OpenRouterTransport(allow_remote=True, client=client)
    cassettes = CassetteTransport(tmp_path, "record", upstream)
    OpenRouterChatModel(cassettes, HOST).complete(request())
    assert str(seen[0].url) == OPENROUTER_BASE_URL + "/chat/completions"
    assert seen[0].headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert FAKE_KEY not in seen[0].content.decode()
    stored = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())
    assert FAKE_KEY not in stored
    assert json.loads(stored)["interactions"]
    with pytest.raises(ModelRequestInvalid) as info:
        upstream.send({"model": MODEL}, "k2")
    assert FAKE_KEY not in str(info.value)
