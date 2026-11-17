"""OpenRouter retries on HTTP 429 / 5xx: same body, backoff, Retry-After, exhaustion,
cassettes, run-level effects and doctor probes. Offline; sleeps are recorded, not slept."""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.model import ModelCallError
from mulebench.agents.llm.openrouter import OpenRouterChatModel, OpenRouterTransport
from mulebench.agents.llm.retry import RetryPolicy, parse_retry_after
from mulebench.agents.llm.transport import CassetteTransport, FakeTransport
from mulebench.attacks import load_builtin
from mulebench.doctor_openrouter import run_openrouter_doctor
from mulebench.harness import run_all
from mulebench.reports import build_report

MODEL = "vendor/tiny-model"
HOST = "SyntheticHost"


def ok_body(content: str = "done") -> dict[str, Any]:
    return {
        "id": "gen",
        "model": MODEL,
        "provider": HOST,
        "choices": [
            {"finish_reason": "stop", "message": {"role": "assistant", "content": content}}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setenv("MB_OPENROUTER_API_KEY", "placeholder")


def transport(
    replies: list[httpx.Response], sleeps: list[float], seen: list[bytes] | None = None
) -> OpenRouterTransport:
    queue = list(replies)

    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(req.content)
        return queue.pop(0)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OpenRouterTransport(
        allow_remote=True,
        client=client,
        sleep=sleeps.append,
        rng=random.Random(0),  # noqa: S311
    )


PARAMS = {"model": MODEL, "seed": 1234, "messages": [{"role": "user", "content": "x"}]}


def test_429_and_5xx_are_retried_with_the_same_body() -> None:
    sleeps: list[float] = []
    seen: list[bytes] = []
    t = transport(
        [httpx.Response(429), httpx.Response(503), httpx.Response(200, json=ok_body())],
        sleeps,
        seen,
    )
    got = t.send(PARAMS, "k")
    assert got.retries == 2
    assert len(seen) == 3
    assert len(set(seen)) == 1  # identical bodies: seed and messages unchanged
    assert json.loads(seen[0])["seed"] == 1234
    assert len(sleeps) == 2
    assert 7.5 <= sleeps[0] <= 15.0  # equal jitter on base 15 s
    assert 15.0 <= sleeps[1] <= 30.0


def test_retry_after_is_honoured_and_capped() -> None:
    sleeps: list[float] = []
    t = transport(
        [
            httpx.Response(429, headers={"Retry-After": "42"}),
            httpx.Response(429, headers={"Retry-After": "9999"}),
            httpx.Response(200, json=ok_body()),
        ],
        sleeps,
    )
    assert t.send(PARAMS, "k").retries == 2
    assert sleeps == [42.0, 300.0]
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
    assert parse_retry_after("Tue, 17 Nov 2026 12:00:30 GMT", now) == 30.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None


def test_error_body_with_http_200_and_transient_code_is_retried() -> None:
    sleeps: list[float] = []
    rate_limited = {"error": {"code": 429, "message": "temporarily rate-limited upstream"}}
    t = transport(
        [httpx.Response(200, json=rate_limited), httpx.Response(200, json=ok_body())], sleeps
    )
    assert t.send(PARAMS, "k").retries == 1


@pytest.mark.parametrize(
    ("status", "kind"), [(429, "provider_rate_limited"), (502, "provider_unavailable")]
)
def test_exhausted_retries_fail_with_their_kind(status: int, kind: str) -> None:
    sleeps: list[float] = []
    t = transport([httpx.Response(status)] * 6, sleeps)
    with pytest.raises(ModelCallError) as info:
        t.send(PARAMS, "k")
    assert info.value.kind == kind
    assert len(sleeps) == 5
    worst = sum(RetryPolicy().base_s * 2**i for i in range(5))
    assert sum(sleeps) <= worst <= 600  # about 10 minutes at most


def test_other_4xx_are_not_retried() -> None:
    sleeps: list[float] = []
    t = transport([httpx.Response(400, text="bad")], sleeps)
    with pytest.raises(Exception, match="HTTP 400"):
        t.send(PARAMS, "k")
    assert sleeps == []


def test_retries_are_stored_in_cassettes_and_replayed(tmp_path: Path) -> None:
    sleeps: list[float] = []
    live = transport([httpx.Response(429), httpx.Response(200, json=ok_body())], sleeps)
    recorder = CassetteTransport(tmp_path, "record", live)
    first = OpenRouterChatModel(recorder, HOST)
    from tests.llm.test_openrouter import request

    assert first.complete(request()).retries == 1
    (stored,) = [json.loads(p.read_text(encoding="utf-8")) for p in tmp_path.iterdir()]
    assert stored["interactions"][0]["retries"] == 1
    replay = OpenRouterChatModel(CassetteTransport(tmp_path, "replay"), HOST)
    assert replay.complete(request()).retries == 1


def test_no_retries_key_in_cassettes_without_retries(tmp_path: Path) -> None:
    recorder = CassetteTransport(tmp_path, "record", FakeTransport([ok_body()]))
    from tests.llm.test_openrouter import request

    OpenRouterChatModel(recorder, HOST).complete(request())
    (stored,) = [json.loads(p.read_text(encoding="utf-8")) for p in tmp_path.iterdir()]
    assert "retries" not in stored["interactions"][0]


class FlakyTransport:
    """Rate-limits every call of the trials named in `limited`; answers the rest."""

    def __init__(self, limited: set[str]) -> None:
        self.limited = limited

    def send(self, params: dict[str, Any], trial_key: str) -> Any:
        if trial_key in self.limited:
            raise ModelCallError("provider_rate_limited", "HTTP 429 after 6 attempts")
        return FakeTransport([ok_body()]).send(params, trial_key)


def run_flaky(limited_trials: set[int], trials: int = 10) -> Any:
    scenario = next(s for s in load_builtin() if s.id == "pix-description-injection-001")
    keys = {
        f"{scenario.id}/baseline/vulnerable/{v}/t{i:03d}"
        for v in ("attack", "benign")
        for i in limited_trials
    }
    agent = LLMAgent(
        OpenRouterChatModel(FlakyTransport(keys), HOST),
        model=MODEL,
        effort="none",
        meter=CostMeter(1.0),
    )
    outcome = run_all(
        [scenario], agent, prompt_variants=("baseline",), trials=trials, presets=("vulnerable",)
    )
    return outcome, build_report(outcome, agent, trials=trials, prompt_variants=["baseline"])


def test_rate_limited_trials_are_errored_and_the_run_continues() -> None:
    outcome, report = run_flaky({0})
    assert outcome.status == "complete"
    trials = [t for c in outcome.results[0].cells for t in c.trials]
    limited = [t for t in trials if t.error == "provider_rate_limited"]
    assert len(limited) == 2  # attack t000 and benign t000
    assert all(t.errored for t in limited)
    assert all(t.status != "exposed_resisted" for t in limited)
    assert report.routing.transient_errored_trials == {"provider_rate_limited": 2}
    (row,) = report.summary.rows
    assert "provider_rate_limited" not in row.not_meaningful_reasons  # 1/10 is not > 10%


def test_more_than_ten_percent_rate_limited_makes_the_cell_not_meaningful() -> None:
    _, report = run_flaky({0, 1})
    (row,) = report.summary.rows
    assert "provider_rate_limited" in row.not_meaningful_reasons
    assert row.resistance_meaningful is False


ENDPOINTS = {
    "data": {
        "id": MODEL,
        "endpoints": [
            {
                "provider_name": HOST,
                "tag": "synthetic/fp8",
                "quantization": "fp8",
                "context_length": 131072,
                "pricing": {"prompt": "0.0000001", "completion": "0.0000003"},
                "supported_parameters": ["tools", "seed", "temperature"],
            }
        ],
    }
}


def ping(token: str, call_id: str) -> dict[str, Any]:
    call = {
        "id": call_id,
        "type": "function",
        "function": {"name": "ping", "arguments": json.dumps({"token": token})},
    }
    body = ok_body("")
    body["choices"] = [
        {
            "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": "", "tool_calls": [call]},
        }
    ]
    return body


def test_doctor_retries_the_probes_before_failing(tmp_path: Path) -> None:
    prices = tmp_path / "p.toml"
    prices.write_text(
        f'as_of = "2026-11-17"\nsource = "t"\n[[price]]\nmodel = "{MODEL}"\nhost = "{HOST}"\n'
        "input_per_mtok = 0.1\noutput_per_mtok = 0.3\n",
        encoding="utf-8",
    )
    replies = [
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json=ping("mb-probe", "c1")),
        httpx.Response(503),
        httpx.Response(200, json=ping("mb-probe-2", "c2")),
    ]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/endpoints"):
            return httpx.Response(200, json=ENDPOINTS)
        return replies.pop(0)

    sleeps: list[float] = []
    checks = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="fp8",
        pricing=prices,
        allow_remote=True,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=sleeps.append,
    )
    levels = {c.name: c.level for c in checks}
    assert levels["tool calling"] == "ok"
    assert levels["tool calling after a tool result"] == "ok"
    assert len(sleeps) == 2
    assert sleeps[0] == 1.0
