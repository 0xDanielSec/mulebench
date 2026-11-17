"""Calls that errored live replay as the same errored trials.

New recordings store a failed call as an `error` interaction. Cassettes recorded
before that have no entry for it; with the run report as `known_errors`, replay
still reproduces the error, and without it the miss stays CassetteMissing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.model import ModelCallError
from mulebench.agents.llm.openrouter import OpenRouterChatModel
from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import fixed_pricer
from mulebench.agents.llm.transport import (
    CassetteMissing,
    CassetteTransport,
    Transport,
    TransportResponse,
    cassette_path,
    known_errors_from_report,
)
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import LLMConfig
from mulebench.reports import build_report

HOST = "SyntheticHost"
MODEL = "vendor/model-a"
SCENARIOS = {"pix-description-cross-customer-read-004", "memory-auto-persistent-exfiltration-014a"}
# a session call of 004 and the memory extraction call of 014a
FAILING = {
    "pix-description-cross-customer-read-004/baseline/vulnerable/benign/t001": "connection",
    "memory-auto-persistent-exfiltration-014a/baseline/vulnerable/benign/t000#mem0": "timeout",
}


class Upstream:
    """Answers in text from the pinned host; fails the calls in FAILING."""

    def __init__(self) -> None:
        self.calls = 0

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        self.calls += 1
        if trial_key in FAILING:
            raise ModelCallError(FAILING[trial_key], "synthetic failure", "req-err")
        body = {
            "id": "gen",
            "model": MODEL,
            "provider": HOST,
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "cost": 0.00001},
        }
        return TransportResponse(body=body, request_id="gen")


def run(transport: Transport) -> dict[str, Any]:
    scenarios = [s for s in load_builtin() if s.id in SCENARIOS]
    agent = LLMAgent(
        OpenRouterChatModel(transport, HOST, "fp8"),
        model=MODEL,
        effort="none",
        meter=CostMeter(1.0),
        temperature=0.7,
        seed=7000,
        pricer=fixed_pricer(Price(input_per_mtok=1, output_per_mtok=2, cache_read_per_mtok=0)),
    )
    outcome = run_all(
        scenarios, agent, prompt_variants=("baseline",), trials=2, presets=("vulnerable",)
    )
    llm = LLMConfig(
        provider="openrouter",
        model=MODEL,
        effort="none",
        max_tokens=4096,
        refusal_fallbacks="off",
        prompt_sha256={},
        temperature=0.7,
        seed=7000,
        seed_derivation="sha256_trial_key_v1",
        openrouter_host=HOST,
        openrouter_quantization="fp8",
    )
    report = build_report(
        outcome, agent, prompt_variants=["baseline"], trials=2, llm=llm, presets=["vulnerable"]
    )
    data: dict[str, Any] = json.loads(report.model_dump_json())
    return data


def trials(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    stack: list[Any] = [report]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "trial_key" in node and "errored" in node:
                out[node["trial_key"]] = node
            else:
                stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def strip_errors(directory: Path) -> int:
    """Turn new cassettes into old ones: drop the error interactions."""
    dropped = 0
    for path in directory.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        kept = [i for i in data["interactions"] if "error" not in i]
        dropped += len(data["interactions"]) - len(kept)
        data["interactions"] = kept
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return dropped


@pytest.fixture
def recorded(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    directory = tmp_path / "cassettes"
    report = run(CassetteTransport(directory, "record", Upstream()))
    return directory, report


def test_live_errors_are_errored_trials_with_the_live_kind(
    recorded: tuple[Path, dict[str, Any]],
) -> None:
    _, report = recorded
    errored = {k: t["error"] for k, t in trials(report).items() if t["errored"]}
    assert errored == {
        "pix-description-cross-customer-read-004/baseline/vulnerable/benign/t001": "connection",
        "memory-auto-persistent-exfiltration-014a/baseline/vulnerable/benign/t000": (
            "memory_extraction:timeout"
        ),
    }


def test_recording_stores_the_failed_call(recorded: tuple[Path, dict[str, Any]]) -> None:
    directory, _ = recorded
    for key, kind in FAILING.items():
        data = json.loads(cassette_path(directory, key).read_text(encoding="utf-8"))
        (entry,) = [i for i in data["interactions"] if "error" in i]
        assert entry["error"] == {"kind": kind, "message": "synthetic failure"}
        assert entry["request_id"] == "req-err"
        assert "response" not in entry


def test_new_cassettes_replay_errored_trials_identically(
    recorded: tuple[Path, dict[str, Any]],
) -> None:
    directory, report = recorded
    assert trials(run(CassetteTransport(directory, "replay"))) == trials(report)


def test_old_cassettes_replay_errored_trials_from_the_report(
    recorded: tuple[Path, dict[str, Any]],
) -> None:
    directory, report = recorded
    assert strip_errors(directory) == 2
    with pytest.raises(CassetteMissing, match="no recorded response"):
        run(CassetteTransport(directory, "replay"))
    known = known_errors_from_report(report)
    assert len(known) == 2
    replay = run(CassetteTransport(directory, "replay", known_errors=known))
    assert trials(replay) == trials(report)


def test_report_errors_are_used_only_for_matching_transport_failures(tmp_path: Path) -> None:
    base = "s/baseline/vulnerable/benign/t000"
    known = {
        base: "memory_extraction:provider_rate_limited",
        "s/baseline/vulnerable/benign/t001": "empty_output",
        "s/baseline/vulnerable/benign/t002": "http_503",
    }
    t = CassetteTransport(tmp_path, "replay", known_errors=known)
    with pytest.raises(ModelCallError) as exc:
        t.send({"x": 1}, base + "#mem0")
    assert exc.value.kind == "provider_rate_limited"
    # the session call of an extraction-errored trial must have been recorded
    with pytest.raises(CassetteMissing):
        t.send({"x": 1}, base)
    # an output error always has a recorded response: never taken from the report
    with pytest.raises(CassetteMissing):
        t.send({"x": 1}, "s/baseline/vulnerable/benign/t001")
    with pytest.raises(ModelCallError) as exc:
        t.send({"x": 1}, "s/baseline/vulnerable/benign/t002#s1")
    assert exc.value.kind == "http_503"
    with pytest.raises(CassetteMissing):
        t.send({"x": 1}, "s/baseline/vulnerable/benign/t003")
