"""The examples load, pass conformance (minimal) and run offline (OpenAI loop, stubbed)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulebench.attacks import load_builtin
from mulebench.byoa import load_agent
from mulebench.harness import run_all
from mulebench.harness.conformance import check_agent
from mulebench.reports import build_report
from mulebench.reports.json_report import report_to_json

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
FAKE_KEY = "sk-" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
SCENARIO = "pix-description-injection-001"


def test_minimal_agent_is_conformant() -> None:
    agent = load_agent("minimal_agent:factory", EXAMPLES)
    c = check_agent(load_builtin(), agent, trials=1)
    assert c.status == "passed"
    assert c.benign_pass is not None
    # It ignores the memory block and does not declare uses_memory, so 017
    # (whose benign control needs memory) is excluded, not failed: every
    # gated benign control passes.
    assert c.benign_pass.k == c.benign_pass.n
    assert "memory-utility-and-leak-017" not in c.per_scenario
    assert any(w.startswith("memory-utility-and-leak-017: excluded") for w in c.warnings)


def test_minimal_agent_resists_the_packaged_attacks() -> None:
    agent = load_agent("minimal_agent:factory", EXAMPLES)
    report = build_report(run_all(load_builtin(), agent, presets=("vulnerable",)), agent)
    assert report.summary.totals.exposed_violated == 0


class StubServer:
    """Plays a fixed conversation: one tool call, then a final answer."""

    def __init__(self, with_usage: bool = True) -> None:
        self.requests: list[tuple[str, dict[str, Any], dict[str, str]]] = []
        self.with_usage = with_usage

    def __call__(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any]:
        self.requests.append((url, payload, headers))
        usage = {"prompt_tokens": 100, "completion_tokens": 7} if self.with_usage else None
        if len(self.requests) == 1:
            message: dict[str, Any] = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {
                            "name": "list_transactions",
                            "arguments": json.dumps({"account_id": "acc_alice"}),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        else:
            message, finish = (
                {"role": "assistant", "content": "Here are your transactions."},
                "stop",
            )
        out: dict[str, Any] = {
            "id": f"r{len(self.requests)}",
            "model": "stub",
            "choices": [{"message": message, "finish_reason": finish}],
        }
        if usage is not None:
            out["usage"] = usage
        return out


def _openai_agent(monkeypatch: pytest.MonkeyPatch, base_url: str, stub: StubServer) -> Any:
    monkeypatch.setenv("MODEL", "stub-model")
    monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    adapter = load_agent("openai_compatible_agent:factory", EXAMPLES)
    adapter.inner._post = stub  # type: ignore[attr-defined]
    return adapter


def _one_trial(agent: Any) -> str:
    scenarios = [s for s in load_builtin() if s.id == SCENARIO]
    return report_to_json(build_report(run_all(scenarios, agent, presets=("vulnerable",)), agent))


def test_openai_loop_runs_offline_and_records_usage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubServer()
    agent = _openai_agent(monkeypatch, "http://[::1]:11434/v1", stub)
    text = _one_trial(agent)
    data = json.loads(text)
    trial = data["scenarios"][0]["cells"][0]["trials"][0]
    assert [r["tool"] for r in trial["trace"]] == ["list_transactions"]
    assert trial["model_calls_recorded"] is True
    assert trial["usage"]["input_tokens"] == 200
    assert trial["final_text"] == "Here are your transactions."
    url, payload, headers = stub.requests[0]
    assert url == "http://[::1]:11434/v1/chat/completions"
    assert {t["function"]["name"] for t in payload["tools"]} >= {"transfer_pix", "open_dispute"}
    assert headers["Authorization"] == f"Bearer {FAKE_KEY}"
    # The key goes to the server only: never to the report or the terminal.
    assert FAKE_KEY not in text
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out + captured.err
    assert "WARNING" not in captured.err


def test_openai_loop_without_usage_is_not_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _openai_agent(monkeypatch, "http://localhost:11434/v1", StubServer(with_usage=False))
    trial = json.loads(_one_trial(agent))["scenarios"][0]["cells"][0]["trials"][0]
    assert trial["model_calls_recorded"] is False
    assert trial["cost_usd"] is None


def test_openai_loop_warns_for_remote_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _openai_agent(monkeypatch, "https://llm.example.test/v1", StubServer())
    err = capsys.readouterr().err
    assert "is not loopback" in err
    assert "may cost money" in err
    assert FAKE_KEY not in err


def test_openai_loop_defaults_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL", "m")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter = load_agent("openai_compatible_agent:factory", EXAMPLES)
    assert adapter.params["base_url"] == "http://localhost:11434/v1"
    assert all(FAKE_KEY not in str(v) for v in adapter.params.values())


def test_openai_loop_needs_model(monkeypatch: pytest.MonkeyPatch) -> None:
    from mulebench.byoa import AgentLoadError

    monkeypatch.delenv("MODEL", raising=False)
    with pytest.raises(AgentLoadError, match="set MODEL"):
        load_agent("openai_compatible_agent:factory", EXAMPLES)
