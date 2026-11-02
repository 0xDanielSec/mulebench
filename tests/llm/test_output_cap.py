"""Output cap: calls that ended at max_tokens, per trial, cell and report."""

from __future__ import annotations

from typing import Any

import pytest

from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import LLMConfig
from mulebench.harness.validity import hit_output_cap, output_cap_fields
from mulebench.reports import build_report, render_table
from tests.llm.test_malformed_calls import completion, tool_call

SCENARIO = "pix-description-injection-001"


@pytest.mark.parametrize(
    ("reason", "hit"),
    [("length", True), ("max_tokens", True), ("stop", False), ("tool_calls", False), (None, False)],
)
def test_hit_output_cap(reason: str | None, hit: bool) -> None:
    assert hit_output_cap(reason) is hit


def test_output_cap_fields() -> None:
    assert output_cap_fields([]) == {"length_calls": 0, "cut_by_cap": False}
    assert output_cap_fields(["tool_calls", "length"]) == {"length_calls": 1, "cut_by_cap": True}
    assert output_cap_fields(["length", "stop"]) == {"length_calls": 1, "cut_by_cap": False}
    assert output_cap_fields(["max_tokens"]) == {"length_calls": 1, "cut_by_cap": True}


def cut_after_one_tool_call(params: dict[str, Any], key: str) -> dict[str, Any]:
    if any(m["role"] == "assistant" for m in params["messages"]):
        body = completion({"role": "assistant", "content": "<think>still thinking"})
        body["choices"][0]["finish_reason"] = "length"
        return body
    return tool_call("list_transactions", '{"account_id": "acc_alice"}')


def test_trials_cut_by_cap_reported_per_trial_cell_and_report() -> None:
    chat = OpenAICompatChatModel(FakeTransport(cut_after_one_tool_call))
    agent = LLMAgent(chat, model="tiny:1b", effort="none", max_tokens=256)
    scenario = next(s for s in load_builtin() if s.id == SCENARIO)
    run = run_all(
        [scenario], agent, trials=2, presets=("vulnerable",), prompt_variants=["baseline"]
    )
    for result in run.results:
        for cell in result.cells:
            assert all(t.length_calls == 1 and t.cut_by_cap for t in cell.trials)
            assert cell.length_calls == 2
            assert cell.cut_by_cap_trials == 2
    llm = LLMConfig(
        provider="openai-compatible",
        model="tiny:1b",
        effort="none",
        max_tokens=256,
        refusal_fallbacks="off",
        prompt_sha256={},
    )
    report = build_report(
        run, agent, prompt_variants=["baseline"], presets=["vulnerable"], trials=2, llm=llm
    )
    assert report.summary.totals.length_calls == 4
    assert report.summary.totals.cut_by_cap_trials == 4
    table = render_table(report)
    assert "output cap: 4 model calls ended at max_tokens  trials cut: 4" in table
    assert f"{SCENARIO} baseline vulnerable attack 2/2" in table
