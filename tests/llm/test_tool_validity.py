"""Tool-call validity is n/a without tool calls; tool calls per trial are reported."""

from __future__ import annotations

from typing import Any

from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import LLMConfig
from mulebench.harness.validity import format_validity, tool_call_validity
from mulebench.reports import build_report, render_table
from tests.llm.test_malformed_calls import completion, first_then_done, text_only, tool_call

SCENARIO = "pix-description-injection-001"
LLM = LLMConfig(
    provider="openai-compatible",
    model="tiny:1b",
    effort="none",
    max_tokens=256,
    refusal_fallbacks="off",
    prompt_sha256={},
)


def run(respond: Any, trials: int = 2) -> Any:
    chat = OpenAICompatChatModel(FakeTransport(respond))
    agent = LLMAgent(chat, model="tiny:1b", effort="none", max_tokens=256)
    scenario = next(s for s in load_builtin() if s.id == SCENARIO)
    outcome = run_all(
        [scenario], agent, trials=trials, presets=["vulnerable"], prompt_variants=["baseline"]
    )
    return build_report(
        outcome, agent, prompt_variants=["baseline"], presets=["vulnerable"], trials=trials, llm=LLM
    )


def test_no_tool_calls_reads_na_not_perfect() -> None:
    report = run(text_only())
    (row,) = report.summary.rows
    assert row.tool_call_validity is not None
    assert row.tool_call_validity.n == 0
    assert row.tool_calls_per_trial == 0
    assert format_validity(row.tool_call_validity) == "n/a (no tool calls)"
    assert "n/a (no tool calls)" in render_table(report)


def test_validity_counts_only_trials_that_attempted_calls() -> None:
    report = run(first_then_done(tool_call("list_transactions", '{"account_id": "acc_alice"}')))
    (row,) = report.summary.rows
    assert row.tool_call_validity is not None
    assert (row.tool_call_validity.k, row.tool_call_validity.n) == (4, 4)
    assert row.tool_calls_per_trial == 1
    cell = report.scenarios[0].cell("vulnerable", "attack", "baseline")
    assert cell.tool_calls_per_trial == 1


def test_empty_output_trials_count_as_invalid() -> None:
    # The mistral-nemo pattern: no call, empty content. No longer reads as 6/6.
    report = run(lambda p, k: completion({"role": "assistant", "content": ""}))
    (row,) = report.summary.rows
    assert row.tool_call_validity is not None
    assert (row.tool_call_validity.k, row.tool_call_validity.n) == (0, 4)
    cells = report.scenarios[0].cells
    assert tool_call_validity([t for c in cells for t in c.trials]).n == 4
