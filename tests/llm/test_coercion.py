"""Digit-string coercion at the LLM agent boundary (synthetic fakes only)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.coercion import coerce_args
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import LLMConfig
from mulebench.harness.runner import run_trial
from mulebench.reports import build_report, render_table

SCHEMA = {
    "type": "object",
    "properties": {
        "limit": {"type": "integer"},
        "account_id": {"type": "string"},
        "authorization_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
}
SCENARIO = next(s for s in load_builtin() if s.id == "pix-description-injection-001")


@pytest.mark.parametrize("value", ["0", "10", "120000", "007"])
def test_digit_strings_become_ints(value: str) -> None:
    assert coerce_args({"limit": value}, SCHEMA, "digit_strings") == (
        {"limit": int(value)},
        ["limit"],
    )


@pytest.mark.parametrize(
    "value", ["1200.00", "1.200", "1,200", "-5", "+5", " 10", "10 ", "R$ 1200", "", "1e3", "١٢"]
)
def test_anything_but_plain_digits_is_left_alone(value: str) -> None:
    assert coerce_args({"limit": value}, SCHEMA, "digit_strings") == ({"limit": value}, [])


def test_only_integer_fields_and_off_mode() -> None:
    args = {"account_id": "123", "authorization_id": "42", "limit": "5", "extra": "7"}
    out, fields = coerce_args(args, SCHEMA, "digit_strings")
    assert out == {"account_id": "123", "authorization_id": "42", "limit": 5, "extra": "7"}
    assert fields == ["limit"]
    assert coerce_args(args, SCHEMA, "off") == (args, [])
    assert coerce_args(args, None, "digit_strings") == (args, [])


# ---------------------------------------------------- agent: llama 3.1 shape


def completion(message: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "chatcmpl-c",
        "model": "llama-like:8b",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
    }


def call(i: int, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"c{i}",
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def llama_like(params: dict[str, Any], key: str) -> dict[str, Any]:
    """Both calls in turn 0, every integer stringified (as seen in a live smoke run)."""
    if any(m["role"] == "assistant" for m in params["messages"]):
        return completion({"role": "assistant", "content": "Paid."})
    calls = [
        call(0, "list_transactions", {"account_id": "acc_alice", "limit": "10"}),
        call(
            1,
            "transfer_pix",
            {
                "from_account_id": "acc_alice",
                "to_pix_key": "landlord@example.test",
                "amount_cents": "120000",
                "authorization_id": "auth_0002",
            },
        ),
    ]
    return completion({"role": "assistant", "content": None, "tool_calls": calls})


def agent(mode: str) -> LLMAgent:
    return LLMAgent(
        OpenAICompatChatModel(FakeTransport(llama_like)),
        model="llama-like:8b",
        effort="none",
        max_tokens=256,
        arg_coercion=mode,  # type: ignore[arg-type]
    )


def test_coercion_makes_the_benign_task_executable() -> None:
    t = run_trial(SCENARIO, "baseline", "vulnerable", "benign", 0, agent("digit_strings"))
    assert t.errored is False
    assert t.benign_pass is True
    assert t.malformed_tool_calls == {}
    assert (t.coerced_calls, t.coerced_args) == (
        2,
        {"list_transactions.limit": 1, "transfer_pix.amount_cents": 1},
    )
    assert t.model_calls[0].coerced_args == ["list_transactions.limit", "transfer_pix.amount_cents"]
    assert t.model_calls[1].coerced_args == []
    executed = {r.tool: r.args for r in t.trace}
    assert executed["transfer_pix"]["amount_cents"] == 120000  # the tools saw an int
    assert executed["list_transactions"]["limit"] == 10


def test_off_restores_strict_errors() -> None:
    t = run_trial(SCENARIO, "baseline", "vulnerable", "benign", 0, agent("off"))
    assert (t.errored, t.error) == (True, "malformed_tool_call:schema")
    assert t.malformed_tool_calls == {"schema": 2}
    assert t.coerced_calls == 0
    assert t.trace == []


def test_agent_params_record_the_mode() -> None:
    assert agent("digit_strings").params["arg_coercion"] == "digit_strings"
    assert agent("off").params["arg_coercion"] == "off"


def test_report_counts_coerced_calls_separately() -> None:
    a = agent("digit_strings")
    outcome = run_all([SCENARIO], a, prompt_variants=["baseline"], presets=["vulnerable"])
    llm = LLMConfig(
        provider="openai-compatible",
        model="llama-like:8b",
        effort="none",
        max_tokens=256,
        refusal_fallbacks="off",
        prompt_sha256={},
        arg_coercion="digit_strings",
    )
    report = build_report(outcome, a, prompt_variants=["baseline"], presets=["vulnerable"], llm=llm)
    totals = report.summary.totals
    assert totals.coerced_calls == 4
    assert totals.coerced_args == {"list_transactions.limit": 2, "transfer_pix.amount_cents": 2}
    assert totals.malformed_tool_calls == {}
    (row,) = report.summary.rows
    assert row.tool_call_validity is not None
    assert row.tool_call_validity.k == row.tool_call_validity.n == 2  # valid after coercion
    cell = report.scenarios[0].cell("vulnerable", "benign", "baseline")
    assert (cell.coerced_calls, cell.coerced_args["transfer_pix.amount_cents"]) == (2, 1)
    assert (
        "coerced tool calls: 4 (list_transactions.limit: 2, transfer_pix.amount_cents: 2)  "
        "arg_coercion: digit_strings"
    ) in render_table(report)


def test_checkpoint_fingerprint_depends_on_the_mode() -> None:
    from mulebench.harness.checkpoint import fingerprint

    on = {"agent": dict(agent("digit_strings").params)}
    off = {"agent": dict(agent("off").params)}
    assert fingerprint(on, [SCENARIO]) != fingerprint(off, [SCENARIO])
