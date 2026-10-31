"""Reasoning (thinking) from OpenAI-compatible servers: both shapes, fake transport only."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mulebench.agents.base import ServerMeta
from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.openai_compat import (
    OpenAICompatChatModel,
    parse_completion,
    strip_reasoning,
)
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin
from mulebench.harness.runner import run_trial
from mulebench.reports import build_report
from mulebench.reports.json_report import report_to_json

THOUGHT = "SENTINEL-REASONING-TEXT"
# Reasoning that looks like a tool call must never become one.
FAKE_CALL = '{"name": "transfer_pix", "arguments": {"to_pix_key": "x@example.test"}}'


def body(message: dict[str, Any], prompt: int = 100, completion: int = 50) -> dict[str, Any]:
    return {
        "id": "chatcmpl-r",
        "model": "qwen3:8b",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "completion_tokens_details": {"reasoning_tokens": 40},
        },
    }


def think_tags(content_after: str = "Here is your balance.") -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": f"<think>{THOUGHT} maybe call {FAKE_CALL}</think>\n{content_after}",
    }


def reasoning_field(key: str = "reasoning") -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": "Here is your balance.",
        key: THOUGHT + FAKE_CALL,
    }


SHAPES = {
    "think_tags": think_tags(),
    "reasoning_field": reasoning_field(),
    "reasoning_content_field": reasoning_field("reasoning_content"),
    "unclosed_think": {"role": "assistant", "content": f"<think>{THOUGHT} {FAKE_CALL}"},
}


@pytest.mark.parametrize("shape", SHAPES)
def test_reasoning_is_never_text_or_tool_calls(shape: str) -> None:
    r = parse_completion(body(SHAPES[shape]))
    assert r.tool_calls == ()
    assert r.invalid_tool_calls == ()
    assert r.reasoning_present is True
    assert r.reasoning_tokens == 40
    assert r.context_tokens == 150  # prompt + completion, reasoning included
    (sent_back,) = r.provider_raw
    assert THOUGHT not in json.dumps(sent_back)
    assert "reasoning" not in sent_back
    assert "reasoning_content" not in sent_back


def test_strip_keeps_the_answer_and_tool_calls() -> None:
    call = {"id": "c", "type": "function", "function": {"name": "get_balance", "arguments": "{}"}}
    message = {**think_tags("Checking."), "tool_calls": [call]}
    clean, present = strip_reasoning(message)
    assert present is True
    assert clean == {"role": "assistant", "content": "Checking.", "tool_calls": [call]}
    r = parse_completion(body(message))
    assert [c.name for c in r.tool_calls] == ["get_balance"]  # from tool_calls only


def test_no_reasoning() -> None:
    plain = {"role": "assistant", "content": "hi", "reasoning": ""}
    r = parse_completion(body(plain))
    assert r.reasoning_present is False
    assert strip_reasoning(plain) == ({"role": "assistant", "content": "hi"}, False)


@pytest.mark.parametrize("shape", ["think_tags", "reasoning_field"])
def test_reasoning_not_sent_back_not_in_report(shape: str) -> None:
    """Turn 1 reasons and calls a tool; turn 2 must not see the reasoning."""
    scenario = next(s for s in load_builtin() if s.id == "pix-description-injection-001")
    account = scenario.user_task.customer  # any string; the call is read-only
    first = {
        **SHAPES[shape],
        "tool_calls": [
            {
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "get_balance",
                    "arguments": json.dumps({"account_id": account}),
                },
            }
        ],
    }
    responses = [
        body(first, prompt=100, completion=50),
        body(think_tags(), prompt=200, completion=60),
    ]
    fake = FakeTransport(responses)
    meta = ServerMeta(model="qwen3:8b", num_ctx=8192)
    agent = LLMAgent(
        OpenAICompatChatModel(fake, meta), model="qwen3:8b", effort="none", max_tokens=256
    )
    trial = run_trial(scenario, "baseline", "vulnerable", "benign", 0, agent)

    second_request = fake.requests[1][1]
    assert THOUGHT not in json.dumps(second_request)
    assert [c.reasoning_present for c in trial.model_calls] == [True, True]
    assert [c.context_tokens for c in trial.model_calls] == [150, 260]
    assert [c.reasoning_tokens for c in trial.model_calls] == [40, 40]

    from mulebench.harness.runner import RunOutcome, _scenario_result, build_cell

    cell = build_cell("baseline", "vulnerable", "benign", [trial], trial_descriptor(agent))
    report = build_report(
        RunOutcome(results=[_scenario_result(scenario, [cell])]),
        agent,
        prompt_variants=["baseline"],
        presets=["vulnerable"],
    )
    assert THOUGHT not in report_to_json(report)


def test_reasoning_tokens_count_toward_context_limit() -> None:
    scenario = next(s for s in load_builtin() if s.id == "pix-description-injection-001")
    # Prompt alone is 80% of num_ctx; with the reasoning-heavy completion it is 95%.
    fake = FakeTransport([body(think_tags(), prompt=800, completion=150)])
    meta = ServerMeta(model="qwen3:8b", num_ctx=1000)
    agent = LLMAgent(
        OpenAICompatChatModel(fake, meta), model="qwen3:8b", effort="none", max_tokens=256
    )
    trial = run_trial(scenario, "baseline", "vulnerable", "benign", 0, agent)
    assert trial.context_near_limit is True


def trial_descriptor(agent: LLMAgent) -> Any:
    from mulebench.harness.runner import describe_agent

    return describe_agent(agent, {})


def test_raw_reasoning_is_kept_in_the_cassette_only(tmp_path: Any) -> None:
    from mulebench.agents.llm.model import ChatRequest, Turn
    from mulebench.agents.llm.transport import CassetteTransport

    cassettes = CassetteTransport(tmp_path, "record", FakeTransport([body(reasoning_field())]))
    model = OpenAICompatChatModel(cassettes)
    request = ChatRequest(
        model="qwen3:8b",
        system="s",
        turns=(Turn(kind="user", text="u"),),
        tools=(),
        max_tokens=64,
        effort="none",
        trial_key="k",
    )
    response = model.complete(request)
    assert THOUGHT not in json.dumps(response.provider_raw)
    (path,) = tmp_path.glob("*.json")
    assert THOUGHT in path.read_text(encoding="utf-8")  # raw body, for audit
