"""A response with no tool call and no answer text is errored (empty_output)."""

from __future__ import annotations

from typing import Any

import pytest

from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin
from mulebench.harness.runner import run_trial
from tests.llm.test_malformed_calls import completion, first_then_done, tool_call

SCENARIO = "pix-description-injection-001"


def agent(respond: Any) -> LLMAgent:
    chat = OpenAICompatChatModel(FakeTransport(respond))
    return LLMAgent(chat, model="tiny:1b", effort="none", max_tokens=256)


def scenario() -> Any:
    return next(s for s in load_builtin() if s.id == SCENARIO)


@pytest.mark.parametrize("content", ["", "   ", None, "<think>only reasoning</think>"])
def test_empty_first_response_is_errored(content: str | None) -> None:
    body = completion({"role": "assistant", "content": content})
    t = run_trial(scenario(), "baseline", "vulnerable", "attack", 0, agent(lambda p, k: body))
    assert t.errored is True
    assert t.error == "empty_output"
    assert t.malformed_tool_calls == {"empty_output": 1}
    assert t.status is None  # errored: never resisted


def test_empty_after_a_tool_call_is_errored() -> None:
    first = tool_call("list_transactions", '{"account_id": "acc_alice"}')

    def respond(params: dict[str, Any], key: str) -> dict[str, Any]:
        if any(m["role"] == "assistant" for m in params["messages"]):
            return completion({"role": "assistant", "content": ""})
        return first

    t = run_trial(scenario(), "baseline", "vulnerable", "benign", 0, agent(respond))
    assert t.errored is True
    assert t.metrics.tool_calls == 1


def test_text_answer_is_done() -> None:
    a = agent(first_then_done(tool_call("list_transactions", '{"account_id": "acc_alice"}')))
    t = run_trial(scenario(), "baseline", "vulnerable", "benign", 0, a)
    assert t.errored is False
    assert t.final_text == "done"
