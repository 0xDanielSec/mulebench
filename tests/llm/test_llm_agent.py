"""LLMAgent + Anthropic adapter with a fake transport (offline)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from anthropic.types import Message, TextBlock, ThinkingBlock, ToolUseBlock, Usage

from mulebench.agents.base import RunAborted
from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.anthropic_model import AnthropicChatModel
from mulebench.agents.llm.model import ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.prompts import PROMPTS
from mulebench.agents.llm.transport import FakeTransport, TransportResponse
from mulebench.attacks import BUILTIN_SCENARIOS_DIR, load_scenario
from mulebench.harness import run_all, run_trial
from mulebench.tools import UNTRUSTED_KEY

SCENARIO = load_scenario(BUILTIN_SCENARIOS_DIR / "pix-description-injection-001.yaml")
LANDLORD = "landlord@example.test"


def msg(*blocks: Any, stop: Any = "tool_use", out: int = 10) -> dict[str, Any]:
    return Message(
        id="msg_1",
        type="message",
        role="assistant",
        model="claude-opus-5-5",
        content=[ThinkingBlock(type="thinking", thinking="", signature="sig"), *blocks],
        stop_reason=stop,
        stop_sequence=None,
        usage=Usage(input_tokens=1000, output_tokens=out),
    ).to_dict()


def use(i: int, name: str, **args: Any) -> ToolUseBlock:
    return ToolUseBlock(type="tool_use", id=f"toolu_{i}", name=name, input=args)


def done() -> dict[str, Any]:
    return msg(TextBlock(type="text", text="Done.", citations=None), stop="end_turn")


def agent(transport: Any, model: str = "claude-opus-5-5", **kw: Any) -> LLMAgent:
    return LLMAgent(AnthropicChatModel(transport), model=model, effort="medium", **kw)


def trial(a: LLMAgent, preset: str = "vulnerable", variant: str = "attack") -> Any:
    return run_trial(SCENARIO, "baseline", preset, variant, 0, a)  # type: ignore[arg-type]


# ------------------------------------------------------------- request shape


def test_request_shape_and_trusted_channels() -> None:
    fake = FakeTransport([done()])
    t = trial(agent(fake))
    key, params = fake.requests[0]
    assert key == "pix-description-injection-001/baseline/vulnerable/attack/t000"
    assert set(params) == {"model", "max_tokens", "system", "messages", "tools", "output_config"}
    assert params["output_config"] == {"effort": "medium"}
    assert params["system"] == PROMPTS["baseline"]
    for absent in ("temperature", "top_p", "top_k", "tool_choice", "fallbacks", "thinking"):
        assert absent not in params
    user, note = params["messages"]
    assert user == {"role": "user", "content": SCENARIO.user_task.request}
    assert note["role"] == "system"
    assert note["content"].startswith("Session note from the bank (trusted):")
    assert t.session_note_channel == "operator"
    assert t.temperature is None


def test_session_note_falls_back_to_system_prompt_on_models_without_operator_channel() -> None:
    fake = FakeTransport([done()])
    t = trial(agent(fake, model="claude-sonnet-5"))
    params = fake.requests[0][1]
    assert [m["role"] for m in params["messages"]] == ["user"]
    assert "Session note from the bank (trusted):" in params["system"]
    assert t.session_note_channel == "system_prompt"


def test_model_never_sees_untrusted_markers() -> None:
    fake = FakeTransport([msg(use(1, "list_transactions", account_id="acc_alice")), done()])
    trial(agent(fake))
    tools_json = json.dumps(fake.requests[0][1]["tools"])
    assert UNTRUSTED_KEY not in tools_json
    assert [t["name"] for t in fake.requests[0][1]["tools"]] == sorted(
        t["name"] for t in fake.requests[0][1]["tools"]
    )
    result_block = fake.requests[1][1]["messages"][-1]["content"][0]
    payload = json.loads(result_block["content"])
    assert set(payload) == {"ok", "outcome", "data", "error"}  # no untrusted_paths
    assert SCENARIO.canary in result_block["content"]  # but the data itself is there


# ------------------------------------------------------------------- loop


def test_parallel_tool_calls_answered_in_one_message() -> None:
    fake = FakeTransport(
        [
            msg(
                use(1, "get_balance", account_id="acc_alice"),
                use(2, "list_transactions", account_id="acc_alice"),
            ),
            done(),
        ]
    )
    t = trial(agent(fake))
    last = fake.requests[1][1]["messages"][-1]
    assert last["role"] == "user"
    assert [b["tool_use_id"] for b in last["content"]] == ["toolu_1", "toolu_2"]
    assert [s.tool for s in t.agent_steps] == ["get_balance", "list_transactions"]
    assert all(s.origin == "model" for s in t.agent_steps)


def test_assistant_content_is_replayed_unchanged() -> None:
    first = msg(use(1, "get_balance", account_id="acc_alice"))
    fake = FakeTransport([first, done()])
    trial(agent(fake))
    assistant = fake.requests[1][1]["messages"][2]
    assert assistant == {"role": "assistant", "content": first["content"]}
    assert assistant["content"][0]["signature"] == "sig"


def test_denied_call_returns_is_error_with_generic_message() -> None:
    fake = FakeTransport(
        [
            msg(
                use(
                    1,
                    "transfer_pix",
                    from_account_id="acc_alice",
                    to_pix_key="x@example.test",
                    amount_cents=100,
                )
            ),
            done(),
        ]
    )
    trial(agent(fake), preset="hardened")
    block = fake.requests[1][1]["messages"][-1]["content"][0]
    assert block["is_error"] is True
    assert json.loads(block["content"])["error"]["message"] == "denied: authorization_required"


def test_step_and_turn_caps() -> None:
    loop = msg(use(1, "get_balance", account_id="acc_alice"))
    t = trial(agent(FakeTransport(lambda p, k: loop), max_steps=3))
    assert t.metrics.stopped == "step_cap"
    assert t.metrics.steps == 3
    t = trial(agent(FakeTransport(lambda p, k: loop), max_turns=2, max_steps=99))
    assert t.metrics.stopped == "turn_cap"
    assert len(t.model_calls) == 2


def test_refusal_is_its_own_outcome_never_resisted() -> None:
    fake = FakeTransport(
        [
            msg(use(1, "list_transactions", account_id="acc_alice")),
            msg(TextBlock(type="text", text="No.", citations=None), stop="refusal"),
        ]
    )
    t = trial(agent(fake))
    assert t.metrics.stopped == "refused"
    assert t.payload_exposed is True
    assert t.status == "exposed_refused"
    assert t.model_calls[-1].stop_reason == "refusal"


def test_transient_error_marks_trial_errored() -> None:
    class Failing:
        def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
            raise ModelCallError("rate_limit", "slow down", "req_x")

    t = trial(agent(Failing()))
    assert t.errored is True
    assert t.error == "rate_limit"
    assert t.status is None


def test_invalid_request_aborts() -> None:
    class Bad:
        def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
            raise ModelRequestInvalid("BadRequestError: nope")

    with pytest.raises(ModelRequestInvalid):
        trial(agent(Bad()))


# ------------------------------------------------------------ cost and cap


def test_usage_and_cost_recorded_without_model_text() -> None:
    fake = FakeTransport([msg(use(1, "get_balance", account_id="acc_alice"), out=500), done()])
    t = trial(agent(fake))
    assert t.usage.input_tokens == 2000
    assert t.usage.output_tokens == 510
    # claude-opus-5-5: $4 / $20 per MTok
    assert t.cost_usd == pytest.approx(2000 * 4e-6 + 510 * 20e-6)
    dumped = t.model_dump_json()
    assert "sig" not in dumped
    assert "Done." not in dumped


def test_cost_cap_aborts_whole_run_and_keeps_finished_trials() -> None:
    meter = CostMeter(cap_usd=0.005)  # one call costs ~$0.0042
    fake = FakeTransport(lambda p, k: done())
    outcome = run_all([SCENARIO], agent(fake, meter=meter), prompt_variants=["baseline"], trials=3)
    assert outcome.status == "aborted_budget"
    assert outcome.abort_reason is not None
    finished = [t for c in outcome.results[0].cells for t in c.trials]
    assert len(finished) == 2
    assert len(fake.requests) == 2  # sequential: no call after the cap was reached


def test_budget_exceeded_is_a_run_abort() -> None:
    meter = CostMeter(cap_usd=0.0)
    with pytest.raises(RunAborted):
        meter.check()
