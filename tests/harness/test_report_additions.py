"""Trial results store final text (never reasoning) and balances; scenarios their hash."""

from __future__ import annotations

from typing import Any

from mulebench.agents import ScriptedAgent
from mulebench.agents.llm import LLMAgent
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import load_builtin, scenario_sha256
from mulebench.harness import run_all
from mulebench.harness.runner import run_trial
from tests.llm.test_malformed_calls import completion

S001 = "pix-description-injection-001"


def scenario(sid: str = S001) -> Any:
    return next(s for s in load_builtin() if s.id == sid)


def test_ledger_before_and_after_balances() -> None:
    t = run_trial(scenario(), "none", "vulnerable", "attack", 0, ScriptedAgent())
    assert t.ledger_before is not None
    assert t.ledger_after is not None
    assert list(t.ledger_before) == sorted(t.ledger_before)
    out = sum(o.amount_cents for o in t.outgoing_transfers if o.actor != "seed")
    assert out > 0
    assert t.ledger_before["acc_alice"] - t.ledger_after["acc_alice"] == out


def test_scripted_final_text_is_stored() -> None:
    t = run_trial(scenario(), "none", "vulnerable", "attack", 0, ScriptedAgent())
    assert isinstance(t.final_text, str)
    assert t.final_text


def test_final_text_never_contains_reasoning() -> None:
    body = completion({"role": "assistant", "content": "<think>SECRET-PLAN</think>All done."})
    chat = OpenAICompatChatModel(FakeTransport(lambda p, k: body))
    agent = LLMAgent(chat, model="tiny:1b", effort="none", max_tokens=256)
    t = run_trial(scenario(), "baseline", "vulnerable", "benign", 0, agent)
    assert t.final_text == "All done."
    assert "SECRET-PLAN" not in t.model_dump_json()


def test_scenario_hash_recorded_and_stable() -> None:
    s = scenario()
    result = run_all([s], ScriptedAgent(), presets=("vulnerable",)).results[0]
    assert result.scenario_sha256 == scenario_sha256(s) == scenario_sha256(scenario())
    changed = s.model_copy(update={"name": s.name + " (edited)"})
    assert scenario_sha256(changed) != scenario_sha256(s)
