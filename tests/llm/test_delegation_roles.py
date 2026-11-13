"""LLMAgent in both delegation roles, with a fake transport (offline)."""

from __future__ import annotations

from typing import Any

from anthropic.types import TextBlock

from mulebench.agents.llm.prompts import PROMPTS, ROLE_PROMPTS, system_prompt
from mulebench.agents.llm.transport import FakeTransport
from mulebench.attacks import BUILTIN_SCENARIOS_DIR, load_scenario
from mulebench.harness import run_trial
from tests.llm.test_llm_agent import agent, msg, use

S015 = load_scenario(BUILTIN_SCENARIOS_DIR / "delegation-payment-instruction-015.yaml")
HANDOFF = "PAY payee=energy@example.test amount_cents=28740 bill_ref=energy-jan"


def text(value: str) -> dict[str, Any]:
    return msg(TextBlock(type="text", text=value, citations=None), stop="end_turn")


def test_llm_plays_both_roles_with_scoped_tools_and_role_prompts() -> None:
    fake = FakeTransport(
        [
            # Reader: one read, then the handoff as its final answer.
            msg(use(1, "list_transactions", account_id="acc_alice")),
            text(HANDOFF),
            # Payer: pays from the handoff, citing the note's authorization.
            msg(
                use(
                    2,
                    "transfer_pix",
                    from_account_id="acc_alice",
                    to_pix_key="energy@example.test",
                    amount_cents=28740,
                    authorization_id="auth_0003",
                )
            ),
            text("Paid."),
        ]
    )
    t = run_trial(S015, "baseline", "vulnerable", "benign", 0, agent(fake))
    keys = [k for k, _ in fake.requests]
    assert keys[0].endswith("#reader")
    assert keys[-1].endswith("#payer")
    reader, payer = fake.requests[0][1], fake.requests[-1][1]
    assert reader["system"] == system_prompt("baseline", "reader")
    assert payer["system"] == system_prompt("baseline", "payer")
    assert [x["name"] for x in reader["tools"]] == ["get_balance", "list_transactions"]
    assert [x["name"] for x in payer["tools"]] == ["open_dispute", "transfer_pix"]
    payer_request = payer["messages"][0]["content"]
    assert HANDOFF in payer_request
    assert S015.user_task.request not in payer_request
    assert t.handoff is not None
    assert t.handoff.reader_text == HANDOFF
    assert t.benign_pass is True


def test_role_prompts_extend_and_do_not_change_variant_hashes() -> None:
    for variant in PROMPTS:
        assert system_prompt(variant) == PROMPTS[variant]
        for role, extra in ROLE_PROMPTS.items():
            assert system_prompt(variant, role).startswith(PROMPTS[variant])
            assert system_prompt(variant, role).endswith(extra)
