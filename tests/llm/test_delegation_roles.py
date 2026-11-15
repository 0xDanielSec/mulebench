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


# ---------------------------------------------- role prompt variants (pilot 06)

PILOT_05_READER = "f308aca7113c243096f84d1a74a4864b885491804f62c7aa9d95a65538679069"
PILOT_05_PAYER = "861f709b637b84b733fae9e133e23046c14f42d66f75bc93d4ab1e3dc002524d"


def test_default_role_prompts_keep_the_pilot_05_hashes() -> None:
    from mulebench.agents.llm.prompts import role_prompt_hashes, role_prompt_sha256

    assert role_prompt_sha256("baseline", "reader") == PILOT_05_READER
    assert role_prompt_sha256("baseline", "payer") == PILOT_05_PAYER
    assert role_prompt_hashes(["baseline"], {}) == {
        "baseline/payer": PILOT_05_PAYER,
        "baseline/reader": PILOT_05_READER,
    }
    cites = role_prompt_hashes(["baseline"], {"reader": "cites_tx"})
    assert cites["baseline/payer"] == PILOT_05_PAYER
    assert cites["baseline/reader"] != PILOT_05_READER


def test_cites_tx_reaches_the_reader_only() -> None:
    from mulebench.agents.llm.prompts import READER_CITES_TX

    fake = FakeTransport(
        [
            msg(use(1, "list_transactions", account_id="acc_alice")),
            text(HANDOFF),
            text("Nothing to pay."),
        ]
    )
    a = agent(fake, role_prompts={"reader": "cites_tx"})
    run_trial(S015, "baseline", "vulnerable", "benign", 0, a)
    reader, payer = fake.requests[0][1], fake.requests[-1][1]
    assert reader["system"] == system_prompt("baseline", "reader", "cites_tx")
    assert reader["system"].endswith(READER_CITES_TX)
    assert "transaction id" in reader["system"]
    assert payer["system"] == system_prompt("baseline", "payer")
    assert fake.requests[0][0].endswith("#reader")  # cassette key form unchanged
    assert a.params["role_prompts"] == {"reader": "cites_tx"}
    assert "role_prompts" not in agent(fake).params


def test_parse_role_prompts() -> None:
    import pytest

    from mulebench.agents.llm.prompts import parse_role_prompts

    assert parse_role_prompts(None) == {}
    assert parse_role_prompts(["reader=cites_tx"]) == {"reader": "cites_tx"}
    assert parse_role_prompts(["reader=default"]) == {"reader": "default"}
    for bad in (["reader"], ["writer=x"], ["reader=nope"], ["payer=cites_tx"]):
        with pytest.raises(ValueError, match="--role-prompt"):
            parse_role_prompts(bad)
    with pytest.raises(ValueError, match="twice"):
        parse_role_prompts(["reader=cites_tx", "reader=default"])


def test_cli_records_role_prompts_and_rejects_unknown(tmp_path: Any, capsys: Any) -> None:
    from mulebench.cli import main

    base = [
        "run", "--builtin", "--scenario", "delegation-payment-instruction-015",
        "--agent", "llm", "--provider", "openai-compatible", "--model", "m",
        "--prompt-variants", "baseline", "--preset", "vulnerable", "--trials", "1",
        "--cassettes", str(tmp_path / "c"),
    ]  # fmt: skip
    assert main([*base, "--role-prompt", "reader=nope"]) == 2
    assert "unknown reader variant" in capsys.readouterr().err
    from mulebench.cli import _build_llm, _parser

    built = _build_llm(_parser().parse_args([*base, "--role-prompt", "reader=cites_tx"]))
    assert not isinstance(built, int)
    llm_agent, config, _, _ = built
    llm = config.model_dump(mode="json")
    assert getattr(llm_agent, "role_prompts", None) == {"reader": "cites_tx"}
    assert llm["role_prompts"] == {"reader": "cites_tx"}
    assert llm["role_prompt_sha256"]["baseline/payer"] == PILOT_05_PAYER
    assert llm["role_prompt_sha256"]["baseline/reader"] != PILOT_05_READER
