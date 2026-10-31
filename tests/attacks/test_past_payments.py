from __future__ import annotations

from datetime import timedelta

import pytest
import yaml

from mulebench.attacks import ScenarioError, parse_scenario, render
from mulebench.harness.seed import seed_cell
from tests.attacks.test_loader import Doc, base, errors_for


def with_past(doc: Doc, **overrides: object) -> Doc:
    payment: dict[str, object] = {
        "ref": "pp_gym",
        "from_account": "acc_alice",
        "to_pix_key": "gym@example.test",
        "amount_cents": 15_000,
        "days_ago": 7,
    }
    payment.update(overrides)
    doc["setup"]["past_payments"] = [payment]
    return doc


def test_past_payment_is_seeded_before_the_session() -> None:
    scenario = parse_scenario(yaml.safe_dump(with_past(base()), sort_keys=False))
    ledger, clock, _ = seed_cell(scenario, render(scenario, "benign"))
    try:
        # Back at the session clock, then +1 s for the one seeded incoming Pix.
        assert clock.now() == scenario.setup.clock + timedelta(seconds=1)
        (past,) = [t for t in ledger.snapshot().transfers if t.kind == "pix_out"]
        assert past.kind == "pix_out"
        assert past.counterparty_key == "gym@example.test"
        assert past.created_at == scenario.setup.clock - timedelta(days=7)
        start = scenario.setup.accounts[0].balance_cents
        assert ledger.get_balance("acc_alice") == start - 15_000 + 1_000  # + seeded pix_in
    finally:
        ledger.close()


def test_past_payments_seeded_oldest_first() -> None:
    doc = with_past(base())
    doc["setup"]["past_payments"].append(
        {
            "ref": "pp_old",
            "from_account": "acc_alice",
            "to_pix_key": "old@example.test",
            "amount_cents": 1,
            "days_ago": 30,
        }
    )
    scenario = parse_scenario(yaml.safe_dump(doc, sort_keys=False))
    ledger, _, _ = seed_cell(scenario, render(scenario, "benign"))
    try:
        seeded = sorted(
            (t for t in ledger.snapshot().transfers if t.kind == "pix_out"), key=lambda t: t.id
        )
        assert [t.counterparty_key for t in seeded] == ["old@example.test", "gym@example.test"]
    finally:
        ledger.close()


def errors_with(**overrides: object) -> str:
    def mutate(doc: Doc) -> None:
        with_past(doc, **overrides)

    return errors_for(mutate)


@pytest.mark.parametrize("days", [0, 1, -3])
def test_days_ago_must_be_at_least_two(days: int) -> None:
    assert "days_ago" in errors_with(days_ago=days)


def test_past_payment_source_must_exist() -> None:
    message = errors_with(from_account="acc_ghost")
    assert "past payment pp_gym: unknown account 'acc_ghost'" in message


def test_past_payment_ref_shares_id_namespace() -> None:
    assert "duplicate id: 'acc_alice'" in errors_with(ref="acc_alice")


def test_past_payment_rejects_unknown_keys() -> None:
    with pytest.raises(ScenarioError):
        parse_scenario(yaml.safe_dump(with_past(base(), note="x"), sort_keys=False))
