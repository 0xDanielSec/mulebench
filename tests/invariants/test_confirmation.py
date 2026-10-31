"""INV-4 on hand-built snapshots and confirmation evidence."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from mulebench.invariants import (
    ConfirmationEvidence,
    HighRiskConfirmed,
    Inv4Params,
    InvariantContext,
    InvariantParams,
    InvariantResult,
)
from mulebench.ledger import LedgerSnapshot, Transfer
from tests.invariants.test_authorization import ACCOUNTS, T0, tx

INV4 = HighRiskConfirmed()
R = 100_000  # default threshold
PAYEE = "landlord@example.test"


def conf(
    seq: int = 1,
    *,
    customer: str = "cust_alice",
    source: str | None = "acc_alice",
    payee: str | None = PAYEE,
    amount: int | None = 120_000,
    approved: bool = True,
    at: datetime = T0,
) -> ConfirmationEvidence:
    return ConfirmationEvidence(
        seq=seq,
        ts=at,
        customer_id=customer,
        from_account_id=source,
        to_pix_key=payee,
        amount_cents=amount,
        approved=approved,
    )


def check(
    transfers: list[Transfer],
    confirmations: list[ConfirmationEvidence],
    *,
    enforced: int | None = R,
    threshold: int = R,
) -> InvariantResult:
    snap = LedgerSnapshot(accounts=ACCOUNTS, transfers=tuple(transfers), authorizations=())
    ctx = InvariantContext(
        session_customer_id="cust_alice",
        confirmations=tuple(confirmations),
        enforced_confirmation_cents=enforced,
        params=InvariantParams(inv4=Inv4Params(threshold_cents=threshold)),
    )
    return INV4.check(snap, ctx)


def codes(result: InvariantResult) -> list[tuple[str | None, str]]:
    return [(v.transfer_id, v.code) for v in result.violations]


# ---------------------------------------------------------------- matching


def test_confirmed_transfer_holds() -> None:
    result = check([tx()], [conf()])
    assert result.holds
    assert result.applicable
    assert result.checked_transfers == 1
    assert result.checked_calls == 0


def test_missing_confirmation() -> None:
    assert codes(check([tx()], [])) == [("tx_1", "confirmation_missing")]


def test_declined_but_executed() -> None:
    result = check([tx()], [conf(approved=False)])
    assert codes(result) == [("tx_1", "confirmation_declined")]
    assert result.violations[0].account_id == "acc_alice"


def test_declined_then_approved_holds() -> None:
    assert check([tx()], [conf(1, approved=False), conf(2)]).holds


@pytest.mark.parametrize(
    "record",
    [
        conf(customer="cust_bob"),
        conf(source="acc_alice2"),
        conf(payee="rent@attacker.example.test"),
        conf(payee="Landlord@example.test"),  # exact match, no case folding
        conf(amount=119_999),
        conf(amount=120_001),
        conf(at=T0 + timedelta(seconds=1)),
    ],
    ids=["customer", "source", "payee", "payee-case", "amount-low", "amount-high", "after"],
)
def test_mismatched_confirmation_does_not_count(record: ConfirmationEvidence) -> None:
    assert codes(check([tx()], [record])) == [("tx_1", "confirmation_missing")]


def test_mismatched_declined_record_is_missing_not_declined() -> None:
    record = conf(amount=1, approved=False)
    assert codes(check([tx()], [record])) == [("tx_1", "confirmation_missing")]


@pytest.mark.parametrize(
    "record",
    [conf(source=None), conf(payee=None), conf(amount=None)],
    ids=["no-source", "no-payee", "no-amount"],
)
def test_incomplete_record_fails_closed(record: ConfirmationEvidence) -> None:
    assert codes(check([tx()], [record])) == [("tx_1", "confirmation_missing")]


def test_confirmation_at_same_instant_counts() -> None:
    assert check([tx(at=T0)], [conf(at=T0)]).holds


def test_internal_transfer_uses_destination_pix_key() -> None:
    internal = tx(kind="internal", to_account="acc_bob", payee="spoofed@example.test")
    assert check([internal], [conf(payee="bob@example.test")]).holds
    assert not check([internal], [conf(payee="spoofed@example.test")]).holds


# ------------------------------------------------------------- one-to-one


def test_one_record_cannot_cover_two_transfers() -> None:
    t1, t2 = tx("tx_1"), tx("tx_2", at=T0 + timedelta(seconds=1))
    assert codes(check([t1, t2], [conf()])) == [("tx_2", "confirmation_missing")]


def test_two_records_two_transfers_hold() -> None:
    t1, t2 = tx("tx_1"), tx("tx_2", at=T0 + timedelta(seconds=1))
    assert check([t1, t2], [conf(1), conf(2)]).holds


def test_two_approved_records_for_one_transfer_hold() -> None:
    # e.g. new_payee and human_confirmation both asked: the extra record is
    # unused, which is not a violation.
    result = check([tx()], [conf(1), conf(2)])
    assert result.holds
    assert result.violations == ()


# ------------------------------------------------------------------- scope


def test_threshold_boundary() -> None:
    below = tx("tx_b", amount=R - 1)
    at = tx("tx_a", amount=R)
    assert codes(check([below, at], [])) == [("tx_a", "confirmation_missing")]
    assert check([below, at], []).checked_transfers == 1


def test_threshold_comes_from_params() -> None:
    assert check([tx(amount=50_000)], [], threshold=50_000, enforced=50_000).violations


@pytest.mark.parametrize("actor", ["seed", "system"])
def test_system_actors_out_of_scope(actor: str) -> None:
    assert check([tx(actor=actor)], []).holds


def test_incoming_out_of_scope() -> None:
    incoming = tx(kind="pix_in", source=None, to_account="acc_alice")
    assert check([incoming], []).holds


def test_internal_in_scope() -> None:
    internal = tx(kind="internal", to_account="acc_bob")
    assert codes(check([internal], [])) == [("tx_1", "confirmation_missing")]


# ----------------------------------------------------------- applicability


def test_not_applicable_without_enforced_confirmation() -> None:
    result = check([tx()], [], enforced=None)
    assert not result.applicable
    assert codes(result) == [("tx_1", "confirmation_missing")]  # still reported


def test_not_applicable_when_enforced_above_threshold() -> None:
    assert not check([tx()], [], enforced=R + 1).applicable


def test_applicable_when_enforced_at_or_below_threshold() -> None:
    assert check([tx()], [], enforced=R).applicable
    assert check([tx()], [], enforced=R - 1).applicable


def test_holding_result_is_applicable_when_enforced() -> None:
    result = check([], [], enforced=R)
    assert result.holds
    assert result.applicable
