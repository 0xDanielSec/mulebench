from __future__ import annotations

import sqlite3

import pytest

from mulebench.ledger import (
    MAX_DESCRIPTION_CHARS,
    AuthorizationAlreadyUsed,
    DescriptionTooLong,
    InvalidAmount,
    Ledger,
    UnknownAccount,
    UnknownAuthorization,
    UnknownCustomer,
)
from tests.conftest import T0


def grant(ledger: Ledger, amount: int = 10_000, payee: str = "ext@example.test") -> str:
    return ledger.add_authorization(
        customer_id="cust_alice",
        from_account_id="acc_alice",
        payee_pix_key=payee,
        max_amount_cents=amount,
    ).id


def pay_with(ledger: Ledger, auth_id: str | None, key: str, amount: int = 1_000) -> None:
    ledger.transfer_pix(
        actor="cust_alice",
        from_account_id="acc_alice",
        to_pix_key="ext@example.test",
        amount_cents=amount,
        idempotency_key=key,
        authorization_id=auth_id,
    )


def test_add_and_get_authorization(ledger: Ledger) -> None:
    auth_id = grant(ledger)
    auth = ledger.get_authorization(auth_id)
    assert auth.customer_id == "cust_alice"
    assert auth.payee_pix_key == "ext@example.test"
    assert auth.max_amount_cents == 10_000
    assert auth.created_at == T0
    entry = ledger.audit_entries()[-1]
    assert (entry.actor, entry.action) == ("customer_channel", "authorization_added")
    assert not ledger.authorization_used(auth_id)


def test_add_authorization_validates_references(ledger: Ledger) -> None:
    with pytest.raises(UnknownCustomer):
        ledger.add_authorization(
            customer_id="cust_nope",
            from_account_id="acc_alice",
            payee_pix_key="x@example.test",
            max_amount_cents=1,
        )
    with pytest.raises(UnknownAccount):
        ledger.add_authorization(
            customer_id="cust_alice",
            from_account_id="acc_nope",
            payee_pix_key="x@example.test",
            max_amount_cents=1,
        )
    with pytest.raises(InvalidAmount):
        grant(ledger, amount=0)
    assert ledger.audit_entries()[-1].action == "authorization_rejected"


def test_unknown_authorization(ledger: Ledger) -> None:
    with pytest.raises(UnknownAuthorization):
        ledger.get_authorization("auth_nope")
    with pytest.raises(UnknownAuthorization):
        pay_with(ledger, "auth_nope", key="k1")
    assert ledger.get_balance("acc_alice") == 500_000


def test_authorization_is_single_use(ledger: Ledger) -> None:
    auth_id = grant(ledger)
    pay_with(ledger, auth_id, key="k1")
    assert ledger.authorization_used(auth_id)
    with pytest.raises(AuthorizationAlreadyUsed):
        pay_with(ledger, auth_id, key="k2")
    assert ledger.get_balance("acc_alice") == 499_000
    assert ledger.audit_entries()[-1].result["error"] == "AuthorizationAlreadyUsed"


def test_idempotent_replay_with_same_authorization_is_not_a_second_use(ledger: Ledger) -> None:
    auth_id = grant(ledger)
    pay_with(ledger, auth_id, key="k1")
    pay_with(ledger, auth_id, key="k1")
    assert ledger.get_balance("acc_alice") == 499_000


def test_ledger_does_not_evaluate_authorization_policy(ledger: Ledger) -> None:
    # Authorization for a different payee and a smaller amount: the ledger still
    # accepts it. Matching is tools-layer policy.
    auth_id = grant(ledger, amount=1, payee="other@example.test")
    pay_with(ledger, auth_id, key="k1", amount=5_000)
    assert ledger.get_balance("acc_alice") == 495_000


def test_unique_index_enforced_at_db_level(ledger: Ledger) -> None:
    auth_id = grant(ledger)
    pay_with(ledger, auth_id, key="k1")
    with pytest.raises(sqlite3.IntegrityError, match="authorization_id"):
        ledger._conn.execute(
            "INSERT INTO transfers (id, kind, from_account_id, amount_cents,"
            " authorization_id, actor, created_at)"
            " VALUES ('tx_raw', 'pix_out', 'acc_alice', 1, ?, 'raw', 'x')",
            (auth_id,),
        )


def test_get_transfer_and_clock(ledger: Ledger) -> None:
    pay_with(ledger, None, key="k1")
    tx = ledger.list_transfers("acc_alice")[0]
    assert ledger.get_transfer(tx.id) == tx
    assert ledger.clock.now() == T0


def test_inbound_description_capped_at_140(ledger: Ledger) -> None:
    ok = "x" * MAX_DESCRIPTION_CHARS
    ledger.record_incoming_pix(
        to_account_id="acc_alice",
        amount_cents=1,
        counterparty_name="Shop Example",
        counterparty_key="shop@example.test",
        description=ok,
    )
    with pytest.raises(DescriptionTooLong):
        ledger.record_incoming_pix(
            to_account_id="acc_alice",
            amount_cents=1,
            counterparty_name="Shop Example",
            counterparty_key="shop@example.test",
            description=ok + "x",
        )
    assert ledger.audit_entries()[-1].action == "pix_in_rejected"
    assert ledger.get_balance("acc_alice") == 500_001
