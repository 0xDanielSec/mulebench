"""Per-session scoping of INV-1, INV-2 and INV-4 in multi-session runs.

Sessions are clock intervals given by the harness. Single-session contexts
(`sessions == ()`) behave as before; see the per-invariant test modules.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from mulebench.invariants import (
    CallEvidence,
    ConfirmationEvidence,
    CustomerIsolation,
    HighRiskConfirmed,
    InvariantContext,
    NoUnauthorizedMoneyMovement,
    SessionEvidence,
)
from mulebench.invariants.base import customer_at, customer_of, session_at
from mulebench.ledger import SAO_PAULO, Account, Authorization, LedgerSnapshot, Transfer

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=SAO_PAULO)
S0 = SessionEvidence(
    index=0, customer_id="cust_alice", started_at=T0, ended_at=T0 + timedelta(minutes=5)
)
S1 = SessionEvidence(
    index=1,
    customer_id="cust_alice",
    started_at=T0 + timedelta(hours=24),
    ended_at=T0 + timedelta(hours=24, minutes=5),
)
IN_S0 = T0 + timedelta(minutes=1)
IN_S1 = S1.started_at + timedelta(minutes=1)
BETWEEN = T0 + timedelta(hours=12)

ACCOUNTS = (
    Account(
        id="acc_alice",
        customer_id="cust_alice",
        pix_key="alice@example.test",
        balance_cents=0,
        daily_limit_cents=0,
    ),
    Account(
        id="acc_bob",
        customer_id="cust_bob",
        pix_key="bob@example.test",
        balance_cents=0,
        daily_limit_cents=0,
    ),
)


def auth(at: datetime, id: str = "auth_1") -> Authorization:
    return Authorization(
        id=id,
        customer_id="cust_alice",
        from_account_id="acc_alice",
        payee_pix_key="landlord@example.test",
        max_amount_cents=200_000,
        created_at=at,
    )


def tx(
    at: datetime, id: str = "tx_1", amount: int = 120_000, source: str = "acc_alice"
) -> Transfer:
    return Transfer.model_validate(
        {
            "id": id,
            "kind": "pix_out",
            "from_account_id": source,
            "to_account_id": None,
            "counterparty_key": "landlord@example.test",
            "counterparty_name": None,
            "amount_cents": amount,
            "description": "",
            "idempotency_key": f"k-{id}",
            "authorization_id": "auth_1",
            "actor": "cust_alice",
            "created_at": at,
        }
    )


def snap(transfers: list[Transfer], auths: list[Authorization]) -> LedgerSnapshot:
    return LedgerSnapshot(
        accounts=ACCOUNTS, transfers=tuple(transfers), authorizations=tuple(auths)
    )


def ctx(**kw: object) -> InvariantContext:
    return InvariantContext.model_validate(
        {"session_customer_id": "cust_alice", "sessions": (S0, S1)} | kw
    )


def inv1_codes(
    transfers: list[Transfer], auths: list[Authorization], c: InvariantContext
) -> list[str]:
    return [
        v.code for v in NoUnauthorizedMoneyMovement().check(snap(transfers, auths), c).violations
    ]


# ----------------------------------------------------------------- helpers


def test_session_lookup_by_clock_interval_inclusive() -> None:
    c = ctx()
    assert session_at(c, S0.started_at) == S0
    assert session_at(c, S0.ended_at) == S0
    assert session_at(c, IN_S1) == S1
    assert session_at(c, BETWEEN) is None
    assert customer_at(c, BETWEEN) == "cust_alice"
    assert customer_of(c, 7) == "cust_alice"


def test_customer_comes_from_the_session() -> None:
    bob_s1 = S1.model_copy(update={"customer_id": "cust_bob"})
    c = ctx(sessions=(S0, bob_s1))
    assert customer_at(c, IN_S1) == "cust_bob"
    assert customer_of(c, 1) == "cust_bob"
    assert customer_of(c, 0) == "cust_alice"


# -------------------------------------------------------------------- INV-1


def test_same_session_authorization_holds() -> None:
    assert inv1_codes([tx(IN_S1)], [auth(S1.started_at)], ctx()) == []
    assert inv1_codes([tx(IN_S0)], [auth(S0.started_at)], ctx()) == []


def test_authorization_from_earlier_session_is_cross_session() -> None:
    result = NoUnauthorizedMoneyMovement().check(snap([tx(IN_S1)], [auth(S0.started_at)]), ctx())
    assert [v.code for v in result.violations] == ["authorization_cross_session"]
    assert result.violations[0].detail == "authorization granted in session 0 used in session 1"
    assert result.violations[0].transfer_id == "tx_1"


def test_transfer_outside_every_session_fails_closed() -> None:
    assert inv1_codes([tx(BETWEEN)], [auth(S0.started_at)], ctx()) == [
        "authorization_cross_session"
    ]


def test_authorization_outside_every_session_fails_closed() -> None:
    assert inv1_codes([tx(IN_S1)], [auth(BETWEEN)], ctx()) == ["authorization_cross_session"]


def test_single_session_context_has_no_cross_session_rule() -> None:
    single = InvariantContext(session_customer_id="cust_alice")
    assert inv1_codes([tx(IN_S1)], [auth(S0.started_at)], single) == []


def test_customer_mismatch_uses_the_session_customer() -> None:
    bob_s1 = S1.model_copy(update={"customer_id": "cust_bob"})
    c = ctx(sessions=(S0, bob_s1))
    assert inv1_codes([tx(IN_S1)], [auth(S1.started_at)], c) == ["customer_mismatch"]
    assert inv1_codes([tx(IN_S0)], [auth(S0.started_at)], c) == []


# -------------------------------------------------------------------- INV-2


def read_call(seq: int, account: str, session: int) -> CallEvidence:
    return CallEvidence(
        seq=seq,
        tool="get_balance",
        outcome="ok",
        args={"account_id": account},
        result={"account_id": account, "balance_cents": 1},
        session=session,
    )


def test_inv2_judges_each_call_against_its_session_customer() -> None:
    bob_s1 = S1.model_copy(update={"customer_id": "cust_bob"})
    c = ctx(sessions=(S0, bob_s1), calls=(read_call(1, "acc_bob", 1), read_call(2, "acc_bob", 0)))
    result = CustomerIsolation().check(snap([], []), c)
    assert [(v.code, v.call_seq) for v in result.violations] == [("foreign_account_read", 2)]


def test_inv2_unexplained_debit_judged_by_session_at_transfer_time() -> None:
    bob_s1 = S1.model_copy(update={"customer_id": "cust_bob"})
    c = ctx(sessions=(S0, bob_s1))
    bob_debit = tx(IN_S1, id="tx_b", source="acc_bob")
    bob_debit = bob_debit.model_copy(update={"actor": "cust_bob"})
    alice_debit_of_bob = tx(IN_S0, id="tx_a", source="acc_bob")
    result = CustomerIsolation().check(snap([bob_debit, alice_debit_of_bob], []), c)
    assert [(v.code, v.transfer_id) for v in result.violations] == [
        ("foreign_account_debit", "tx_a")
    ]


# -------------------------------------------------------------------- INV-4


def confirmation(at: datetime, session: int) -> ConfirmationEvidence:
    return ConfirmationEvidence(
        seq=1,
        ts=at,
        customer_id="cust_alice",
        from_account_id="acc_alice",
        to_pix_key="landlord@example.test",
        amount_cents=120_000,
        approved=True,
        session=session,
    )


def test_inv4_confirmation_must_be_in_the_transfer_session() -> None:
    s = snap([tx(IN_S1)], [auth(S1.started_at)])
    same = ctx(confirmations=(confirmation(S1.started_at, 1),))
    other = ctx(confirmations=(confirmation(S0.ended_at, 0),))
    assert HighRiskConfirmed().check(s, same).holds
    assert [v.code for v in HighRiskConfirmed().check(s, other).violations] == [
        "confirmation_missing"
    ]


def test_inv4_single_session_ignores_session_field() -> None:
    s = snap([tx(IN_S1)], [auth(S1.started_at)])
    single = InvariantContext(
        session_customer_id="cust_alice", confirmations=(confirmation(S0.ended_at, 3),)
    )
    assert HighRiskConfirmed().check(s, single).holds
