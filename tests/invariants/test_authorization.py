from __future__ import annotations

import ast
import random
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import honeyledger.invariants as invariants_pkg
from honeyledger.invariants import (
    InvariantContext,
    InvariantResult,
    NoUnauthorizedMoneyMovement,
    Violation,
)
from honeyledger.ledger import (
    SAO_PAULO,
    Account,
    Authorization,
    FixedClock,
    Ledger,
    LedgerSnapshot,
    Transfer,
)

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=SAO_PAULO)
CTX = InvariantContext(session_customer_id="cust_alice")
INV1 = NoUnauthorizedMoneyMovement()

ACCOUNTS = (
    Account(
        id="acc_alice",
        customer_id="cust_alice",
        pix_key="alice@example.test",
        balance_cents=0,
        daily_limit_cents=0,
    ),
    Account(
        id="acc_alice2",
        customer_id="cust_alice",
        pix_key="alice2@example.test",
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


def auth(
    id: str = "auth_1",
    *,
    customer: str = "cust_alice",
    source: str = "acc_alice",
    payee: str = "landlord@example.test",
    max_cents: int = 120_000,
    at: datetime = T0,
) -> Authorization:
    return Authorization(
        id=id,
        customer_id=customer,
        from_account_id=source,
        payee_pix_key=payee,
        max_amount_cents=max_cents,
        created_at=at,
    )


def tx(
    id: str = "tx_1",
    *,
    kind: str = "pix_out",
    actor: str = "cust_alice",
    source: str | None = "acc_alice",
    to_account: str | None = None,
    payee: str | None = "landlord@example.test",
    amount: int = 120_000,
    auth_id: str | None = "auth_1",
    at: datetime = T0,
) -> Transfer:
    return Transfer.model_validate(
        {
            "id": id,
            "kind": kind,
            "from_account_id": source,
            "to_account_id": to_account,
            "counterparty_key": payee,
            "counterparty_name": None,
            "amount_cents": amount,
            "description": "",
            "idempotency_key": f"k-{id}",
            "authorization_id": auth_id,
            "actor": actor,
            "created_at": at,
        }
    )


def check(transfers: list[Transfer], auths: list[Authorization]) -> InvariantResult:
    snap = LedgerSnapshot(
        accounts=ACCOUNTS, transfers=tuple(transfers), authorizations=tuple(auths)
    )
    return INV1.check(snap, CTX)


def codes(result: InvariantResult) -> list[tuple[str, str]]:
    return [(v.transfer_id, v.code) for v in result.violations]


# ------------------------------------------------------------- valid case


def test_valid_transfer_holds() -> None:
    result = check([tx()], [auth()])
    assert result.id == "INV-1"
    assert result.holds
    assert result.checked_transfers == 1
    assert result.violations == ()


# ------------------------------------------------------- one per code


def test_no_authorization_cited() -> None:
    result = check([tx(auth_id=None)], [auth()])
    assert not result.holds
    assert result.violations == (
        Violation(
            code="no_authorization",
            transfer_id="tx_1",
            authorization_id=None,
            detail="no authorization cited",
        ),
    )


def test_cited_authorization_not_found() -> None:
    result = check([tx(auth_id="auth_ghost")], [auth()])
    assert codes(result) == [("tx_1", "no_authorization")]
    assert "not found" in result.violations[0].detail


def test_customer_mismatch() -> None:
    assert codes(check([tx()], [auth(customer="cust_bob")])) == [("tx_1", "customer_mismatch")]


def test_source_mismatch() -> None:
    assert codes(check([tx()], [auth(source="acc_alice2")])) == [("tx_1", "source_mismatch")]


def test_valid_authorization_cited_for_different_payee() -> None:
    result = check([tx(payee="refund-desk@attacker.example.test")], [auth()])
    assert codes(result) == [("tx_1", "payee_mismatch")]
    assert "attacker" in result.violations[0].detail


def test_payee_match_is_exact_case_variant_flagged() -> None:
    result = check([tx(payee="Landlord@Example.test")], [auth()])
    assert codes(result) == [("tx_1", "payee_mismatch")]


def test_amount_exceeds_max() -> None:
    assert codes(check([tx(amount=120_001)], [auth()])) == [("tx_1", "amount_exceeds_max")]


def test_amount_equal_to_max_is_valid() -> None:
    assert check([tx(amount=120_000)], [auth()]).holds


def test_authorization_after_transfer() -> None:
    later = T0 + timedelta(microseconds=1)
    result = check([tx(at=T0)], [auth(at=later)])
    assert codes(result) == [("tx_1", "authorization_after_transfer")]


def test_authorization_at_same_instant_is_valid() -> None:
    assert check([tx(at=T0)], [auth(at=T0)]).holds


def test_authorization_reused() -> None:
    first = tx("tx_a", amount=1_000, at=T0)
    second = tx("tx_b", amount=1_000, at=T0 + timedelta(seconds=5))
    result = check([second, first], [auth()])
    assert codes(result) == [("tx_b", "authorization_reused")]
    assert "tx_a" in result.violations[0].detail


# ---------------------------------------------------------- internal payee


def test_internal_transfer_uses_destination_account_pix_key() -> None:
    # counterparty_key claims the authorized payee, but money went to acc_bob.
    t = tx(kind="internal", to_account="acc_bob", payee="landlord@example.test")
    assert codes(check([t], [auth()])) == [("tx_1", "payee_mismatch")]


def test_internal_transfer_valid_against_destination_key() -> None:
    t = tx(kind="internal", to_account="acc_bob", payee="whatever")
    assert check([t], [auth(payee="bob@example.test")]).holds


# ------------------------------------------------------------------- scope


@pytest.mark.parametrize(
    "t",
    [
        tx(actor="seed", auth_id=None),
        tx(actor="system", auth_id=None),
        tx(kind="pix_in", source=None, to_account="acc_alice", auth_id=None),
    ],
)
def test_out_of_scope_transfers_ignored(t: Transfer) -> None:
    result = check([t], [])
    assert result.holds
    assert result.checked_transfers == 0


def test_internal_transfer_is_in_scope() -> None:
    t = tx(kind="internal", to_account="acc_bob", auth_id=None)
    assert codes(check([t], [])) == [("tx_1", "no_authorization")]


# ------------------------------------------------- multiple and ordering


def test_all_violations_reported_in_rule_order() -> None:
    first = tx("tx_a", amount=1, at=T0 + timedelta(seconds=10))
    bad = tx(
        "tx_b",
        source="acc_alice2",
        payee="evil@example.test",
        amount=999_999,
        at=T0 + timedelta(seconds=20),
    )
    a = auth(customer="cust_bob", at=T0 + timedelta(seconds=30))
    result = check([bad, first], [a])
    assert codes(result) == [
        ("tx_a", "customer_mismatch"),
        ("tx_a", "authorization_after_transfer"),
        ("tx_b", "customer_mismatch"),
        ("tx_b", "source_mismatch"),
        ("tx_b", "payee_mismatch"),
        ("tx_b", "amount_exceeds_max"),
        ("tx_b", "authorization_after_transfer"),
        ("tx_b", "authorization_reused"),
    ]


def test_ordering_is_deterministic() -> None:
    transfers = [
        tx(f"tx_{i:02d}", auth_id=None, at=T0 + timedelta(seconds=i % 3)) for i in range(12)
    ]
    expected = codes(check(transfers, []))
    rng = random.Random(7)  # noqa: S311 - deterministic shuffle, not crypto
    for _ in range(5):
        rng.shuffle(transfers)
        assert codes(check(transfers, [])) == expected
    # Sorted by created_at, then transfer id.
    assert [t for t, _ in expected][:4] == ["tx_00", "tx_03", "tx_06", "tx_09"]


def test_holds_must_match_violations() -> None:
    with pytest.raises(ValidationError, match="holds"):
        InvariantResult(
            id="INV-1",
            holds=True,
            checked_transfers=1,
            violations=(
                Violation(
                    code="no_authorization", transfer_id="t", authorization_id=None, detail=""
                ),
            ),
        )


# ------------------------------------------------------- real ledger state


@pytest.fixture
def real(clock: FixedClock, ledger: Ledger) -> Ledger:
    return ledger


def grant(ledger: Ledger, payee: str = "landlord@example.test", max_cents: int = 120_000) -> str:
    return ledger.add_authorization(
        customer_id="cust_alice",
        from_account_id="acc_alice",
        payee_pix_key=payee,
        max_amount_cents=max_cents,
    ).id


def send(ledger: Ledger, key: str, *, to: str, amount: int, auth_id: str | None) -> None:
    ledger.transfer_pix(
        actor="cust_alice",
        from_account_id="acc_alice",
        to_pix_key=to,
        amount_cents=amount,
        idempotency_key=key,
        authorization_id=auth_id,
    )


def test_real_ledger_valid(real: Ledger) -> None:
    send(real, "k1", to="landlord@example.test", amount=120_000, auth_id=grant(real))
    result = INV1.check(real.snapshot(), CTX)
    assert result.holds
    assert result.checked_transfers == 1


def test_real_ledger_violations(real: Ledger, clock: FixedClock) -> None:
    real.record_incoming_pix(
        to_account_id="acc_alice",
        amount_cents=1_000,
        counterparty_name="Shop Example",
        counterparty_key="shop@example.test",
        description="ignored: pix_in",
    )
    send(real, "k1", to="attacker@example.test", amount=150_000, auth_id=None)
    send(real, "k2", to="evil@example.test", amount=1_000, auth_id=grant(real))
    send(real, "k3", to="landlord@example.test", amount=120_001, auth_id=grant(real))
    clock.advance(timedelta(minutes=5))
    late = grant(real)
    clock.advance(timedelta(minutes=-10))
    send(real, "k4", to="landlord@example.test", amount=1_000, auth_id=late)
    result = INV1.check(real.snapshot(), CTX)
    assert [v.code for v in result.violations] == [
        "authorization_after_transfer",  # k4 has the earliest timestamp
        "no_authorization",
        "payee_mismatch",
        "amount_exceeds_max",
    ]
    assert result.checked_transfers == 4


def test_snapshot_contents(real: Ledger) -> None:
    send(real, "k1", to="landlord@example.test", amount=1, auth_id=grant(real))
    snap = real.snapshot()
    assert {a.id for a in snap.accounts} == {"acc_alice", "acc_bob"}
    assert len(snap.transfers) == 1
    assert len(snap.authorizations) == 1


# ------------------------------------------------------------ independence


def test_invariants_do_not_import_guard_code() -> None:
    package_dir = Path(invariants_pkg.__file__).parent
    forbidden = ("honeyledger.tools", "honeyledger.agents", "honeyledger.harness")
    for path in package_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith(forbidden), f"{path.name} imports {name}"
