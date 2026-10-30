"""Crash consistency: a failure at any point of an operation commits nothing.

Faults are injected (a) between the state change and the audit write, (b) at
every SQL statement of a transfer, (c) in the rejected-audit path, and (d) by
killing a separate process in the middle of a transaction on a file database.
After each fault: state and audit log equal the pre-call state, the audit hash
chain verifies, and the ledger keeps working.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from mulebench.ledger import FixedClock, Ledger, LedgerSnapshot
from tests.conftest import counter_ids, seed


class Boom(Exception):
    pass


def state(led: Ledger) -> tuple[LedgerSnapshot, list[tuple[int, str, str]]]:
    audit = [(e.seq, e.action, e.hash) for e in led.audit_entries()]
    return led.snapshot(), audit


def internal_transfer(led: Ledger, key: str = "k1") -> None:
    led.transfer_pix(
        actor="cust_alice",
        from_account_id="acc_alice",
        to_pix_key="bob@example.test",  # internal: debit AND credit
        amount_cents=1_000,
        idempotency_key=key,
    )


def assert_unchanged_and_usable(led: Ledger, before: Any) -> None:
    assert state(led) == before, "partial state was committed"
    assert not led._conn.in_transaction, "transaction left open"
    assert led.verify_audit_chain().ok
    internal_transfer(led)  # same key: must be a fresh transfer, not a replay
    assert led.get_balance("acc_bob") == 10_000 + 1_000
    assert led.audit_entries()[-1].action == "transfer"
    assert led.verify_audit_chain().ok


# ---------------------------------------- (a) between state and audit write


@pytest.mark.parametrize("exc_type", [Boom, KeyboardInterrupt])
def test_fault_between_state_change_and_audit_write(
    ledger: Ledger, exc_type: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    before = state(ledger)
    real = ledger._audit

    def failing(actor: str, action: str, *args: Any) -> None:
        if action == "transfer":
            raise exc_type("audit write failed")
        real(actor, action, *args)

    monkeypatch.setattr(ledger, "_audit", failing)
    with pytest.raises(exc_type):
        internal_transfer(ledger)
    monkeypatch.undo()
    assert_unchanged_and_usable(ledger, before)


def test_fault_in_dispute_audit_write(ledger: Ledger, monkeypatch: pytest.MonkeyPatch) -> None:
    internal_transfer(ledger, "k0")
    tx = ledger.list_transfers("acc_alice")[0].id
    before = state(ledger)
    real = ledger._audit

    def failing(actor: str, action: str, *args: Any) -> None:
        if action == "dispute_opened":
            raise Boom
        real(actor, action, *args)

    monkeypatch.setattr(ledger, "_audit", failing)
    with pytest.raises(Boom):
        ledger.open_dispute(actor="cust_alice", transfer_id=tx, reason="x")
    monkeypatch.undo()
    count = ledger._conn.execute("SELECT COUNT(*) FROM disputes").fetchone()[0]
    assert count == 0
    assert state(ledger) == before
    assert not ledger._conn.in_transaction


# ------------------------------------------- (b) at every SQL statement


class FaultyConnection:
    """Delegates to a sqlite3 connection; raises before the N-th execute."""

    def __init__(self, conn: Any, fail_at: int | None, exc: BaseException) -> None:
        self._conn = conn
        self.fail_at = fail_at
        self.exc = exc
        self.statements: list[str] = []

    def execute(self, sql: str, *params: Any) -> Any:
        if self.fail_at is not None and len(self.statements) == self.fail_at:
            self.fail_at = None  # one fault only
            raise self.exc
        self.statements.append(sql.split()[0] + " " + " ".join(sql.split()[1:3]))
        return self._conn.execute(sql, *params)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def transfer_statements(clock: FixedClock) -> list[str]:
    led = Ledger(clock=clock, id_factory=counter_ids())
    seed(led)
    proxy = FaultyConnection(led._conn, None, Boom())
    led._conn = proxy  # type: ignore[assignment]
    internal_transfer(led)
    led.close()
    return proxy.statements


def test_transfer_statement_list_covers_debit_credit_insert_audit(clock: FixedClock) -> None:
    joined = " | ".join(transfer_statements(clock))
    for fragment in (
        "BEGIN IMMEDIATE",
        "UPDATE accounts",
        "INSERT INTO transfers",
        "INSERT INTO audit_log",
        "COMMIT",
    ):
        assert fragment in joined


@pytest.mark.parametrize("exc", [Boom("fault"), KeyboardInterrupt()], ids=["error", "interrupt"])
def test_fault_at_every_statement_commits_nothing(clock: FixedClock, exc: BaseException) -> None:
    statements = transfer_statements(clock)
    assert len(statements) >= 8
    for i, stmt in enumerate(statements):
        led = Ledger(clock=clock, id_factory=counter_ids())
        seed(led)
        before = state(led)
        real_conn = led._conn
        led._conn = FaultyConnection(real_conn, i, exc)  # type: ignore[assignment]
        with pytest.raises(type(exc)):
            internal_transfer(led)
        led._conn = real_conn
        assert state(led) == before, f"partial commit when failing at #{i}: {stmt}"
        assert not real_conn.in_transaction, f"transaction left open at #{i}: {stmt}"
        assert_unchanged_and_usable(led, before)
        led.close()


# ------------------------------------------------ (c) rejected-audit path


def test_fault_while_auditing_a_rejection(ledger: Ledger, monkeypatch: pytest.MonkeyPatch) -> None:
    before = state(ledger)
    real = ledger._audit

    def failing(actor: str, action: str, *args: Any) -> None:
        if action == "transfer_rejected":
            raise Boom
        real(actor, action, *args)

    monkeypatch.setattr(ledger, "_audit", failing)
    with pytest.raises(Boom):
        ledger.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=10**8,  # InsufficientFunds -> rejected-audit path
            idempotency_key="big",
        )
    monkeypatch.undo()
    assert_unchanged_and_usable(ledger, before)


# --------------------------------------------------- (d) process killed


CHILD = textwrap.dedent(
    """
    import os, sys
    from datetime import datetime
    from mulebench.ledger import SAO_PAULO, FixedClock, Ledger

    led = Ledger(sys.argv[1], clock=FixedClock(datetime(2026, 1, 15, 10, tzinfo=SAO_PAULO)))
    real = led._audit

    def die(actor, action, *args):
        if action == "transfer":
            os._exit(17)  # hard kill inside BEGIN IMMEDIATE, after the UPDATEs
        real(actor, action, *args)

    led._audit = die
    led.transfer_pix(actor="cust_alice", from_account_id="acc_alice",
                     to_pix_key="bob@example.test", amount_cents=1000, idempotency_key="k1")
    sys.exit(0)  # not reached
    """
)


def test_process_killed_mid_transaction_commits_nothing(tmp_path: Path, clock: FixedClock) -> None:
    db = tmp_path / "crash.db"
    led = Ledger(str(db), clock=clock, id_factory=counter_ids())
    seed(led)
    before = state(led)
    led.close()

    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", CHILD, str(db)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 17, proc.stderr

    reopened = Ledger(str(db), clock=clock, id_factory=counter_ids())
    try:
        assert state(reopened) == before
        assert reopened.verify_audit_chain().ok
        internal_transfer(reopened)
        assert reopened.get_balance("acc_bob") == 10_000 + 1_000
    finally:
        reopened.close()
