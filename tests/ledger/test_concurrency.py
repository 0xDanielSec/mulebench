"""Race tests on a file-based DB with WAL; :memory: cannot prove the race."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

from honeyledger.ledger import FixedClock, Ledger, LedgerError
from tests.conftest import seed

WORKERS = 8


def _setup_db(tmp_path: Path, clock: FixedClock) -> str:
    db = str(tmp_path / "race.db")
    led = Ledger(db, clock=clock)
    seed(led)
    led.close()
    conn = sqlite3.connect(db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()
    return db


def _race(db: str, clock: FixedClock, call: Callable[[Ledger, int], None]) -> list[str]:
    """Run `call` in WORKERS threads, each with its own connection, released together."""
    barrier = threading.Barrier(WORKERS)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        led = Ledger(db, clock=clock, busy_timeout_ms=10_000)
        barrier.wait()
        try:
            call(led, i)
            result = "ok"
        except LedgerError as exc:
            result = type(exc).__name__
        except Exception as exc:  # surfaced through the outcome list
            result = f"unexpected:{exc!r}"
        finally:
            led.close()
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return outcomes


def test_concurrent_transfers_respect_daily_limit(tmp_path: Path, clock: FixedClock) -> None:
    db = _setup_db(tmp_path, clock)  # acc_alice: 500_000 balance, 300_000 daily limit

    def call(led: Ledger, i: int) -> None:
        led.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=70_000,
            idempotency_key=f"race-{i}",
        )

    outcomes = _race(db, clock, call)
    assert sorted(outcomes) == ["DailyLimitExceeded"] * 4 + ["ok"] * 4
    check = Ledger(db, clock=clock)
    assert check.get_balance("acc_alice") == 500_000 - 4 * 70_000
    assert check.spent_today_cents("acc_alice") == 280_000
    check.close()


def test_concurrent_transfers_never_overdraw(tmp_path: Path, clock: FixedClock) -> None:
    db = _setup_db(tmp_path, clock)  # acc_bob: 10_000 balance, 100_000 daily limit

    def call(led: Ledger, i: int) -> None:
        led.transfer_pix(
            actor="cust_bob",
            from_account_id="acc_bob",
            to_pix_key="ext@example.test",
            amount_cents=3_000,
            idempotency_key=f"b-{i}",
        )

    outcomes = _race(db, clock, call)
    assert sorted(outcomes) == ["InsufficientFunds"] * 5 + ["ok"] * 3
    check = Ledger(db, clock=clock)
    assert check.get_balance("acc_bob") == 1_000
    check.close()


def test_concurrent_same_idempotency_key_moves_money_once(
    tmp_path: Path, clock: FixedClock
) -> None:
    db = _setup_db(tmp_path, clock)

    def call(led: Ledger, _i: int) -> None:
        led.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=1_000,
            idempotency_key="same",
        )

    outcomes = _race(db, clock, call)
    assert outcomes == ["ok"] * WORKERS
    check = Ledger(db, clock=clock)
    assert check.get_balance("acc_alice") == 499_000
    assert len(check.list_transfers("acc_alice")) == 1
    actions = [e.action for e in check.audit_entries()]
    assert actions.count("transfer") == 1
    assert actions.count("transfer_replayed") == WORKERS - 1
    check.close()


def test_concurrent_use_of_one_authorization_moves_money_once(
    tmp_path: Path, clock: FixedClock
) -> None:
    db = _setup_db(tmp_path, clock)
    setup = Ledger(db, clock=clock)
    auth_id = setup.add_authorization(
        customer_id="cust_alice",
        from_account_id="acc_alice",
        payee_pix_key="ext@example.test",
        max_amount_cents=1_000,
    ).id
    setup.close()

    def call(led: Ledger, i: int) -> None:
        led.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=1_000,
            idempotency_key=f"auth-{i}",
            authorization_id=auth_id,
        )

    outcomes = _race(db, clock, call)
    assert sorted(outcomes) == ["AuthorizationAlreadyUsed"] * (WORKERS - 1) + ["ok"]
    check = Ledger(db, clock=clock)
    assert check.get_balance("acc_alice") == 499_000
    check.close()
