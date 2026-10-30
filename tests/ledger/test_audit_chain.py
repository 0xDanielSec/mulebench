"""Tamper evidence of the audit hash chain.

The append-only triggers normally block UPDATE and DELETE. To simulate an
attacker who goes around them, each test copies the database file, drops the
triggers in the copy through raw sqlite3, tampers, and verifies the copy.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import shutil
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from mulebench.ledger import (
    GENESIS_HASH,
    AuditSchemaOutdated,
    FixedClock,
    Ledger,
)
from tests.conftest import counter_ids, seed


@pytest.fixture
def db(tmp_path: Path, clock: FixedClock) -> Path:
    """A file ledger: 4 seed rows, then transfers of 100, 101, 102 (seq 5-7)."""
    path = tmp_path / "ledger.db"
    led = Ledger(str(path), clock=clock, id_factory=counter_ids())
    seed(led)
    for i in range(3):
        led.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=100 + i,
            idempotency_key=f"k{i}",
        )
    led.close()
    return path


def open_ledger(path: Path, clock: FixedClock) -> Ledger:
    return Ledger(str(path), clock=clock, id_factory=counter_ids())


def tampered(tmp_path: Path, src: Path, sql: Callable[[sqlite3.Connection], None]) -> Path:
    copy = tmp_path / "tampered.db"
    con = sqlite3.connect(src)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    shutil.copy2(src, copy)
    con = sqlite3.connect(copy)
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("DROP TRIGGER audit_no_delete")
    sql(con)
    con.commit()
    con.close()
    return copy


def row_hash(prev: str, row: dict[str, object]) -> str:
    fields = ("seq", "ts", "actor", "action", "args_json", "result_json", "outcome")
    content = json.dumps(
        {k: row[k] for k in fields}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(f"{prev}\n{content}".encode()).hexdigest()


def rows(con: sqlite3.Connection) -> list[dict[str, object]]:
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute("SELECT * FROM audit_log ORDER BY seq")]


def codes(path: Path, clock: FixedClock, **kwargs: str) -> list[tuple[int | None, str]]:
    led = open_ledger(path, clock)
    try:
        report = led.verify_audit_chain(**kwargs)
    finally:
        led.close()
    assert report.ok == (not report.problems)
    return [(p.seq, p.code) for p in report.problems]


# ------------------------------------------------------------ intact chain


def test_intact_chain_verifies(db: Path, clock: FixedClock) -> None:
    led = open_ledger(db, clock)
    report = led.verify_audit_chain()
    entries = led.audit_entries()
    led.close()
    assert report.ok
    assert report.problems == ()
    assert report.rows_checked == len(entries) >= 7
    assert report.head_hash == entries[-1].hash
    assert entries[0].prev_hash == GENESIS_HASH
    for prev, cur in itertools.pairwise(entries):
        assert cur.prev_hash == prev.hash
        assert cur.seq == prev.seq + 1


def test_hash_formula_is_independent_and_documented(db: Path) -> None:
    con = sqlite3.connect(db)
    all_rows = rows(con)
    con.close()
    prev = GENESIS_HASH
    for r in all_rows:
        assert r["prev_hash"] == prev
        assert r["hash"] == row_hash(prev, r)
        prev = str(r["hash"])


def test_empty_ledger_chain(clock: FixedClock) -> None:
    led = Ledger(clock=clock)
    report = led.verify_audit_chain()
    assert (report.ok, report.rows_checked, report.head_hash) == (True, 0, GENESIS_HASH)
    assert led.verify_audit_chain(expected_head=GENESIS_HASH).ok
    bad = led.verify_audit_chain(expected_head="f" * 64)
    assert [(p.seq, p.code) for p in bad.problems] == [(None, "head_mismatch")]
    led.close()


def test_rejected_operations_are_chained(ledger: Ledger) -> None:
    with pytest.raises(Exception):  # noqa: B017, PT011 - any ledger rejection
        ledger.transfer_pix(
            actor="cust_alice",
            from_account_id="acc_alice",
            to_pix_key="ext@example.test",
            amount_cents=10**9,
            idempotency_key="big",
        )
    assert ledger.audit_entries()[-1].outcome == "rejected"
    assert ledger.verify_audit_chain().ok


def test_triggers_still_block_raw_updates(db: Path) -> None:
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("UPDATE audit_log SET actor = 'x' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("DELETE FROM audit_log WHERE seq = 1")
    con.close()


# ------------------------------------------------------------------ tamper


def test_modified_args_detected(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        con.execute(
            "UPDATE audit_log SET args_json = replace(args_json, '100', '999') WHERE seq = 5"
        )

    assert codes(tampered(tmp_path, db, sql), clock) == [(5, "hash_mismatch")]


def test_modified_outcome_detected(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        con.execute("UPDATE audit_log SET outcome = 'rejected' WHERE seq = 3")

    assert codes(tampered(tmp_path, db, sql), clock) == [(3, "hash_mismatch")]


def test_deleted_middle_row_detected(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        con.execute("DELETE FROM audit_log WHERE seq = 4")

    assert codes(tampered(tmp_path, db, sql), clock) == [
        (5, "seq_gap"),
        (5, "prev_hash_mismatch"),
    ]


def test_reordered_rows_detected(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        # Swap rows 2 and 3 completely (content and stored hashes).
        con.execute("UPDATE audit_log SET seq = -2 WHERE seq = 2")
        con.execute("UPDATE audit_log SET seq = 2 WHERE seq = 3")
        con.execute("UPDATE audit_log SET seq = 3 WHERE seq = -2")

    found = codes(tampered(tmp_path, db, sql), clock)
    assert (2, "prev_hash_mismatch") in found
    assert (2, "hash_mismatch") in found
    assert (3, "hash_mismatch") in found
    assert (4, "prev_hash_mismatch") in found


def test_rehashed_single_row_breaks_next_link(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        r = rows(con)[4]  # seq 5
        r["actor"] = "intruder"
        con.execute(
            "UPDATE audit_log SET actor = ?, hash = ? WHERE seq = 5",
            ("intruder", row_hash(str(r["prev_hash"]), r)),
        )

    assert codes(tampered(tmp_path, db, sql), clock) == [(6, "prev_hash_mismatch")]


def test_malformed_hash_detected(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    def sql(con: sqlite3.Connection) -> None:
        con.execute("UPDATE audit_log SET hash = upper(hash) WHERE seq = 2")

    found = codes(tampered(tmp_path, db, sql), clock)
    assert found[0] == (2, "malformed_row")
    assert (3, "prev_hash_mismatch") in found


def test_tail_truncation_needs_external_anchor(tmp_path: Path, db: Path, clock: FixedClock) -> None:
    led = open_ledger(db, clock)
    anchor = led.verify_audit_chain().head_hash
    last = led.audit_entries()[-1].seq
    led.close()

    def sql(con: sqlite3.Connection) -> None:
        con.execute("DELETE FROM audit_log WHERE seq = ?", (last,))

    copy = tampered(tmp_path, db, sql)
    assert codes(copy, clock) == []  # NOT detected without an anchor
    assert codes(copy, clock, expected_head=anchor) == [(last - 1, "head_mismatch")]


def test_full_rewrite_is_not_detected_known_limitation(
    tmp_path: Path, db: Path, clock: FixedClock
) -> None:
    """No secret key: whoever can write the file and knows the formula can
    recompute the whole chain. Only an external head anchor reveals it."""
    led = open_ledger(db, clock)
    anchor = led.verify_audit_chain().head_hash
    led.close()

    def sql(con: sqlite3.Connection) -> None:
        prev = GENESIS_HASH
        for r in rows(con):
            if r["seq"] == 2:
                r["actor"] = "intruder"
            h = row_hash(prev, r)
            con.execute(
                "UPDATE audit_log SET actor = ?, prev_hash = ?, hash = ? WHERE seq = ?",
                (r["actor"], prev, h, r["seq"]),
            )
            prev = h

    copy = tampered(tmp_path, db, sql)
    assert codes(copy, clock) == []
    assert [c for _, c in codes(copy, clock, expected_head=anchor)] == ["head_mismatch"]


# ------------------------------------------------------------------ schema


def test_outdated_audit_schema_rejected(tmp_path: Path, clock: FixedClock) -> None:
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
        " actor TEXT NOT NULL, action TEXT NOT NULL, args_json TEXT NOT NULL,"
        " result_json TEXT NOT NULL, outcome TEXT NOT NULL)"
    )
    con.commit()
    con.close()
    with pytest.raises(AuditSchemaOutdated):
        Ledger(str(path), clock=clock)
