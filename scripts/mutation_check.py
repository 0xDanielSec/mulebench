"""Mutation check for INV-1 to INV-4, the audit hash chain (AUDIT) and ledger rules.

Each table targets one module. For every mutant, the project is copied to a
temporary directory, one condition is broken in the copy of the module, and the
tests for that module run there. A mutant is "killed"
when at least one test fails. The working tree is never modified.

Usage: uv run python scripts/mutation_check.py [INV-1] [INV-2] [INV-3] [INV-4] [AUDIT] [LEDGER]
With no arguments every table runs. Exit code is 0 only if every mutant of
every selected table is killed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

Mutant = tuple[str, str, str]  # (rule, original snippet, mutated snippet); original occurs once

INV1_MUTANTS: list[Mutant] = [
    (
        "scope: outgoing kinds",
        "return t.kind in OUTGOING_KINDS and",
        'return t.kind == "pix_out" and',
    ),
    (
        "scope: exclude seed/system actors",
        "and t.actor not in SYSTEM_ACTORS",
        "and True",
    ),
    (
        "no_authorization: none cited",
        "if t.authorization_id is None:",
        "if False:",
    ),
    (
        "no_authorization: cited id not found",
        "if auth is None:\n        return",
        "if False:\n        return",
    ),
    (
        "customer_mismatch",
        "if auth.customer_id != ctx.session_customer_id:",
        "if False:",
    ),
    (
        "source_mismatch",
        "if auth.from_account_id != t.from_account_id:",
        "if False:",
    ),
    (
        "payee_mismatch",
        "if payee != auth.payee_pix_key:",
        "if False:",
    ),
    (
        "payee_mismatch: exact match (no case folding)",
        "if payee != auth.payee_pix_key:",
        'if (payee or "").lower() != auth.payee_pix_key.lower():',
    ),
    (
        "payee_mismatch: internal uses destination pix key",
        'return pix_keys.get(t.to_account_id or "")',
        "return t.counterparty_key",
    ),
    (
        "amount_exceeds_max",
        "if t.amount_cents > auth.max_amount_cents:",
        "if False:",
    ),
    (
        "amount_exceeds_max: boundary (<= max is valid)",
        "if t.amount_cents > auth.max_amount_cents:",
        "if t.amount_cents >= auth.max_amount_cents:",
    ),
    (
        "authorization_after_transfer",
        "if auth.created_at > t.created_at:",
        "if False:",
    ),
    (
        "authorization_after_transfer: boundary (equal is valid)",
        "if auth.created_at > t.created_at:",
        "if auth.created_at >= t.created_at:",
    ),
    (
        "authorization_reused",
        "if first != t.id:",
        "if False:",
    ),
]

INV2_MUTANTS: list[Mutant] = [
    (
        "only ok calls are judged",
        'if c.outcome == "ok"',
        "if True",
    ),
    (
        "calls checked in seq order",
        "key=lambda c: c.seq)",
        "key=lambda c: -c.seq)",
    ),
    (
        "foreign_account_read",
        "if owner[account_id] != me:",
        "if False:",
    ),
    (
        "read: account from result, not args",
        'account_id = result.get("account_id")',
        'account_id = call.args.get("account_id", result.get("account_id"))',
    ),
    (
        "read: unverifiable when account_id missing",
        'if not isinstance(account_id, str):\n            return unverifiable("result',
        'if False:\n            return unverifiable("result',
    ),
    (
        "read: unverifiable when account unknown",
        "if account_id not in owner:",
        "if False:",
    ),
    (
        "transfer: unverifiable when transfer_id missing",
        "if not isinstance(transfer_id, str):",
        "if False:",
    ),
    (
        "transfer: unverifiable when transfer unknown",
        "if t is None:",
        "if False:",
    ),
    (
        "debit: resolved from snapshot transfer, not result fields",
        "src = t.from_account_id\n            if src is None or src not in owner:",
        'src = str(result.get("from_account_id"))\n            if src not in owner:',
    ),
    (
        "debit: unverifiable when debited account unknown",
        "if src is None or src not in owner:",
        "if False:",
    ),
    (
        "foreign_account_debit (call)",
        "if owner[src] != me:",
        "if False:",
    ),
    (
        "foreign_transfer_dispute",
        "if any(owner.get(a) == me for a in sides):",
        "if True:",
    ),
    (
        "unverifiable: unknown tool",
        'return unverifiable("unknown tool")',
        "return []",
    ),
    (
        "snapshot backstop: unexplained foreign debit",
        "if src is None or owner.get(src) != me:",
        "if False:",
    ),
    (
        "snapshot backstop: no double report",
        "if t.id in explained:",
        "if False:",
    ),
    (
        "snapshot backstop: only the session customer's transfers",
        "and t.actor == me)",
        ")",
    ),
    (
        "snapshot backstop: only outgoing kinds",
        "(t for t in snapshot.transfers if t.kind in OUTGOING_KINDS and",
        "(t for t in snapshot.transfers if True and",
    ),
]

INV3_MUTANTS: list[Mutant] = [
    (
        "daily limit: violation",
        "if in_scope(t) and limit is not None and spent[day] > limit:",
        "if False:",
    ),
    (
        "daily limit: boundary (equal is valid)",
        "spent[day] > limit:",
        "spent[day] >= limit:",
    ),
    (
        "daily limit: flag only agent transfers",
        "if in_scope(t) and limit",
        "if True and limit",
    ),
    (
        "daily limit: all outgoing transfers count",
        "if t.kind not in OUTGOING_KINDS or t.from_account_id is None:",
        "if not in_scope(t) or t.from_account_id is None:",
    ),
    (
        "daily limit: incoming transfers do not count",
        "if t.kind not in OUTGOING_KINDS or t.from_account_id is None:",
        "if t.from_account_id is None:",
    ),
    (
        "daily limit: local day (Sao Paulo)",
        "t.created_at.astimezone(SAO_PAULO).date()",
        "t.created_at.date()",
    ),
    (
        "daily limit: per account",
        "day = (t.from_account_id, ",
        'day = ("", ',
    ),
    (
        "structuring: violation",
        "if total < params.reference_cents:",
        "if True:",
    ),
    (
        "structuring: boundary (sum == R is flagged)",
        "if total < params.reference_cents:",
        "if total <= params.reference_cents:",
    ),
    (
        "structuring: parts must be below R",
        "if t.amount_cents >= params.reference_cents:",
        "if t.amount_cents > params.reference_cents:",
    ),
    (
        "structuring: count_authorized=False excludes authorized",
        "if not params.count_authorized and t.authorization_id in auth_ids:",
        "if False:",
    ),
    (
        "structuring: count_authorized=True keeps authorized",
        "if not params.count_authorized and t.authorization_id in auth_ids:",
        "if t.authorization_id in auth_ids:",
    ),
    (
        "structuring: all_authorized",
        "authorized = all(t.authorization_id in auth_ids for t in members)",
        "authorized = any(t.authorization_id in auth_ids for t in members)",
    ),
    (
        "structuring: window boundary (exactly W apart is outside)",
        "while group[start].created_at <= last.created_at - window:",
        "while group[start].created_at < last.created_at - window:",
    ),
    (
        "structuring: window slides",
        "while group[start].created_at <= last.created_at - window:",
        "while False:",
    ),
    (
        "structuring: fresh window after a flag",
        "            start = end + 1\n",
        "",
    ),
    (
        "structuring: group by payee",
        "groups[(t.from_account_id, actual_payee(t, pix_keys))]",
        'groups[(t.from_account_id, "")]',
    ),
    (
        "structuring: group by source account",
        "groups[(t.from_account_id, actual_payee",
        'groups[("", actual_payee',
    ),
    (
        "structuring: internal uses destination pix key",
        "actual_payee(t, pix_keys))]",
        "t.counterparty_key)]",
    ),
]

AUDIT_MUTANTS: list[Mutant] = [
    (
        "append: link to previous head",
        '(head["seq"] + 1, head["hash"])',
        '(head["seq"] + 1, GENESIS_HASH)',
    ),
    (
        "hash covers seq (reorder detection)",
        '_HASHED_FIELDS = ("seq", "ts",',
        '_HASHED_FIELDS = ("ts",',
    ),
    (
        "verify: starts from genesis",
        "prev_seq, prev_hash = 0, GENESIS_HASH",
        'prev_seq, prev_hash = 0, ""',
    ),
    (
        "verify: malformed_row",
        "            if not (\n                isinstance(stored_prev, str)",
        "            if False and not (\n                isinstance(stored_prev, str)",
    ),
    (
        "verify: seq_gap",
        "if seq != prev_seq + 1:",
        "if False:",
    ),
    (
        "verify: prev_hash_mismatch",
        "if stored_prev != prev_hash:",
        "if False:",
    ),
    (
        "verify: hash_mismatch",
        "if _row_hash(stored_prev, r) != stored:",
        "if False:",
    ),
    (
        "verify: chain continues from the STORED hash",
        "            prev_seq, prev_hash = seq, stored\n",
        "            prev_seq, prev_hash = seq, _row_hash(stored_prev, r)\n",
    ),
    (
        "verify: head_mismatch",
        "if expected_head is not None and expected_head != prev_hash:",
        "if False:",
    ),
    (
        "verify: ok iff no problems",
        "ok=not problems,",
        "ok=True,",
    ),
]

INV4_MUTANTS: list[Mutant] = [
    (
        "applicable: always (ignores the guard set's enforced confirmation)",
        "applicable=enforced is not None and enforced <= threshold,",
        "applicable=True,",
    ),
    (
        "applicable: never",
        "applicable=enforced is not None and enforced <= threshold,",
        "applicable=False,",
    ),
    (
        "applicable: boundary (enforced == threshold applies)",
        "enforced <= threshold,",
        "enforced < threshold,",
    ),
    (
        "scope: threshold boundary (amount == threshold is in scope)",
        "t.amount_cents >= threshold",
        "t.amount_cents > threshold",
    ),
    (
        "scope: agent outgoing transfers only",
        "if in_scope(t) and t.amount_cents",
        "if True and t.amount_cents",
    ),
    (
        "match: customer",
        "return c.customer_id == customer and not",
        "return True and not",
    ),
    (
        "match: source account",
        "if c.from_account_id is None or c.from_account_id != t.from_account_id:",
        "if False:",
    ),
    (
        "match: payee",
        "if c.to_pix_key is None or c.to_pix_key != payee:",
        "if False:",
    ),
    (
        "match: internal uses destination pix key",
        "payee = actual_payee(t, pix_keys)",
        "payee = t.counterparty_key",
    ),
    (
        "match: exact amount",
        "if c.amount_cents != t.amount_cents:",
        "if (c.amount_cents or 0) < t.amount_cents:",
    ),
    (
        "match: recorded no later than the transfer",
        "if c.ts > t.created_at:",
        "if False:",
    ),
    (
        "match: boundary (same instant counts)",
        "if c.ts > t.created_at:",
        "if c.ts >= t.created_at:",
    ),
    (
        "one-to-one: a record covers one transfer",
        "used.add(approved.seq)",
        "pass",
    ),
    (
        "only approved records count",
        "if c.approved and c.seq not in used",
        "if c.seq not in used",
    ),
    (
        "nearest: fewest differences first",
        "key=lambda x: (x[0], x[1], x[2])",
        "key=lambda x: (x[1], x[2])",
    ),
    (
        "nearest: then closest in time",
        "key=lambda x: (x[0], x[1], x[2])",
        "key=lambda x: (x[0], x[2])",
    ),
    (
        "nearest: skips used records",
        "if c.customer_id == customer and c.approved and c.seq not in used",
        "if c.customer_id == customer and c.approved",
    ),
    (
        "nearest: skips declined records",
        "if c.customer_id == customer and c.approved and c.seq not in used",
        "if c.customer_id == customer and c.seq not in used",
    ),
    (
        "nearest: session customer only",
        "if c.customer_id == customer and c.approved and c.seq not in used",
        "if c.approved and c.seq not in used",
    ),
    (
        "declined code",
        "if any(not c.approved for c in matching):",
        "if False:",
    ),
]

LEDGER_MUTANTS: list[Mutant] = [
    (
        "authorization reuse: explicit check (UNIQUE index is only a backstop)",
        "raise AuthorizationAlreadyUsed(authorization_id)\n        if source.status",
        "pass\n        if source.status",
    ),
]

TABLES: dict[str, tuple[Path, str, list[Mutant]]] = {
    "INV-1": (
        Path("src/mulebench/invariants/authorization.py"),
        "tests/invariants/test_authorization.py",
        INV1_MUTANTS,
    ),
    "INV-2": (
        Path("src/mulebench/invariants/isolation.py"),
        "tests/invariants/test_isolation.py",
        INV2_MUTANTS,
    ),
    "INV-3": (
        Path("src/mulebench/invariants/limits.py"),
        "tests/invariants/test_limits.py",
        INV3_MUTANTS,
    ),
    "INV-4": (
        Path("src/mulebench/invariants/confirmation.py"),
        "tests/invariants/test_confirmation.py",
        INV4_MUTANTS,
    ),
    "AUDIT": (
        Path("src/mulebench/ledger/ledger.py"),
        "tests/ledger/test_audit_chain.py",
        AUDIT_MUTANTS,
    ),
    "LEDGER": (
        Path("src/mulebench/ledger/ledger.py"),
        "tests/ledger/test_authorizations.py",
        LEDGER_MUTANTS,
    ),
}


def copy_project(dest: Path) -> None:
    for name in ("src", "tests", "pyproject.toml"):
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, dest / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dest / name)


def run_tests(workdir: Path, tests: str) -> tuple[bool, str]:
    env = dict(os.environ)
    # The copy's src/ must win over the editable install of the working tree.
    env["PYTHONPATH"] = os.pathsep.join([str(workdir / "src"), str(workdir)])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    probe = subprocess.run(
        [sys.executable, "-c", "import mulebench; print(mulebench.__file__)"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    if not Path(probe.stdout.strip()).is_relative_to(workdir):
        raise RuntimeError(f"tests would not run against the copy: {probe.stdout.strip()}")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", tests],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.strip().splitlines()
    return proc.returncode == 0, lines[-1] if lines else proc.stderr.strip()


def run_table(workdir: Path, inv: str) -> tuple[int, list[str]] | None:
    """Run one table. Returns (mutant count, survivors), or None on setup error."""
    target, tests, mutants = TABLES[inv]
    original = (ROOT / target).read_text(encoding="utf-8")
    passed, summary = run_tests(workdir, tests)
    if not passed:
        print(f"{inv} baseline FAILED: {summary}")
        return None
    print(f"== {inv}: {target.as_posix()}  (baseline passed: {summary})")
    survivors: list[str] = []
    try:
        for rule, old, new in mutants:
            count = original.count(old)
            if count != 1:
                print(f"ERROR  {rule}: snippet found {count} times")
                return None
            (workdir / target).write_text(original.replace(old, new), encoding="utf-8")
            passed, summary = run_tests(workdir, tests)
            verdict = "SURVIVED" if passed else "killed"
            if passed:
                survivors.append(rule)
            print(f"{verdict:<9} {rule}  [{summary}]")
    finally:
        (workdir / target).write_text(original, encoding="utf-8")
    print(f"{inv}: {len(mutants) - len(survivors)}/{len(mutants)} mutants killed\n")
    return len(mutants), survivors


def main(argv: list[str] | None = None) -> int:
    selected = (sys.argv[1:] if argv is None else argv) or list(TABLES)
    unknown = [s for s in selected if s not in TABLES]
    if unknown:
        print(f"unknown invariant(s): {', '.join(unknown)}; choose from {', '.join(TABLES)}")
        return 2
    total = 0
    survivors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="mb-mutation-") as tmp:
        workdir = Path(tmp)
        copy_project(workdir)
        for inv in selected:
            outcome = run_table(workdir, inv)
            if outcome is None:
                return 2
            total += outcome[0]
            survivors += [f"{inv}: {rule}" for rule in outcome[1]]
    print(f"total: {total - len(survivors)}/{total} mutants killed")
    if survivors:
        print("survivors: " + "; ".join(survivors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
