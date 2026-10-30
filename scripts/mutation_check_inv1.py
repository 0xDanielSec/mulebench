"""Mutation check for INV-1.

For each rule, copy the project to a temporary directory, break one condition
in the copy of `invariants/authorization.py`, and run the INV-1 tests there.
A rule is "killed" when at least one test fails. The working tree is never
modified.

Usage: uv run python scripts/mutation_check_inv1.py
Exit code is 0 only if every mutant is killed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path("src/mulebench/invariants/authorization.py")
TESTS = "tests/invariants/test_authorization.py"

# (rule, original snippet, mutated snippet). Each original must occur once.
MUTANTS: list[tuple[str, str, str]] = [
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


def copy_project(dest: Path) -> None:
    for name in ("src", "tests", "pyproject.toml"):
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, dest / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dest / name)


def run_tests(workdir: Path) -> tuple[bool, str]:
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
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", TESTS],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.strip().splitlines()
    return proc.returncode == 0, lines[-1] if lines else proc.stderr.strip()


def main() -> int:
    original = (ROOT / TARGET).read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="mb-mutation-") as tmp:
        workdir = Path(tmp)
        copy_project(workdir)

        passed, summary = run_tests(workdir)
        if not passed:
            print(f"baseline FAILED: {summary}")
            return 2
        print(f"baseline passed: {summary}\n")

        survivors: list[str] = []
        for rule, old, new in MUTANTS:
            count = original.count(old)
            if count != 1:
                print(f"ERROR  {rule}: snippet found {count} times")
                return 2
            (workdir / TARGET).write_text(original.replace(old, new), encoding="utf-8")
            passed, summary = run_tests(workdir)
            verdict = "SURVIVED" if passed else "killed"
            if passed:
                survivors.append(rule)
            print(f"{verdict:<9} {rule}  [{summary}]")
        (workdir / TARGET).write_text(original, encoding="utf-8")

    print(f"\n{len(MUTANTS) - len(survivors)}/{len(MUTANTS)} mutants killed")
    if survivors:
        print("survivors: " + ", ".join(survivors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
