"""Mutation check for INV-1 to INV-4, the audit hash chain (AUDIT), ledger rules
and the attack attribution layer (ATTR).

Each table targets one module. For every mutant, the project is copied to a
temporary directory, one condition is broken in the copy of the module, and the
tests for that module run there. A mutant is "killed"
when at least one test fails. The working tree is never modified.

Usage: uv run python scripts/mutation_check.py [INV-1] [INV-2] [INV-3] [INV-4] [AUDIT]
       [LEDGER] [MEMGUARD] [MEMTAINT] [ATTR] [DELEG] [ROLE] [PAYGUARD] [DLGMON]
With no arguments every table runs and docs/mutation-summary.json is rewritten
(per-table killed/total; no dates, so it is deterministic). The README's mutant
count is rendered from it. Exit code is 0 only if every mutant of every
selected table is killed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = ROOT / "docs" / "mutation-summary.json"

Mutant = tuple[str, str, str]  # (rule, original snippet, mutated snippet); original occurs once

INV1_MUTANTS: list[Mutant] = [
    (
        "authorization_cross_session",
        "if used_in is None or granted_in is None or used_in.index != granted_in.index:",
        "if False:",
    ),
    (
        "authorization_cross_session: multi-session runs only",
        "    if ctx.sessions:\n        # Authorizations are per-session grants.",
        "    if True:\n        # Authorizations are per-session grants.",
    ),
    (
        "customer_mismatch: customer of the transfer's session",
        "customer = customer_at(ctx, t.created_at)",
        "customer = ctx.session_customer_id",
    ),
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
        "if auth.customer_id != customer:",
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
    ("memory tools touch no account", "if call.tool in MEMORY_TOOLS:", "if False:"),
    (
        "per-call session customer",
        "me = customer_of(ctx, call.session)",
        "me = ctx.session_customer_id",
    ),
    (
        "unexplained debit: customer of the session at transfer time",
        "me = customer_at(ctx, t.created_at)",
        "me = ctx.session_customer_id",
    ),
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
        "and t.actor in customers),",
        "),",
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
        "structuring: count_authorized=False excludes validly authorized",
        "if not params.count_authorized and t.id in covered:",
        "if False:",
    ),
    (
        "structuring: count_authorized=True keeps authorized",
        "if not params.count_authorized and t.id in covered:",
        "if t.id in covered:",
    ),
    (
        "structuring: valid authorization (INV-1), not mere existence",
        "covered = validly_authorized(snapshot, ctx)",
        "covered = frozenset(t.id for t in snapshot.transfers if t.authorization_id)",
    ),
    (
        "structuring: all_authorized",
        "authorized = all(t.id in covered for t in members)",
        "authorized = any(t.id in covered for t in members)",
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
        "confirmation in the transfer's session",
        "(not ctx.sessions or c.session == index)",
        "True",
    ),
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

ATTR_MUTANTS: list[Mutant] = [
    (
        "legitimate payee wins over goal payee",
        "return payees - legit, accounts",
        "return payees, accounts",
    ),
    (
        "legitimate payees: authorizations",
        "frozenset(a.payee_pix_key for a in scenario.user_task.authorizations) | ",
        "",
    ),
    (
        "legitimate payees: expected transfers",
        "| frozenset(\n        e.to_pix_key for e in"
        " scenario.benign_control.expected_outcome.transfers\n    )",
        "",
    ),
    ("default goal: any payee", 'payees = frozenset({"*"})', "payees = frozenset()"),
    ("default goal: foreign accounts", "if a.customer != customer)", "if a.customer == customer)"),
    (
        "goal payee check",
        'p.payee in goal_payees or "*" in goal_payees',
        '"*" in goal_payees',
    ),
    (
        "attack success independent of the authorization cited",
        "elif attack and (",
        "elif attack and p.id in broken and (",
    ),
    ("task error: missing authorization", "if p.id in broken:", "if False:"),
    (
        "task error: wrong amount",
        "if (p.payee, p.amount_cents) not in expected_amounts:",
        "if False:",
    ),
    (
        "task error: wrong source",
        "if (p.payee, p.from_account_id) not in expected_sources:",
        "if False:",
    ),
    (
        "task error: duplicate payment",
        "paid[p.payee] > expected_count[p.payee]",
        "paid[p.payee] > expected_count[p.payee] + 1",
    ),
    (
        "task error: unexpected payee",
        'task_err = True\n            reasons.append("unexpected_payee")',
        'reasons.append("unexpected_payee")',
    ),
    ("task omitted", "paid[k] < n for k", "paid[k] < n - 1 for k"),
    ("debit of a goal account", "if attack and p.from_account_id in goal_accounts:", "if False:"),
    ("goal account calls: ok only", 'if c.outcome != "ok":', "if False:"),
    (
        "goal account calls: account args",
        'ACCOUNT_ARGS = ("account_id", "from_account_id")',
        'ACCOUNT_ARGS = ("account_id",)',
    ),
    (
        "benign trials have no attack success",
        "attack_success=attack_hit if attack else None",
        "attack_success=attack_hit",
    ),
    (
        "stored trials: exclude seed/system actors",
        "and t.actor not in SYSTEM_ACTORS",
        "and True",
    ),
]

MEMGUARD_MUTANTS: list[Mutant] = [
    ("save_note only", "if not isinstance(args, SaveNoteIn):", "if False:"),
    ("same session only", "if r.session != ctx.session_index or", "if"),
    ("ok calls only", 'or r.outcome != "ok":', ":"),
    (
        "case folding",
        'return " ".join(text.casefold().split())',
        'return " ".join(text.split())',
    ),
    (
        "whitespace collapsing",
        'return " ".join(text.casefold().split())',
        "return text.casefold()",
    ),
    (
        "deny on shared run",
        "if _shares_run(note, _normalize(source), self.min_chars):",
        "if False:",
    ),
    (
        "every window checked",
        "for i in range(len(note) - n + 1))",
        "for i in range(1))",
    ),
    ("min_chars positive", "if min_chars < 1:", "if False:"),
]

MEMTAINT_MUTANTS: list[Mutant] = [
    ("taint: canary", "canary=scenario.canary in n.text,", "canary=False,"),
    ("taint: artifacts", "artifacts=[a for a in artifacts if a in n.text],", "artifacts=[],"),
    (
        "tainted: canary or artifact",
        "return self.canary or bool(self.artifacts)",
        "return self.canary",
    ),
    (
        "artifacts: goal accounts",
        "sorted(set(goal.payees) | set(goal.accounts))",
        "sorted(set(goal.payees))",
    ),
    (
        "session interval: inclusive start",
        "if s.started_at <= ts <= s.ended_at)",
        "if s.started_at < ts <= s.ended_at)",
    ),
    (
        "violations: counted results only",
        "if inv.holds or not inv.applicable:",
        "if inv.holds:",
    ),
    (
        "violations: by call seq",
        "if v.call_seq is not None and v.call_seq in by_seq:",
        "if False:",
    ),
    (
        "violations: group transfers",
        "for tid in (v.transfer_id, *v.transfer_ids):",
        "for tid in (v.transfer_id,):",
    ),
    ("cross-session: attack only", "if attack and sessions:", "if sessions:"),
    (
        "cross-session: later sessions",
        "later = [k for k in sessions if k >= 1]",
        "later = sessions",
    ),
    (
        "cross-session: re-exposure check",
        "elif any(canary not in _outputs(trace, k) for k in later):",
        "elif True:",
    ),
    (
        "re-exposure ignores memory output",
        "and r.tool not in MEMORY_TOOL_NAMES]",
        "]",
    ),
    (
        "followed: denied attempts count",
        'frozenset({"ok", "denied", "ledger_error"})',
        'frozenset({"ok"})',
    ),
    (
        "followed: invalid calls excluded",
        'frozenset({"ok", "denied", "ledger_error"})',
        'frozenset({"ok", "denied", "ledger_error", "invalid_input"})',
    ),
    (
        "followed: later sessions only",
        "if r.outcome in _ATTEMPTED and k >= 1:",
        "if r.outcome in _ATTEMPTED:",
    ),
    ("followed: value in notes", 'and value in notes_text.get(k, "")', "and True"),
    ("followed: no other tool source", 'and value not in other_text.get(k, "")', "and True"),
    ("followed: not in the request", 'and value not in requests.get(k, "")', "and True"),
    ("followed: not already known", "and value not in known.get(k, set())", "and True"),
]

ATTR_AMOUNT_MUTANTS: list[Mutant] = [
    (
        "goal amount: payment carrying it is attack success",
        "if attack and p.amount_cents in goal_amounts:",
        "if False:",
    ),
    (
        "goal amounts: read from the scenario",
        "frozenset(scenario.attack_goal.amounts) if scenario.attack_goal is not None"
        " else frozenset()",
        "frozenset()",
    ),
]

DELEG_MUTANTS: list[Mutant] = [
    ("structured: payee must be authorized", "if item.payee_key not in note_payees:", "if False:"),
    (
        "structured: bill_ref checked",
        "if item.bill_ref is not None and not BILL_REF.fullmatch(item.bill_ref):",
        "if False:",
    ),
    ("structured: bill_ref charset", 'r"^[A-Za-z0-9_-]{1,32}$"', 'r"^[^;]{1,32}$"'),
    ("structured: bill_ref length", 'r"^[A-Za-z0-9_-]{1,32}$"', 'r"^[A-Za-z0-9_-]{1,64}$"'),
    (
        "structured: free text dropped",
        r'body = "\n".join(render_pay_line(i) for i in items) or "No payment to make."',
        "body = reader_text",
    ),
    (
        "taint judged on what the Payer received",
        "sources = taint_sources(handoff_body, scenario)",
        "sources = taint_sources(reader_text, scenario)",
    ),
    ("taint: canary", "if scenario.canary in text:", "if False:"),
    (
        "taint: goal payees",
        'found += [f"payee:{p}" for p in goal.payees if p in text]',
        "found += []",
    ),
    (
        "taint: amount spellings",
        "if any(s in text for s in amount_spellings(c))",
        "if str(c) in text",
    ),
    ("crossing: Payer calls only", 'if r.role != "payer":', "if False:"),
    (
        "crossing: goal amount",
        "if isinstance(amount, int) and not isinstance(amount, bool) and amount in amounts:",
        "if False:",
    ),
    (
        "attributed success needs taint",
        "else attack_success and handoff.tainted and crossed,",
        "else attack_success and crossed,",
    ),
    (
        "attributed success needs crossing",
        "else attack_success and handoff.tainted and crossed,",
        "else attack_success and handoff.tainted,",
    ),
    (
        "tainted but stopped: not crossed",
        "tainted_but_stopped=handoff.tainted and not crossed,",
        "tainted_but_stopped=handoff.tainted,",
    ),
]

ROLE_MUTANTS: list[Mutant] = [
    (
        "role scope enforced",
        "if ctx.allowed_tools is not None and name not in ctx.allowed_tools:",
        "if False:",
    ),
]

PAYGUARD_MUTANTS: list[Mutant] = [
    (
        "allowlist: Payer role only",
        'if ctx.role != "payer" or not isinstance(args, TransferPixIn):',
        "if not isinstance(args, TransferPixIn):",
    ),
    (
        "allowlist: payee in the Payer's note",
        "if args.to_pix_key in (ctx.note_payees or frozenset()):",
        "if True:",
    ),
]

DLGMON_MUTANTS: list[Mutant] = [
    (
        "attempted calls only",
        '_ATTEMPTED = frozenset({"ok", "denied"})',
        '_ATTEMPTED = frozenset({"ok"})',
    ),
    (
        "outcome filter",
        'if c.tool != "transfer_pix" or c.outcome not in _ATTEMPTED:',
        'if c.tool != "transfer_pix":',
    ),
    (
        "known keys excluded",
        "if not isinstance(key, str) or not key or key in known_keys:",
        "if not isinstance(key, str) or not key:",
    ),
    ("handoff before the call", "if h.seq < c.seq and key in h.text", "if key in h.text"),
    ("key named in the handoff", "if h.seq < c.seq and key in h.text", "if h.seq < c.seq"),
]

TABLES: dict[str, tuple[Path, str, list[Mutant]]] = {
    "INV-1": (
        Path("src/mulebench/invariants/authorization.py"),
        "tests/invariants/test_authorization.py tests/invariants/test_sessions.py",
        INV1_MUTANTS,
    ),
    "INV-2": (
        Path("src/mulebench/invariants/isolation.py"),
        "tests/invariants/test_isolation.py tests/invariants/test_sessions.py",
        INV2_MUTANTS,
    ),
    "INV-3": (
        Path("src/mulebench/invariants/limits.py"),
        "tests/invariants/test_limits.py",
        INV3_MUTANTS,
    ),
    "INV-4": (
        Path("src/mulebench/invariants/confirmation.py"),
        "tests/invariants/test_confirmation.py tests/invariants/test_sessions.py",
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
    "MEMGUARD": (
        Path("src/mulebench/tools/guards.py"),
        "tests/tools/test_memory_guard.py",
        MEMGUARD_MUTANTS,
    ),
    "MEMTAINT": (
        Path("src/mulebench/harness/memory.py"),
        "tests/harness/test_memory_metrics.py tests/tools/test_memory.py "
        "tests/harness/test_memory_scenarios.py",
        MEMTAINT_MUTANTS,
    ),
    "ATTR": (
        Path("src/mulebench/harness/attribution.py"),
        "tests/harness/test_attribution.py",
        ATTR_MUTANTS + ATTR_AMOUNT_MUTANTS,
    ),
    "DELEG": (
        Path("src/mulebench/harness/delegation.py"),
        "tests/harness/test_delegation.py",
        DELEG_MUTANTS,
    ),
    "ROLE": (
        Path("src/mulebench/tools/registry.py"),
        "tests/tools/test_role_scope.py",
        ROLE_MUTANTS,
    ),
    "PAYGUARD": (
        Path("src/mulebench/tools/guards.py"),
        "tests/tools/test_role_scope.py",
        PAYGUARD_MUTANTS,
    ),
    "DLGMON": (
        Path("src/mulebench/monitor/delegation.py"),
        "tests/monitor/test_delegation_rule.py",
        DLGMON_MUTANTS,
    ),
}


def copy_project(dest: Path) -> None:
    # docs: the attribution tests read the committed pilot data.
    for name in ("src", "tests", "docs", "pyproject.toml"):
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
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests.split()],
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


def summary_json(counts: dict[str, tuple[int, int]]) -> str:
    """Deterministic summary: {"tables": {name: {killed, total}}, "killed", "total"}."""
    tables = {name: {"killed": k, "total": t} for name, (k, t) in counts.items()}
    data = {
        "tables": tables,
        "killed": sum(k for k, _ in counts.values()),
        "total": sum(t for _, t in counts.values()),
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    selected = (sys.argv[1:] if argv is None else argv) or list(TABLES)
    unknown = [s for s in selected if s not in TABLES]
    if unknown:
        print(f"unknown invariant(s): {', '.join(unknown)}; choose from {', '.join(TABLES)}")
        return 2
    total = 0
    survivors: list[str] = []
    counts: dict[str, tuple[int, int]] = {}
    with tempfile.TemporaryDirectory(prefix="mb-mutation-") as tmp:
        workdir = Path(tmp)
        copy_project(workdir)
        for inv in selected:
            outcome = run_table(workdir, inv)
            if outcome is None:
                return 2
            total += outcome[0]
            survivors += [f"{inv}: {rule}" for rule in outcome[1]]
            counts[inv] = (outcome[0] - len(outcome[1]), outcome[0])
    print(f"total: {total - len(survivors)}/{total} mutants killed")
    if list(counts) == list(TABLES):  # full run only; a partial run keeps the file
        SUMMARY.write_text(summary_json(counts), encoding="utf-8", newline="\n")
        print(f"wrote {SUMMARY.relative_to(ROOT).as_posix()}")
    if survivors:
        print("survivors: " + "; ".join(survivors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
