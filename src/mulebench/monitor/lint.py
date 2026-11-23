"""Tell lint: reject detection rules that depend on scenario-specific tells.

A rule that matches a canary, a synthetic account id, a scenario domain or
the exact text of a payload detects the lab scenario, not the attack class.
The lint derives every tell from the scenario files themselves, so a new
scenario is covered without editing the lint:

* canary: `MB-CANARY-...` (any, by pattern) and every canary a scenario names;
* identifier: account ids, customer ids, pix keys, transaction refs and other
  identifier-shaped values (no whitespace, with `_`, `@` or `-`) from scenario
  setups, injections and attack goals, matched as whole tokens;
* domain: every domain in scenario text (pix keys, URLs), `example.test` and
  any `attacker.` host;
* payload: any run of PAYLOAD_NGRAM characters (case-folded, whitespace
  collapsed) of an injection payload, benign-control payload or seeded
  transaction text;
* amount: an amount (cents >= MIN_AMOUNT_CENTS) from a scenario setup or
  payload, as digits or as `123.45` / `123,45`, outside a `let Name = N;`
  parameter line.

It reads rule files as plain text (Sigma-like YAML and Sentinel KQL YAML), so
prose that cites a scenario value fails too.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mulebench.attacks import Scenario
from mulebench.monitor.events import trace_json_schema

PAYLOAD_NGRAM = 16
MIN_AMOUNT_CENTS = 2000  # 1000 is a factor of ten in rule prose
# The agent tool API and the trace event names: vocabulary every rule shares
# with every scenario.
SHARED_TERMS = (
    "get_balance",
    "list_transactions",
    "transfer_pix",
    "open_dispute",
    "save_note",
    "read_notes",
    "authorization_id",
    "from_account_id",
    "to_pix_key",
    "amount_cents",
    "pix key",
)
CANARY_RE = re.compile(r"MB-CANARY-[A-Za-z0-9_-]+")
GENERIC_DOMAINS = ("example.test",)
_ATTACKER_HOST = re.compile(r"\battacker\.[a-z0-9.-]+", re.IGNORECASE)
_DOMAIN = re.compile(r"(?:(?<=@)|(?<=//))[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.IGNORECASE)
_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]*[_@-][A-Za-z0-9_.@-]*$")
_PARAM_LINE = re.compile(r"^\s*let\s+\w+\s*=\s*-?[0-9.]+\s*;")
_AMOUNT_IN_TEXT = re.compile(r"(?<![\d.,])(\d{1,9})[.,](\d{2})(?![\d])")
_RULE_SUFFIXES = (".yml", ".yaml", ".kql")

TellKind = Literal["canary", "identifier", "domain", "payload", "amount"]


@dataclass(frozen=True)
class Tells:
    canaries: frozenset[str]
    identifiers: frozenset[str]
    domains: frozenset[str]
    payloads: tuple[str, ...]  # normalized payload texts
    amounts: frozenset[int]  # cents
    shared: str = ""  # normalized shared vocabulary


@dataclass(frozen=True, order=True)
class LintFinding:
    path: str
    line: int
    kind: TellKind
    tell: str


def _normalize(text: str) -> str:
    return " ".join(text.casefold().split())


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _ints(value: object, key: str = "") -> Iterator[int]:
    if isinstance(value, bool):
        return
    if isinstance(value, int) and ("cents" in key or "amount" in key):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _ints(v, str(k))
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _ints(v, key)


def tells_from(scenarios: Iterable[Scenario]) -> Tells:
    canaries: set[str] = set()
    identifiers: set[str] = set()
    domains: set[str] = set(GENERIC_DOMAINS)
    payloads: list[str] = []
    amounts: set[int] = set()
    for sc in scenarios:
        data = sc.model_dump(mode="json")
        for s in _strings(data):
            canaries.update(CANARY_RE.findall(s))
            domains.update(d.lower() for d in _DOMAIN.findall(s))
        if isinstance(data.get("canary"), str):
            canaries.add(data["canary"])
        structured = [data.get(k) for k in ("setup", "injection", "attack_goal")]
        for s in _strings(structured):
            if _IDENT.match(s) and len(s) >= 4:
                identifiers.add(s)
        amounts.update(_ints(data.get("setup")))
        texts = [
            *_strings((data.get("injection") or {}).get("payload")),
            *_strings((data.get("benign_control") or {}).get("payload")),
            *(
                t
                for tx in (data.get("setup") or {}).get("transactions") or []
                for t in _strings(tx)
                if " " in t
            ),
        ]
        for t in texts:
            norm = _normalize(t.replace("{{payload}}", " "))
            if len(norm) >= PAYLOAD_NGRAM:
                payloads.append(norm)
            for whole, frac in _AMOUNT_IN_TEXT.findall(t):
                amounts.add(int(whole) * 100 + int(frac))
    identifiers -= {c for c in canaries}
    return Tells(
        canaries=frozenset(canaries),
        identifiers=frozenset(identifiers),
        domains=frozenset(domains),
        payloads=tuple(sorted(set(payloads))),
        amounts=frozenset(a for a in amounts if a >= MIN_AMOUNT_CENTS),
        shared=_shared_vocabulary(),
    )


def _shared_vocabulary() -> str:
    """Text every rule may use: the trace format and the tool API. A payload
    run inside it is shared vocabulary, not a tell."""
    schema = json.dumps(trace_json_schema(), sort_keys=True)
    return _normalize(schema + " " + " ".join(SHARED_TERMS))


def _payload_ngram(line: str, payloads: Sequence[str], shared: str) -> str | None:
    norm = _normalize(line)
    n = PAYLOAD_NGRAM
    for i in range(len(norm) - n + 1):
        gram = norm[i : i + n].strip()
        # A run of at least two words (one word is vocabulary, not payload text).
        if " " not in gram or gram in shared:
            continue
        if any(gram in p for p in payloads):
            return gram
    return None


def _amount_spellings(cents: int) -> tuple[str, ...]:
    whole, frac = divmod(cents, 100)
    return (str(cents), f"{whole}.{frac:02d}", f"{whole},{frac:02d}")


def lint_text(text: str, path: str, tells: Tells) -> list[LintFinding]:
    out: set[LintFinding] = set()
    for n, line in enumerate(text.splitlines(), start=1):
        for c in CANARY_RE.findall(line):
            out.add(LintFinding(path, n, "canary", c))
        for c in tells.canaries:
            if c in line:
                out.add(LintFinding(path, n, "canary", c))
        for ident in tells.identifiers:
            if re.search(rf"(?<![\w@.-]){re.escape(ident)}(?![\w@-])", line):
                out.add(LintFinding(path, n, "identifier", ident))
        lowered = line.lower()
        for d in tells.domains:
            if re.search(rf"(?<![\w-]){re.escape(d)}(?![\w-])", lowered):
                out.add(LintFinding(path, n, "domain", d))
        for m in _ATTACKER_HOST.findall(line):
            out.add(LintFinding(path, n, "domain", m.lower()))
        gram = _payload_ngram(line, tells.payloads, tells.shared)
        if gram is not None:
            out.add(LintFinding(path, n, "payload", gram))
        if not _PARAM_LINE.match(line):
            for cents in tells.amounts:
                for spelled in _amount_spellings(cents):
                    if re.search(rf"(?<![\d.,]){re.escape(spelled)}(?![\d]|[.,]\d)", line):
                        out.add(LintFinding(path, n, "amount", spelled))
    return sorted(out)


def rule_paths(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out += sorted(q for q in p.rglob("*") if q.suffix in _RULE_SUFFIXES)
        else:
            out.append(p)
    return out


def lint_paths(paths: Iterable[Path], tells: Tells) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for p in rule_paths(paths):
        findings += lint_text(p.read_text(encoding="utf-8"), p.as_posix(), tells)
    return findings
