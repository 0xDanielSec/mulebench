"""Sentinel KQL export: rule set, generated files, and structural checks.

These tests do not execute KQL (no Kusto engine offline) and do not parse it:
syntax is checked only by the opt-in parser in tests/monitor/kql/ (set
MB_KQL_PARSER=1 with a .NET SDK). Without it, queries are reviewed, not
syntax-checked.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from mulebench.cli import main
from mulebench.monitor.kql import (
    NOT_EXPORTED,
    OUTPUT_COLUMNS,
    TABLE,
    TABLE_COLUMNS,
    kql_rule_files,
    kql_rules,
)
from mulebench.monitor.rules import RULES

ROOT = Path(__file__).resolve().parents[2]
KQL_DIR = ROOT / "docs" / "monitor-kql"
RULES_KQL = kql_rules()
IDS = [k.rule.id for k in RULES_KQL]


def strip_literals(query: str) -> str:
    """The query without string literals and // comments (for bracket checks)."""
    out = re.sub(r"//[^\n]*", "", query)
    out = re.sub(r'@"[^"]*"', '""', out)
    out = re.sub(r"@'[^']*'", "''", out)
    out = re.sub(r'"(?:[^"\\]|\\.)*"', '""', out)
    return re.sub(r"'(?:[^'\\]|\\.)*'", "''", out)


def test_one_rule_per_monitor_rule_except_documented() -> None:
    assert set(NOT_EXPORTED) == {"MB-INV1-authorization_cross_session"}
    assert sorted(IDS) == sorted(r.id for r in RULES if r.id not in NOT_EXPORTED)
    assert len(IDS) == 25


def test_committed_files_match_generator() -> None:
    files = kql_rule_files()
    committed = {p.name: p.read_text(encoding="utf-8") for p in KQL_DIR.glob("*.yaml")}
    assert committed == files, (
        "regenerate: uv run mulebench monitor rules --format kql --out docs/monitor-kql"
    )


@pytest.mark.parametrize("rule", RULES_KQL, ids=IDS)
def test_query_structure(rule: object) -> None:
    query: str = rule.query  # type: ignore[attr-defined]
    bare = strip_literals(query)
    assert TABLE in query
    # Every scan of the table filters on EventType first.
    for m in re.finditer(rf"{TABLE}\b", query):
        assert re.match(r"\s*\|\s*where EventType (==|in) ", query[m.end() :]), query[m.start() :][
            :80
        ]
    for open_, close in ("()", "[]", "{}"):
        assert bare.count(open_) == bare.count(close), open_
    # Exact, case-sensitive comparisons only: no case-insensitive operators.
    assert "=~" not in bare
    assert not re.search(r"\b(has|contains)\b(?!_cs)", bare)
    last = query.strip().splitlines()[-1]
    assert last == "| project " + ", ".join(OUTPUT_COLUMNS)
    assert f'RuleId = "{rule.rule.id}"' in query  # type: ignore[attr-defined]


def test_payee_comparison_is_exact() -> None:
    q = next(k.query for k in RULES_KQL if k.rule.id == "MB-INV1-payee_mismatch")
    assert "PayeeMismatch = not(NoAuth) and Payee != AuthPayee" in q


def test_inv4_is_count_based() -> None:
    q = next(k.query for k in RULES_KQL if k.rule.id == "MB-INV4-confirmation_missing")
    assert "K > ApprovedBefore" in q
    assert "ConfTime <= CreatedAt" in q


@pytest.mark.parametrize("name", sorted(kql_rule_files()))
def test_rule_document(name: str) -> None:
    doc = yaml.safe_load(kql_rule_files()[name])
    assert doc["kind"] == "Scheduled"
    assert doc["severity"] in ("High", "Medium", "Low", "Informational")
    assert doc["triggerOperator"] == "gt"
    assert doc["triggerThreshold"] == 0
    assert doc["queryFrequency"] == "1h"
    assert doc["queryPeriod"] in ("1d", "2d")
    assert "to be reviewed" in doc["tags"]
    assert "not production-validated" in doc["description"]
    columns = set(OUTPUT_COLUMNS)
    for m in doc["entityMappings"]:
        for f in m["fieldMappings"]:
            assert f["columnName"] in columns
    assert set(doc["customDetails"].values()) <= columns
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in doc["relevantTechniques"])


def test_table_columns_cover_the_trace_format() -> None:
    names = {n for n, _ in TABLE_COLUMNS}
    assert {"TimeGenerated", "EventType", "SessionId", "Seq", "Args", "Result"} <= names
    assert "Type" not in names  # reserved in Log Analytics


def test_cli_writes_kql(tmp_path: Path) -> None:
    assert main(["monitor", "rules", "--format", "kql", "--out", str(tmp_path)]) == 0
    assert len(list(tmp_path.glob("*.yaml"))) == 25


_TS_FIELDS = ("created_at", "ts")
_RELATIONAL = re.compile(r"(\w+)\s*(<=|>=|<|>)\s*(\w+)")


def string_columns(bare: str) -> set[str]:
    """Columns that hold strings: tostring() results and their plain aliases."""
    names = set(re.findall(r"(\w+)\s*=\s*tostring\(", bare))
    names |= {"SessionId", "CustomerId", "EventType", "Tool", "Outcome", "Text"}
    changed = True
    while changed:
        aliases = {a for a, b in re.findall(r"\b(\w+)\s*=\s*(\w+)\b(?!\s*\()", bare) if b in names}
        changed = not aliases <= names
        names |= aliases
    return names


@pytest.mark.parametrize("rule", RULES_KQL, ids=IDS)
def test_dynamic_timestamps_are_cast_and_strings_use_strcmp(rule: object) -> None:
    """Kusto rejects <, <=, >, >= on strings (KS106). Timestamps read from
    dynamic columns must go through todatetime(); string ordering must use
    strcmp()."""
    query: str = rule.query  # type: ignore[attr-defined]
    bare = strip_literals(query)
    for m in re.finditer(rf"\.({'|'.join(_TS_FIELDS)})\b", bare):
        before = bare[: m.start()]
        assert re.search(r"todatetime\(\s*\w+$", before), bare[m.start() - 40 : m.end()]
    strings = string_columns(bare)
    for left, op, right in _RELATIONAL.findall(bare):
        assert left not in strings, f"{left} {op} {right}: use strcmp()"
        assert right not in strings, f"{left} {op} {right}: use strcmp()"


def test_string_ordering_check_catches_the_original_bug() -> None:
    bad = "T | project MId = TransferId | where MId <= TransferId"
    strings = string_columns(bad + " | extend TransferId = tostring(x)")
    assert any(a in strings or b in strings for a, _, b in _RELATIONAL.findall(bad))
