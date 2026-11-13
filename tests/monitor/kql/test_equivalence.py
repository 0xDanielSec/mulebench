"""KQL equivalence harness (offline).

KQL cannot be executed offline, so equivalence is shown in two parts:

1. Fixtures and expected rows: for every exported rule, a trace with a hit
   session and a near-miss session, and the rows the rule must return. The
   rows come from the Python monitor engine (tests/monitor/kql/cases.py) and
   are checked for drift here. Known divergences are listed separately with the
   engine rows and the KQL behavior.
2. The queries themselves are syntax- and schema-checked only when
   MB_KQL_PARSER=1 and a .NET SDK is installed (tools/kql-check, Microsoft's
   Kusto.Language parser). Otherwise that test is skipped and the queries are
   reviewed, not parsed. Neither part runs the queries on data.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mulebench.monitor.kql import NOT_EXPORTED, TABLE_COLUMNS, kql_rules, to_table_row
from tests.monitor.kql import cases

ROOT = Path(__file__).resolve().parents[3]
EXPORTED = sorted(k.rule.id for k in kql_rules())


def test_committed_files_match_engine() -> None:
    for path, text in cases.generated().items():
        assert path.read_text(encoding="utf-8") == text, (
            f"{path.name} is stale; run `uv run python -m tests.monitor.kql.cases`"
        )
    committed = {p.name for p in cases.FIXTURES.glob("*.jsonl")}
    committed |= {p.name for p in cases.EXPECTED.glob("*.json")}
    assert committed == {p.name for p in cases.generated() if p != cases.DIVERGENCES}


def test_every_exported_rule_has_a_case() -> None:
    assert sorted({c.rule_id for c in cases.CASES}) == EXPORTED
    assert not set(NOT_EXPORTED) & {c.rule_id for c in cases.CASES + cases.DIVERGENCE_CASES}


@pytest.mark.parametrize("case", cases.CASES, ids=[c.rule_id for c in cases.CASES])
def test_hit_session_fires_and_near_miss_does_not(case: cases.Case) -> None:
    rows = cases.engine_rows(case)
    assert rows, "the hit session must raise the rule"
    assert {r["SessionId"] for r in rows} == {case.hit}
    if case.miss is not None:
        assert case.miss not in {r["SessionId"] for r in rows}


def kql_alert_key(row: dict[str, Any]) -> str:
    """Python port of the AlertKey expression in every query (mulebench.monitor.kql._emit)."""
    tids, seqs, accs = row["TransferIds"], row["CallSeq"], row["Accounts"]
    parts = [
        row["RuleId"],
        row["SessionId"],
        ",".join(tids),
        ",".join(map(str, seqs)) if not tids else "",
        ",".join(accs) if not (tids or seqs) else "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def test_kql_alert_key_formula_matches_engine_alert_id() -> None:
    rows = [r for c in cases.CASES for r in cases.engine_rows(c)]
    rows += [
        r
        for d in json.loads(cases.DIVERGENCES.read_text(encoding="utf-8"))
        for r in d["engine_rows"]
    ]
    assert rows
    for r in rows:
        assert kql_alert_key(r) == r["AlertKey"], r


def test_inv4_two_transfers_one_confirmation_matches_engine() -> None:
    """Count-based single use catches it, so it is a regular case, not a divergence."""
    case = next(c for c in cases.CASES if c.name == "two_transfers_one_confirmation")
    (row,) = cases.engine_rows(case)
    assert row["TransferIds"] == ["tx_hit_2"]
    assert all(d.name != case.name for d in cases.DIVERGENCE_CASES)


def test_divergences_are_documented() -> None:
    data = json.loads(cases.DIVERGENCES.read_text(encoding="utf-8"))
    assert [d["rule_id"] for d in data] == [c.rule_id for c in cases.DIVERGENCE_CASES]
    for d in data:
        assert d["rule_id"] in EXPORTED
        assert d["reason"]
        assert d["kql_behavior"]


def test_fixture_events_map_to_table_columns() -> None:
    columns = {n for n, _ in TABLE_COLUMNS}
    for path in cases.FIXTURES.glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = to_table_row(json.loads(line))
            assert set(row) <= columns, path.name


# ------------------------------------------------------------ opt-in parser


@pytest.mark.skipif(
    os.environ.get("MB_KQL_PARSER") != "1",
    reason="KQL parser check is opt-in: set MB_KQL_PARSER=1 with a .NET 8 SDK "
    "(tools/kql-check). Without it the queries are reviewed, not parsed.",
)
def test_queries_parse_with_kusto_language(tmp_path: Path) -> None:
    dotnet = shutil.which("dotnet")
    assert dotnet is not None, "MB_KQL_PARSER=1 needs the dotnet CLI with an SDK"
    for k in kql_rules():
        (tmp_path / f"{k.rule.id}.kql").write_text(k.query, encoding="utf-8")
    schema = "(" + ", ".join(f"{n}:{t}" for n, t in TABLE_COLUMNS) + ")"
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [
            dotnet,
            "run",
            "--project",
            str(ROOT / "tools" / "kql-check"),
            "--",
            str(tmp_path),
            schema,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
