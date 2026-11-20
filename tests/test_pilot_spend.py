"""scripts/pilot_spend.py: real spend from reports and the phase-2 budget gate."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def spend() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pilot_spend", ROOT / "scripts" / "pilot_spend.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pilot_spend"] = module
    spec.loader.exec_module(module)
    return module


def report(tmp_path: Path, name: str, provider: float | None, table: float) -> Path:
    data: dict[str, Any] = {
        "run_status": "complete",
        "routing": {"provider_cost_usd": provider},
        "cost_totals": {"cost_usd": table},
    }
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_sums_provider_cost_and_falls_back_to_table(
    spend: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    a = report(tmp_path, "a.json", 0.50, 0.70)
    b = report(tmp_path, "b.json", None, 1.20)
    assert spend.main([str(a), str(b)]) == 0
    out = capsys.readouterr().out
    assert "spend so far: US$ 1.7000 over 2 report(s)" in out
    assert "table (provider cost missing)" in out


def test_gate_allows_exactly_the_cap_and_stops_above(
    spend: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    a = report(tmp_path, "a.json", 6.00, 6.50)
    assert spend.main([str(a), "--cap", "9.00", "--next", "3.00"]) == 0
    assert "GO:" in capsys.readouterr().out
    assert spend.main([str(a), "--cap", "9.00", "--next", "3.01"]) == 1
    assert "STOP (not run: budget)" in capsys.readouterr().out


def test_glob_selects_the_pilot_reports(
    spend: ModuleType, tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    report(runs, "pilot-10-a.json", 1.00, 1.00)
    report(runs, "pilot-11-a.json", 0.25, 0.50)
    monkeypatch.setattr(spend, "ROOT", tmp_path)
    assert spend.main(["--glob", "runs/pilot-11-*.json", "--cap", "5.00", "--next", "4.75"]) == 0
    out = capsys.readouterr().out
    assert "pilot-10-a.json" not in out
    assert "spend so far: US$ 0.2500 over 1 report(s)" in out
