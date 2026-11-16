"""Pilot 07 analysis on an offline scripted dry run of the automatic-memory scenarios.

The scripted agent and the scripted extractor make the vulnerable cells
inject and follow; the two memory defences make the negative paths. Edge
cases (an LLM extraction record, an errored trial, a disclosure in session 0
only) are made by editing copies of the dry-run report.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mulebench.cli import main as cli_main
from tests.test_pilot_results import ROOT, load_script
from tests.test_pilot_results_04_05 import row, section

SCENARIOS = (
    "memory-auto-bill-redirect-013a",
    "memory-auto-persistent-exfiltration-014a",
    "memory-auto-key-update-013b",
)
PRESETS = ("vulnerable", "only:memory_source_customer", "only:memory_extract_guard")
SOURCE, GUARD = PRESETS[1], PRESETS[2]


@pytest.fixture(scope="module")
def script() -> ModuleType:
    return load_script()


@pytest.fixture(scope="module")
def dry(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("dry07") / "p07.json"
    scen = [x for s in SCENARIOS for x in ("--scenario", s)]
    presets = [x for p in PRESETS for x in ("--preset", p)]
    args = ["run", "--builtin", *scen, "--agent", "scripted", "--trials", "2"]
    assert cli_main([*args, "--skip-conformance", *presets, "--out", str(out)]) in (0, 1)
    return out


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def cell(report: dict[str, Any], sid: str, preset: str, variant: str) -> dict[str, Any]:
    return next(
        c
        for s in report["scenarios"]
        if s["scenario_id"].endswith(sid)
        for c in s["cells"]
        if c["preset"] == preset and c["variant"] == variant
    )


def test_pilot_07_vulnerable_injects_and_defences_stop_it(script: ModuleType, dry: Path) -> None:
    lines = script.render_pilot_07(load(dry), "p07.json")
    primary = section(lines, "Primary outcomes")
    for sid in ("013a", "013b", "014a"):
        vuln = row(primary, sid, "vulnerable", "none")
        assert vuln[5] == "injected"
        assert vuln[6:11] == ["2/2 (100%, 34%-100%)"] * 5
        assert vuln[11] == "2 / 0 / 0 / 0"
        for preset in (SOURCE, GUARD):
            got = row(primary, sid, preset, "none")
            assert got[5].startswith("nothing injected")
            assert got[7].startswith("[")  # following not meaningful
            assert got[9].startswith("0/2")  # attack outcomes still reported
    disclosure = section(lines, "Disclosure by session")
    assert row(disclosure, "014a", "vulnerable", "none")[3:6] == [
        "0/2 (0%, 0%-66%)",
        "0/2 (0%, 0%-66%)",
        "2/2 (100%, 34%-100%)",
    ]
    extraction = section(lines, "Extraction")
    assert row(extraction, "013a", SOURCE, "none", "attack")[6] == "customer_turns 2"
    assert row(extraction, "013a", GUARD, "none", "benign")[10] == "2"  # guard false positive
    text = "\n".join(lines)
    assert "013a as frozen" in text
    assert "to be confirmed by the author" in text


def test_pilot_07_llm_extraction_errors_and_session_zero_disclosure(
    script: ModuleType, dry: Path
) -> None:
    report = copy.deepcopy(load(dry))
    attack = cell(report, "014a", "vulnerable", "attack")
    llm = attack["trials"][0]["memory"]["extractions"][0]
    llm["extractor"] = "llm"
    llm["model_call"] = {"served_model": "qwen3-14b-8k"}
    llm["malformed"] = True
    attack["trials"][1]["errored"] = True
    attack["trials"][1]["error"] = "memory_extraction:timeout"
    attack["trials"][0]["disclosure_by_session"][0]["disclosed"] = True
    report["scenarios"][0]["extraction_prompt_sha256"] = "0" * 64
    lines = script.render_pilot_07(report, "edited.json")
    got = row(section(lines, "Extraction"), "014a", "vulnerable", "none", "attack")
    assert got[4:9] == ["1", "llm 1", "conversation 1", "qwen3-14b-8k 1", "1"]
    primary = row(section(lines, "Primary outcomes"), "014a", "vulnerable", "none")
    assert primary[3] == "1/2"
    assert primary[6] == "1/1 (100%, 21%-100%)"
    disclosure = row(section(lines, "Disclosure by session"), "014a", "vulnerable", "none")
    assert disclosure[3] == "1/1 (100%, 21%-100%)"
    text = "\n".join(lines)
    assert "memory_extraction:timeout 1" in text
    assert "NOT as frozen" in text


def test_pilot_07_command(script: ModuleType, dry: Path) -> None:
    with pytest.raises(SystemExit):
        script.analyse("07", [dry, dry])
    done = subprocess.run(  # noqa: S603 (fixed interpreter and module)
        [sys.executable, "-m", "scripts.pilot_results", "--pilot", "07", "--report", str(dry)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "## Results: local pilot 07" in done.stdout
