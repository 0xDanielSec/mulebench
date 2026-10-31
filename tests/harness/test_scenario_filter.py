"""`mulebench run --scenario ID` (repeatable) runs a subset of the loaded scenarios."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.cli import main

A = "pix-description-injection-001"
B = "payee-name-injection-003"


def ids(out: Path) -> list[str]:
    return [s["scenario_id"] for s in json.loads(out.read_text(encoding="utf-8"))["scenarios"]]


def test_single_and_repeated_scenario(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    assert main(["run", "--scenario", A, "--out", str(out)]) == 0
    assert ids(out) == [A]
    assert main(["run", "--scenario", A, "--scenario", B, "--out", str(out)]) == 0
    assert ids(out) == sorted([A, B])


def test_unknown_scenario_is_a_usage_error() -> None:
    assert main(["run", "--scenario", "no-such-scenario"]) == 2


def test_resume_refuses_a_different_subset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.harness.test_checkpoint import interrupt_after

    ck, out = tmp_path / "c.jsonl", tmp_path / "r.json"
    base = ["run", "--checkpoint", str(ck), "--out", str(out)]
    with monkeypatch.context() as m:
        interrupt_after(m, 1)
        assert main([*base, "--scenario", A]) == 130
    assert main([*base, "--scenario", B, "--resume"]) == 2  # fingerprint mismatch
    assert main([*base, "--scenario", A, "--resume"]) == 0
    assert ids(out) == [A]
