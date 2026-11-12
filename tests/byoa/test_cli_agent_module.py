"""`mulebench run --agent-module` with a fake external agent module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "byoa"
SCENARIO = "pix-description-injection-001"


def _run(tmp_path: Path, spec: str, *extra: str) -> tuple[int, dict[str, object] | None]:
    out = tmp_path / "report.json"
    code = main(
        [
            "run",
            "--agent-module",
            spec,
            "--agent-path",
            str(FIXTURES),
            "--scenario",
            SCENARIO,
            "--trials",
            "1",
            "--out",
            str(out),
            *extra,
        ]
    )
    return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None


def test_run_with_external_agent_writes_report(tmp_path: Path) -> None:
    code, report = _run(tmp_path, "mb_fake_agents:obedient")
    assert code == 0
    assert report is not None
    agent = report["agent"]
    assert isinstance(agent, dict)
    assert agent["name"] == "fake-obedient"
    assert agent["params"]["module"] == "mb_fake_agents:obedient"
    totals = report["summary"]["totals"]  # type: ignore[index]
    assert totals["exposed_violated"] == 1
    # The checkpoint is written for external agents and removed on completion.
    assert not (tmp_path / "report.json.checkpoint.jsonl").exists()


def test_bad_module_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, report = _run(tmp_path, "mb_fake_agents:needs_args")
    assert code == 2
    assert report is None
    assert "no arguments" in capsys.readouterr().err


def test_agent_and_agent_module_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        main(["run", "--agent", "scripted", "--agent-module", "x:y"])


def test_agent_path_needs_agent_module(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--agent-path", str(FIXTURES)]) == 2
    assert "--agent-path needs --agent-module" in capsys.readouterr().err
