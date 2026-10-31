"""Per-trial checkpoint, --resume and Ctrl+C partial reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.cli import main
from mulebench.harness import run_all
from mulebench.harness import runner as runner_module
from mulebench.harness.checkpoint import Checkpoint, CheckpointError, fingerprint
from mulebench.reports.reader import load_report

SCENARIOS = [s for s in load_builtin() if s.id == "pix-description-injection-001"]


def interrupt_after(monkeypatch: pytest.MonkeyPatch, n: int) -> None:
    """Make the (n+1)-th run_trial call raise KeyboardInterrupt."""
    real = runner_module.run_trial
    calls = {"n": 0}

    def fake(*args: Any, **kw: Any) -> Any:
        calls["n"] += 1
        if calls["n"] > n:
            raise KeyboardInterrupt
        return real(*args, **kw)

    monkeypatch.setattr(runner_module, "run_trial", fake)


def finished_trials() -> list[Any]:
    out = run_all(SCENARIOS, ScriptedAgent())
    return [t for s in out.results for c in s.cells for t in c.trials]


# ---------------------------------------------------------------- file


def test_write_and_resume(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    trials = finished_trials()
    ck = Checkpoint.open(path, "fp", resume=False)
    for t in trials[:2]:
        ck.write(t)
    ck.close()
    again = Checkpoint.open(path, "fp", resume=True)
    assert list(again.completed) == [t.trial_key for t in trials[:2]]
    assert again.completed[trials[0].trial_key] == trials[0]
    again.close()


def test_refuses_to_overwrite_and_to_resume_other_config(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    Checkpoint.open(path, "fp", resume=False).close()
    with pytest.raises(CheckpointError, match="exists"):
        Checkpoint.open(path, "fp", resume=False)
    with pytest.raises(CheckpointError, match="different run configuration"):
        Checkpoint.open(path, "other", resume=True)
    with pytest.raises(CheckpointError, match="nothing to resume"):
        Checkpoint.open(tmp_path / "missing.jsonl", "fp", resume=True)
    (tmp_path / "junk.jsonl").write_text("hello\n", encoding="utf-8")
    with pytest.raises(CheckpointError, match="not a mulebench checkpoint"):
        Checkpoint.open(tmp_path / "junk.jsonl", "fp", resume=True)


def test_torn_last_line_is_dropped_and_appending_stays_valid(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    trials = finished_trials()
    ck = Checkpoint.open(path, "fp", resume=False)
    ck.write(trials[0])
    ck.close()
    with path.open("ab") as f:
        f.write(trials[1].model_dump_json().encode()[:50])  # crash mid-write
    ck = Checkpoint.open(path, "fp", resume=True)
    assert list(ck.completed) == [trials[0].trial_key]
    ck.write(trials[1])
    ck.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert all(json.loads(line) for line in lines)


def test_fingerprint_covers_config_and_scenarios() -> None:
    a = fingerprint({"trials": 1}, SCENARIOS)
    assert a == fingerprint({"trials": 1}, SCENARIOS)
    assert a != fingerprint({"trials": 2}, SCENARIOS)
    assert a != fingerprint({"trials": 1}, load_builtin())


# ------------------------------------------------------------ run_all


def test_interrupt_keeps_finished_trials(monkeypatch: pytest.MonkeyPatch) -> None:
    interrupt_after(monkeypatch, 3)
    out = run_all(SCENARIOS, ScriptedAgent())
    assert out.status == "aborted_interrupt"
    assert sum(len(c.trials) for s in out.results for c in s.cells) == 3


def test_completed_trials_are_not_rerun(monkeypatch: pytest.MonkeyPatch) -> None:
    trials = finished_trials()
    seen: list[str] = []
    out = run_all(
        SCENARIOS,
        ScriptedAgent(),
        completed={t.trial_key: t for t in trials[:3]},
        on_trial=lambda t: seen.append(t.trial_key),
    )
    assert seen == [trials[3].trial_key]
    assert [t for s in out.results for c in s.cells for t in c.trials] == trials


# ---------------------------------------------------------------- CLI


def test_cli_interrupt_then_resume_matches_a_full_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scen = tmp_path / "scenarios"
    scen.mkdir()
    src = next(p for p in _builtin_files() if p.name.startswith("pix-description-injection-001"))
    (scen / src.name).write_bytes(src.read_bytes())
    out, ck = tmp_path / "r.json", tmp_path / "r.ckpt"
    base = ["run", str(scen), "--out", str(out), "--checkpoint", str(ck)]

    with monkeypatch.context() as m:
        interrupt_after(m, 2)
        assert main(base) == 130
    partial = load_report(out)  # a valid report
    assert partial.run_status == "aborted_interrupt"
    assert len(ck.read_text(encoding="utf-8").splitlines()) == 1 + 2

    assert main([*base, "--resume"]) == 0
    assert not ck.exists()  # deleted after a complete run
    resumed = out.read_bytes()
    full = tmp_path / "full.json"
    assert main(["run", str(scen), "--out", str(full)]) == 0
    assert resumed == full.read_bytes()


def test_cli_resume_needs_a_checkpoint(tmp_path: Path) -> None:
    assert main(["run", "--resume"]) == 2


def _builtin_files() -> list[Path]:
    from importlib.resources import files

    root = files("mulebench.attacks") / "scenarios"
    return [Path(str(p)) for p in root.iterdir() if str(p).endswith(".yaml")]
