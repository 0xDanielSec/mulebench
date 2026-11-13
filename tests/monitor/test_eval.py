from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.monitor_eval import evaluate, render_markdown
from mulebench.reports import build_report, report_to_json

SCENARIOS = load_builtin()


@pytest.fixture(scope="module")
def report_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    report = build_report(run_all(SCENARIOS, ScriptedAgent()), ScriptedAgent())
    path = tmp_path_factory.mktemp("eval") / "scripted.json"
    path.write_text(report_to_json(report), encoding="utf-8")
    return path


def test_eval_on_scripted_run_is_consistent_and_scores(report_path: Path) -> None:
    [r] = evaluate([report_path], SCENARIOS).reports
    c = r.consistency
    assert c.compared
    assert all(v == 0 for v in c.mismatches.values()), c.examples
    assert c.streaming_equals_batch == c.streaming_compared == r.trials
    assert r.positives > 0  # the scripted vulnerable agent is attacked successfully
    p = r.primary
    assert p.threshold == "high"
    assert p.tp + p.fn == r.positives
    assert p.tp + p.fp_attack + p.fp_benign + p.fn + p.tn == r.attack_trials + r.benign_trials
    assert [x.threshold for x in r.by_severity] == ["critical", "high", "medium"]
    # Lower thresholds can only flag more trials.
    flagged = [x.tp + x.fp_attack + x.fp_benign for x in r.by_severity]
    assert flagged == sorted(flagged)
    assert len(r.misses) == p.fn


def test_markdown_has_tables(report_path: Path) -> None:
    text = render_markdown(evaluate([report_path], SCENARIOS))
    assert "| threshold | TP |" in text
    assert "high (primary)" in text
    assert "streaming = batch" in text


def test_cli_eval_writes_json(report_path: Path, tmp_path: Path) -> None:
    from mulebench.cli import main

    out = tmp_path / "eval.json"
    assert main(["monitor", "eval", str(report_path), "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["primary_threshold"] == "high"
