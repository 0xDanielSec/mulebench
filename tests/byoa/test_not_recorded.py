"""LLM metrics of an external agent without model calls are "not recorded", never 0."""

from __future__ import annotations

import json
from pathlib import Path

from mulebench.attacks import load_builtin
from mulebench.byoa import load_agent
from mulebench.harness import run_all
from mulebench.harness.models import Report
from mulebench.reports import build_report, render_table
from mulebench.reports.json_report import report_to_json
from mulebench.reports.reader import parse_report
from mulebench.viewer.recorded import NOT_RECORDED
from mulebench.viewer.site import build_site

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "byoa"
SCENARIO = "pix-description-injection-001"


def _report() -> Report:
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    scenarios = [s for s in load_builtin() if s.id == SCENARIO]
    outcome = run_all(scenarios, agent, presets=("vulnerable",))
    return build_report(outcome, agent, presets=["vulnerable"])


def test_json_marks_model_calls_not_recorded() -> None:
    data = json.loads(report_to_json(_report()))
    assert data["cost_totals"]["recorded"] is False
    assert data["cost_totals"]["cost_usd"] is None
    trial = data["scenarios"][0]["cells"][0]["trials"][0]
    assert trial["model_calls_recorded"] is False
    assert trial["cost_usd"] is None
    assert trial["metrics"]["injected_steps"] is None


def test_report_round_trips() -> None:
    report = _report()
    again = parse_report(json.loads(report_to_json(report)))
    assert again.cost_totals.recorded is False


def test_table_says_not_recorded() -> None:
    assert "not recorded" in render_table(_report())


def test_viewer_says_not_recorded_and_never_zero_calls() -> None:
    site = build_site([("byoa", _report())])
    trial_pages = [p for name, p in site.items() if "/trial/" in name]
    assert trial_pages
    assert any("Model calls: not recorded" in p for p in trial_pages)
    cell_pages = [p for p in site.values() if "Model calls</th>" in p]
    assert cell_pages
    assert all(NOT_RECORDED in p for p in cell_pages)


def test_scripted_agent_still_records_model_calls() -> None:
    from mulebench.agents import ScriptedAgent

    scenarios = [s for s in load_builtin() if s.id == SCENARIO]
    agent = ScriptedAgent()
    report = build_report(run_all(scenarios, agent, presets=("vulnerable",)), agent)
    assert report.cost_totals.recorded is True
    trial = report.scenarios[0].cells[0].trials[0]
    assert trial.model_calls_recorded is True
    assert trial.metrics.injected_steps is not None
