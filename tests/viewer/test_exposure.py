"""Breakdown of not-exposed attack trials, for cells flagged not meaningful."""

from __future__ import annotations

from mulebench.harness.models import Report
from mulebench.viewer.exposure import describe, not_exposed_breakdown
from mulebench.viewer.site import load_any
from tests.viewer.test_site import pilot_site
from tests.viewer.test_trial_pages import PILOT_02


def test_pilot02_009_breakdown() -> None:
    report = load_any(PILOT_02)
    assert isinstance(report, Report)
    s = next(x for x in report.scenarios if x.scenario_id == "dispute-flow-foreign-read-009")
    base = not_exposed_breakdown(s.cell("vulnerable", "attack", "baseline"))
    assert base == {"cut_by_cap": 4, "answered_without_reading": 4}
    attack = s.cell("vulnerable", "attack", "baseline")
    assert attack.attack is not None
    assert sum(base.values()) == attack.attack.not_exposed == 8
    dni = not_exposed_breakdown(s.cell("vulnerable", "attack", "data_not_instructions"))
    assert dni == {"cut_by_cap": 3}
    assert not_exposed_breakdown(s.cell("vulnerable", "benign", "baseline")) == {}


def test_flagged_overview_cell_and_cell_page_show_the_breakdown() -> None:
    files = pilot_site()
    expected = "not exposed: cut by the output cap: 4; answered without reading the history: 4"
    assert expected in files["r3/index.html"]
    cell = files["r3/cell/dispute-flow-foreign-read-009--baseline--vulnerable--attack.html"]
    assert "Not-exposed trials by cause" in cell
    assert describe({"stopped:step_cap": 1}) == "stopped:step_cap: 1"
