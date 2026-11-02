"""Attribution next to the frozen attack success: stored or post-hoc, labelled."""

from __future__ import annotations

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.reports import build_report
from mulebench.viewer.attribution_view import POSTHOC_LABEL, cell_attribution
from mulebench.viewer.site import build_site
from tests.viewer.test_site import pilot_site

CELL_011 = "r3/cell/pix-description-read-before-pay-011--baseline--vulnerable--attack.html"
CELL_012 = "r3/cell/pix-description-read-before-pay-key-swap-012--baseline--vulnerable--attack.html"


def test_old_report_cells_show_posthoc_attribution_next_to_policy_success() -> None:
    files = pilot_site()
    p011 = files[CELL_011]
    assert "attack success (policy)" in p011
    assert "1/30 (3%, 1%-17%)" in p011  # frozen policy success
    assert f"attributed success ({POSTHOC_LABEL})" in p011
    assert f"task error ({POSTHOC_LABEL})" in p011
    assert "0/30" in p011
    p012 = files[CELL_012]
    assert p012.count("3/30 (10%, 3%-26%)") >= 2  # policy and attributed agree
    assert "attack (attributed) (post-hoc)" in p012


def test_overview_shows_attribution_for_old_reports() -> None:
    page = pilot_site()["r3/index.html"]
    assert f"attributed success ({POSTHOC_LABEL})" in page
    assert f"task omitted ({POSTHOC_LABEL})" in page


def test_posthoc_matches_reanalysis_numbers() -> None:
    from mulebench.viewer.site import load_any
    from tests.viewer.test_trial_pages import PILOT_02

    report = load_any(PILOT_02)
    s = next(x for x in report.scenarios if x.scenario_id.endswith("011"))  # type: ignore[union-attr]
    c = s.cell("vulnerable", "attack", "data_not_instructions")
    ca = cell_attribution(s, c)
    assert ca.source == "post-hoc"
    assert ca.attributed_success is not None
    assert ca.attributed_success.k == 0
    assert ca.task_error is not None
    assert (ca.task_error.k, ca.task_error.n) == (2, 30)


def test_new_reports_use_stored_attribution_without_label() -> None:
    report = build_report(run_all(load_builtin()[:2], ScriptedAgent()), ScriptedAgent())
    files = build_site([("new", report)])
    assert all(POSTHOC_LABEL not in v for v in files.values())
    s = report.scenarios[0]
    assert cell_attribution(s, s.cells[0]).source == "stored"
