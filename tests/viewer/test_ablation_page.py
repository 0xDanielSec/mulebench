"""Ablation report page."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.reports.ablation import AblationReport, run_ablation
from mulebench.viewer.site import build_site, load_any
from mulebench.workloads import load_workloads
from tests.viewer.test_site import check_links
from tests.viewer.test_trial_pages import EVIL


@cache
def ablation() -> AblationReport:
    return run_ablation(load_builtin(), ScriptedAgent(), load_workloads())


def test_ablation_page_renders_every_table(tmp_path: Path) -> None:
    path = tmp_path / "ablation.json"
    path.write_text(ablation().model_dump_json(), encoding="utf-8")
    report = load_any(path)
    assert isinstance(report, AblationReport)
    files = build_site([("ablation", report)])
    page = files["a1/index.html"]
    for caption in (
        "Attack outcome per guard set and scenario",
        "Scenario flags",
        "Security vs usability per guard set",
        "Guard friction",
        "Legitimate workloads per guard set",
        "Damage and usability per cap",
        "Unauthorized outflow per scenario",
    ):
        assert caption in page
    for g in report.guard_sets:
        assert json.dumps(g)[1:-1] in page or g in page
    check_links(files)


def test_ablation_text_is_escaped() -> None:
    report = ablation().model_copy(update={"limitations": [EVIL], "guards": [EVIL]})
    page = build_site([(EVIL, report)])["a1/index.html"]
    assert "<script>alert" not in page
    assert "<img" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
