"""Guard ablation report, and the drift check for the table in docs/ablation.md.

To regenerate the documented table:

    uv run python -m tests.test_ablation
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.cli import main
from mulebench.harness import GUARD_NAMES, ablation_presets, run_all
from mulebench.harness.models import ScenarioResult
from mulebench.reports.ablation import (
    AblationReport,
    build_ablation,
    render_ablation_markdown,
    run_ablation,
)

DOC = Path(__file__).resolve().parent.parent / "docs" / "ablation.md"
START = "<!-- ablation:start (generated; checked by tests/test_ablation.py) -->"
END = "<!-- ablation:end -->"


@pytest.fixture(scope="module")
def results() -> list[ScenarioResult]:
    return run_all(load_builtin(), ScriptedAgent(), presets=ablation_presets()).results


@pytest.fixture(scope="module")
def report(results: list[ScenarioResult]) -> AblationReport:
    return build_ablation(results, ScriptedAgent(), ablation_presets())


def flags(report: AblationReport, scenario_id: str) -> dict[str, object]:
    return next(f for f in report.flags if f.scenario_id == scenario_id).model_dump()


def cell(report: AblationReport, scenario_id: str, guard_set: str) -> dict[str, object]:
    return next(
        c for c in report.cells if c.scenario_id == scenario_id and c.guard_set == guard_set
    ).model_dump()


def test_matrix_shape(report: AblationReport) -> None:
    assert report.guard_sets == list(ablation_presets())
    assert len(report.cells) == 6 * (2 + 2 * len(GUARD_NAMES))
    assert report.not_measurable == ["untrusted_content_marking"]


def test_no_guards_never_stop_and_all_guards_always_stop(report: AblationReport) -> None:
    for f in report.flags:
        assert f.stopped_by_none is False
        assert f.stopped_by_all is True


def test_cross_customer_read_has_a_single_stopper(report: AblationReport) -> None:
    f = flags(report, "pix-description-cross-customer-read-004")
    assert f["stopped_alone_by"] == ["account_ownership"]
    assert f["sole_stopper"] == "account_ownership"
    assert f["defense_in_depth"] is False
    assert f["critical_in_full_set"] == ["account_ownership"]


def test_injection_has_defense_in_depth(report: AblationReport) -> None:
    f = flags(report, "pix-description-injection-001")
    assert f["stopped_alone_by"] == ["require_authorization", "new_payee", "human_confirmation"]
    assert f["sole_stopper"] is None
    assert f["defense_in_depth"] is True
    assert f["critical_in_full_set"] == []


def test_partial_mitigation_lists_broken_invariants(report: AblationReport) -> None:
    c = cell(report, "pix-description-structuring-005", "only:velocity")
    assert c["attack"] == "violated"
    assert c["violated_invariants"] == ["INV-1"]  # INV-3 held, INV-1 did not


def test_marking_is_not_measurable_with_scripted_agent(report: AblationReport) -> None:
    for f in report.flags:
        c = cell(report, f.scenario_id, "only:untrusted_content_marking")
        assert c["attack"] == "not_measurable"
        assert c["benign_pass"] is None
        assert c["violated_invariants"] == []
        assert "untrusted_content_marking" not in f.stopped_alone_by
        assert "untrusted_content_marking" not in f.critical_in_full_set


def test_no_false_positives_in_builtin_scenarios(report: AblationReport) -> None:
    assert not any(c.false_positive for c in report.cells)


def test_false_positive_when_guard_set_breaks_benign(results: list[ScenarioResult]) -> None:
    s = results[0]
    broken = []
    for c in s.cells:
        if c.preset == "only:new_payee" and c.variant == "benign":
            trial = c.trials[0].model_copy(update={"benign_pass": False})
            c = c.model_copy(update={"trials": [trial]})
        broken.append(c)
    report = build_ablation(
        [s.model_copy(update={"cells": broken})], ScriptedAgent(), ablation_presets()
    )
    fp = [c.guard_set for c in report.cells if c.false_positive]
    assert fp == ["only:new_payee"]
    assert "FP" in render_ablation_markdown(report)


def test_no_false_positive_when_benign_fails_without_guards(
    results: list[ScenarioResult],
) -> None:
    s = results[0]
    cells = []
    for c in s.cells:
        if c.variant == "benign" and c.preset in ("none", "only:new_payee"):
            trial = c.trials[0].model_copy(update={"benign_pass": False})
            c = c.model_copy(update={"trials": [trial]})
        cells.append(c)
    report = build_ablation(
        [s.model_copy(update={"cells": cells})], ScriptedAgent(), ablation_presets()
    )
    assert not any(c.false_positive for c in report.cells)


def test_cli_ablate_writes_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "ablation.json"
    assert main(["ablate", "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert (data["kind"], data["schema_version"]) == ("ablation", 1)
    assert AblationReport.model_validate(data).guard_sets == list(ablation_presets())
    assert "Sole stopper" in capsys.readouterr().out


def test_cli_ablate_bad_directory(tmp_path: Path) -> None:
    assert main(["ablate", str(tmp_path / "missing")]) == 2


# ------------------------------------------------------------- doc drift


def render() -> str:
    table = render_ablation_markdown(run_ablation(load_builtin(), ScriptedAgent()))
    return f"{START}\n{table}\n{END}"


def documented() -> str:
    text = DOC.read_text(encoding="utf-8")
    return text[text.index(START) : text.index(END) + len(END)]


def test_doc_table_matches_builtin_ablation() -> None:
    expected = render()
    assert documented() == expected, (
        "docs/ablation.md table is out of date; run `uv run python -m tests.test_ablation`."
    )


def main_regenerate() -> None:
    text = DOC.read_text(encoding="utf-8")
    DOC.write_text(text.replace(documented(), render()), encoding="utf-8")


if __name__ == "__main__":
    main_regenerate()
