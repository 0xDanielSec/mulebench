from __future__ import annotations

from pathlib import Path

import pytest

from mulebench.harness import format_rate, wilson
from mulebench.reports import UnsupportedReportVersion, load_report, parse_report, report_to_json

FIXTURE_V1 = Path(__file__).resolve().parents[1] / "fixtures" / "report_v1.json"


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [
        (0, 10, 0.0, 0.277533),
        (10, 10, 0.722467, 1.0),
        (5, 10, 0.236590, 0.763410),
        (1, 30, 0.005909, 0.166703),
    ],
)
def test_wilson_reference_values(k: int, n: int, low: float, high: float) -> None:
    r = wilson(k, n)
    assert r.low == pytest.approx(low, abs=1e-5)
    assert r.high == pytest.approx(high, abs=1e-5)


def test_wilson_empty_and_invalid() -> None:
    assert wilson(0, 0).rate is None
    with pytest.raises(ValueError, match="k <= n"):
        wilson(3, 2)


def test_zero_successes_prints_only_an_upper_bound() -> None:
    text = format_rate(wilson(0, 10))
    assert text == "0/10 (<=28% upper 95%)"
    assert "safe" not in text
    assert format_rate(wilson(3, 10)) == "3/10 30% [11%-60%]"
    assert format_rate(wilson(0, 0)) == "-"


def test_v1_report_is_readable_as_v3() -> None:
    report = load_report(FIXTURE_V1)
    assert report.schema_version == 3
    assert report.axes.prompt_variants == ["none"]
    assert report.axes.trials_per_cell == 1
    cell = report.scenarios[0].cell("vulnerable", "attack")
    assert cell.trials[0].status == "exposed_violated"
    assert cell.attack is not None
    assert cell.attack.attack_success.k == 1
    t = report.summary.totals
    assert (t.attack_trials, t.exposed_violated, t.exposed_resisted) == (2, 1, 1)


def test_v3_round_trip_and_unknown_version() -> None:
    report = load_report(FIXTURE_V1)
    import json

    again = parse_report(json.loads(report_to_json(report)))
    assert again == report
    with pytest.raises(UnsupportedReportVersion):
        parse_report({"schema_version": 99})
