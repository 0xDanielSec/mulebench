"""Stored limitations are shown as-is, with a note when they are out of date."""

from __future__ import annotations

from mulebench.reports.json_report import LIMITATIONS
from mulebench.viewer.notes import stale_limitation
from tests.viewer.test_site import pilot_site

OLD_INV4 = "INV-4 (human confirmation for high-risk actions) is not implemented yet."


def test_stale_limitation_detection() -> None:
    assert stale_limitation(OLD_INV4) == ["INV-4"]
    assert all(stale_limitation(x) == [] for x in LIMITATIONS)
    assert stale_limitation("INV-9 is not implemented yet.") == []
    assert stale_limitation("INV-2 judges successful calls only.") == []


def test_pilot_pages_keep_the_text_and_add_the_note() -> None:
    page = pilot_site()["r3/index.html"]
    assert OLD_INV4 in page
    assert (
        "Limitation text from an older harness version: INV-4 is implemented in this "
        "version of mulebench." in page
    )


NOTE = (
    "exact matches in the final answer only; approximate and tool-argument "
    "disclosure not available for this report"
)


def test_old_report_disclosure_rates_carry_the_note() -> None:
    files = pilot_site()
    cell = files[
        "r3/cell/pix-description-cross-customer-read-004--baseline--vulnerable--attack.html"
    ]
    assert NOTE in cell
    trial = next(
        v
        for k, v in files.items()
        if k.startswith("r3/trial/pix-description-cross-customer") and "--attack--" in k
    )
    assert NOTE in trial


def test_new_reports_have_no_disclosure_note() -> None:
    from mulebench.agents import ScriptedAgent
    from mulebench.attacks import load_builtin
    from mulebench.harness import run_all
    from mulebench.reports import build_report
    from mulebench.viewer.site import build_site

    report = build_report(run_all(load_builtin(), ScriptedAgent()), ScriptedAgent())
    assert all(NOTE not in v for v in build_site([("new", report)]).values())
