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
