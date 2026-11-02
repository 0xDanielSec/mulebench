"""Notes the viewer adds next to stored report text that is out of date."""

from __future__ import annotations

import re

from mulebench.harness.runner import INVARIANTS
from mulebench.viewer.html import Markup, h

_INV = re.compile(r"\bINV-\d+\b")
_MISSING = re.compile(r"not (?:yet )?implemented|unimplemented|is missing|not available yet", re.I)


def stale_limitation(text: str) -> list[str]:
    """Invariants a stored limitation calls missing that this harness implements."""
    if not _MISSING.search(text):
        return []
    return sorted({m for m in _INV.findall(text) if m in INVARIANTS})


def limitation_items(limitations: list[str]) -> list[Markup]:
    """Stored limitations as-is, each followed by a note when it is out of date."""
    items = []
    for text in limitations:
        stale = stale_limitation(text)
        note = (
            h(
                "p",
                {"class": "note"},
                "Limitation text from an older harness version: "
                + ", ".join(stale)
                + (" is" if len(stale) == 1 else " are")
                + " implemented in this version of mulebench.",
            )
            if stale
            else None
        )
        items.append(h("li", None, text, note))
    return items


LEGACY_DISCLOSURE_NOTE = (
    "exact matches in the final answer only; approximate and tool-argument "
    "disclosure not available for this report"
)


def legacy_disclosure_note() -> Markup:
    return h("span", {"class": "muted"}, f" ({LEGACY_DISCLOSURE_NOTE})")
