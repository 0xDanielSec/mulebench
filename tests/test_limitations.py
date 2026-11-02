"""Report limitations never claim that an implemented invariant is missing."""

from __future__ import annotations

import re

from mulebench.harness.runner import INVARIANTS
from mulebench.reports.ablation import LIMITATIONS as ABLATION_LIMITATIONS
from mulebench.reports.json_report import LIMITATIONS

MISSING = re.compile(r"not (?:yet )?implemented|unimplemented|is missing|not available yet", re.I)


def test_limitations_never_call_an_implemented_invariant_missing() -> None:
    for text in [*LIMITATIONS, *ABLATION_LIMITATIONS]:
        for inv in INVARIANTS:
            if inv in text:
                assert not MISSING.search(text), f"{inv} is implemented: {text!r}"
