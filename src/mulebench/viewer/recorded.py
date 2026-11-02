"""Missing data is never a number.

Reports grow fields over time, and pydantic fills a field missing from an
older report with its default (0, False, None). The viewer must not show that
default as a measurement. `model_fields_set` says whether a field was present
in the stored JSON (or set by the harness that built the report); anything
else renders as "not recorded", or as a value derived from data the report
did store, labelled as derived.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from mulebench.harness.models import CellResult, Report, TrialResult
from mulebench.harness.validity import hit_output_cap

NOT_RECORDED = "not recorded"
DERIVED_CAP = "derived from stop reasons"


def recorded(model: BaseModel, field: str) -> bool:
    return field in model.model_fields_set


def shown(model: BaseModel, field: str, fmt: Callable[[object], str] = str) -> str:
    """The field formatted, or "not recorded" when the report did not store it."""
    if not recorded(model, field):
        return NOT_RECORDED
    value = getattr(model, field)
    return NOT_RECORDED if value is None else fmt(value)


@dataclass(frozen=True)
class CapCuts:
    """Model calls that ended at the output cap, and trials whose last call did."""

    calls: int
    trials: int
    derived: bool  # computed from stored stop reasons, not stored by the harness

    def label(self, n: int) -> str:
        return f"{n} ({DERIVED_CAP})" if self.derived else str(n)


def trial_cap(t: TrialResult) -> CapCuts:
    if recorded(t, "length_calls") and recorded(t, "cut_by_cap"):
        return CapCuts(t.length_calls, int(t.cut_by_cap), derived=False)
    reasons = [m.stop_reason for m in t.model_calls]
    cut = bool(reasons) and hit_output_cap(reasons[-1])
    return CapCuts(sum(hit_output_cap(r) for r in reasons), int(cut), derived=True)


def cell_cap(c: CellResult) -> CapCuts:
    if recorded(c, "length_calls") and recorded(c, "cut_by_cap_trials"):
        return CapCuts(c.length_calls, c.cut_by_cap_trials, derived=False)
    per = [trial_cap(t) for t in c.trials]
    return CapCuts(sum(p.calls for p in per), sum(p.trials for p in per), derived=True)


def report_cap(report: Report) -> CapCuts:
    t = report.summary.totals
    if recorded(t, "length_calls") and recorded(t, "cut_by_cap_trials"):
        return CapCuts(t.length_calls, t.cut_by_cap_trials, derived=False)
    per = [cell_cap(c) for s in report.scenarios for c in s.cells]
    return CapCuts(sum(p.calls for p in per), sum(p.trials for p in per), derived=True)


def money(value: object) -> str:
    """Formatter for `shown`: centavos as reais."""
    if not isinstance(value, int):
        return NOT_RECORDED
    sign = "-" if value < 0 else ""
    v = abs(value)
    return f"{sign}R$ {v // 100:,}.{v % 100:02d}"


def yes_no(value: bool | None) -> str:
    return NOT_RECORDED if value is None else ("yes" if value else "no")
