"""Attribution for the viewer: stored when the report has it, otherwise
computed post-hoc from stored transfers and trace with the same code as
scripts/reanalyze.py (`attribute_stored`), and labelled as such."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from mulebench.harness.attribution import attribute_stored
from mulebench.harness.models import Attribution, CellResult, ScenarioResult, TrialResult
from mulebench.harness.stats import Rate, wilson
from mulebench.viewer.scenarios import builtin_scenarios

Source = Literal["stored", "post-hoc", "unavailable"]
POSTHOC_LABEL = "post-hoc (computed by viewer)"


@dataclass(frozen=True)
class CellAttribution:
    source: Source
    attributed_success: Rate | None  # attack cells only
    task_error: Rate | None
    task_omitted: Rate | None


def trial_attribution(
    s: ScenarioResult, c: CellResult, t: TrialResult
) -> tuple[Attribution | None, Source]:
    if t.errored:
        return None, "unavailable"
    if t.attribution is not None:
        return t.attribution, "stored"
    scenario = builtin_scenarios().get(s.scenario_id)
    if scenario is None:
        return None, "unavailable"
    return attribute_stored(scenario, c.variant, t), "post-hoc"


def cell_attribution(s: ScenarioResult, c: CellResult) -> CellAttribution:
    ok = [t for t in c.trials if not t.errored]
    pairs = [(t, *trial_attribution(s, c, t)) for t in ok]
    if any(a is None for _, a, _ in pairs):
        return CellAttribution("unavailable", None, None, None)
    sources = {src for _, _, src in pairs}
    source: Source = "post-hoc" if "post-hoc" in sources else "stored"
    attrs = [a for _, a, _ in pairs if a is not None]
    task_error = wilson(sum(a.task_error for a in attrs), len(attrs))
    task_omitted = wilson(sum(a.task_omitted for a in attrs), len(attrs))
    attributed = None
    if c.variant == "attack":
        exposed = [a for t, a, _ in pairs if t.payload_exposed and a is not None]
        attributed = wilson(sum(a.attack_success is True for a in exposed), len(exposed))
    return CellAttribution(source, attributed, task_error, task_omitted)
