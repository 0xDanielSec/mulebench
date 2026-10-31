"""Read v1, v2 or v3 reports, presented as v3.

v2 differs from v3 only by fields v3 adds with defaults, so a v2 report is read
as v3 with those defaults. v2 recorded no malformed-call or context data, so its
rows read as resistance_meaningful=true by default. v1 is upgraded (one trial,
prompt "none").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mulebench.agents.base import TokenUsage
from mulebench.harness.models import (
    NO_PROMPT,
    PRESETS,
    VARIANTS,
    AgentDescriptor,
    Axes,
    CellMetrics,
    CostTotals,
    Generator,
    OutgoingTransfer,
    Report,
    ScenarioResult,
    Summary,
    SummaryRow,
    SummaryTotals,
    TrialResult,
)
from mulebench.harness.runner import build_cell
from mulebench.invariants import InvariantResult, violation
from mulebench.reports import v1_models as v1


class UnsupportedReportVersion(ValueError):
    pass


def load_report(path: Path) -> Report:
    return parse_report_json(path.read_text(encoding="utf-8"))


def parse_report(data: dict[str, Any]) -> Report:
    return parse_report_json(json.dumps(data))


def parse_report_json(text: str) -> Report:
    # JSON-mode validation: strict models accept JSON arrays for tuple fields.
    data = json.loads(text)
    version = data.get("schema_version")
    if version == 3:
        return Report.model_validate_json(text)
    if version == 2:
        data["schema_version"] = 3
        return Report.model_validate_json(json.dumps(data))
    if version == 1:
        return upgrade_v1(v1.Report.model_validate_json(text))
    raise UnsupportedReportVersion(f"unsupported report schema_version: {version!r}")


def _upgrade_invariant(old: v1.InvariantResult) -> InvariantResult:
    return InvariantResult(
        id=old.id,
        holds=old.holds,
        checked_transfers=old.checked_transfers,
        checked_calls=0,
        violations=tuple(
            violation(
                v.code,
                v.detail,
                transfer_id=v.transfer_id,
                authorization_id=v.authorization_id,
            )
            for v in old.violations
        ),
    )


def upgrade_v1(old: v1.Report) -> Report:
    agent = AgentDescriptor(name=old.agent.name, params={**old.agent.params, "agent_hints": {}})
    scenarios: list[ScenarioResult] = []
    for s in old.scenarios:
        cells = []
        for c in s.cells:
            trial = TrialResult(
                trial=0,
                trial_key=c.session_id,
                session_id=c.session_id,
                errored=False,
                error=None,
                payload_exposed=c.payload_exposed,
                status=c.status,
                utility_exact=c.utility_exact,
                utility_subset=c.utility_subset,
                session_note_channel=None,
                model_calls=[],
                usage=TokenUsage(),
                cost_usd=None,
                invariants=[_upgrade_invariant(i) for i in c.invariants],
                outgoing_transfers=[
                    OutgoingTransfer(**t.model_dump()) for t in c.outgoing_transfers
                ],
                agent_steps=c.agent_steps,
                trace=c.trace,
                metrics=CellMetrics(**c.metrics.model_dump()),
            )
            cells.append(build_cell(NO_PROMPT, c.preset, c.variant, [trial], agent))
        scenarios.append(
            ScenarioResult(
                scenario_id=s.scenario_id,
                name=s.name,
                category=s.category,
                channel=s.channel,
                expected_invariants=s.expected_invariants,
                cells=cells,
            )
        )
    rows = [
        SummaryRow(
            scenario_id=s.scenario_id,
            prompt_variant=NO_PROMPT,
            preset=preset,
            attack=s.cell(preset, "attack").attack,
            benign=s.cell(preset, "benign").benign,
        )
        for s in scenarios
        for preset in PRESETS
    ]
    t = old.summary.totals
    return Report(
        schema_version=3,
        generator=Generator(**old.generator.model_dump()),
        agent=AgentDescriptor(**old.agent.model_dump()),  # top level stays as recorded
        llm=None,
        pricing=None,
        axes=Axes(
            prompt_variants=[NO_PROMPT],
            presets=list(PRESETS),
            variants=list(VARIANTS),
            trials_per_cell=1,
        ),
        run_status="complete",
        cost_totals=CostTotals(usage=TokenUsage(), cost_usd=None, priced=True),
        limitations=old.limitations,
        summary=Summary(
            rows=rows,
            totals=SummaryTotals(
                scenarios=t.scenarios,
                attack_trials=t.attack_cells,
                exposed_violated=t.exposed_violated,
                exposed_resisted=t.exposed_resisted,
                exposed_refused=0,
                not_exposed=t.not_exposed,
                errored=0,
                benign_trials=t.benign_cells,
                benign_utility_pass=t.benign_utility_pass,
            ),
        ),
        scenarios=scenarios,
    )
