"""Versioned, deterministic JSON report (schema_version 1)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import mulebench
from mulebench.agents import Agent
from mulebench.harness.models import (
    PRESETS,
    AgentDescriptor,
    Generator,
    Report,
    ScenarioResult,
    Summary,
    SummaryRow,
    SummaryTotals,
)

LIMITATIONS = [
    "The scripted agent obeys instructions found in tool output by construction; "
    "results validate the harness, not the vulnerability of any real model.",
    "All scenario data is synthetic.",
    "INV-1 assumes a single session per run.",
    "Only INV-1 is implemented.",
]


def build_report(results: Sequence[ScenarioResult], agent: Agent) -> Report:
    rows: list[SummaryRow] = []
    for s in sorted(results, key=lambda r: r.scenario_id):
        for preset in PRESETS:
            attack, benign = s.cell(preset, "attack"), s.cell(preset, "benign")
            rows.append(
                SummaryRow(
                    scenario_id=s.scenario_id,
                    preset=preset,
                    attack_status=attack.status,
                    attack_utility_subset=attack.utility_subset,
                    benign_utility_exact=benign.utility_exact,
                    attack_invariants_hold=all(i.holds for i in attack.invariants),
                )
            )
    attack_cells = [c for s in results for c in s.cells if c.variant == "attack"]
    benign_cells = [c for s in results for c in s.cells if c.variant == "benign"]
    totals = SummaryTotals(
        scenarios=len(results),
        attack_cells=len(attack_cells),
        exposed_violated=sum(c.status == "exposed_violated" for c in attack_cells),
        exposed_resisted=sum(c.status == "exposed_resisted" for c in attack_cells),
        not_exposed=sum(c.status == "not_exposed" for c in attack_cells),
        benign_cells=len(benign_cells),
        benign_utility_pass=sum(c.utility_exact is True for c in benign_cells),
    )
    return Report(
        schema_version=1,
        generator=Generator(name="mulebench", version=mulebench.__version__),
        agent=AgentDescriptor(name=type(agent).__name__, params=dict(getattr(agent, "params", {}))),
        limitations=list(LIMITATIONS),
        summary=Summary(rows=rows, totals=totals),
        scenarios=sorted(results, key=lambda r: r.scenario_id),
    )


def report_to_json(report: Report) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def write_report(report: Report, path: Path) -> None:
    path.write_bytes(report_to_json(report).encode("utf-8"))


def report_json_schema() -> dict[str, Any]:
    return Report.model_json_schema()


def schema_to_json() -> str:
    return json.dumps(report_json_schema(), indent=2, ensure_ascii=False) + "\n"
