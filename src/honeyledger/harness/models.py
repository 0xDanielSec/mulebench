"""Result and report models. Serialized as the versioned JSON report."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from honeyledger.agents import AgentStep
from honeyledger.invariants import InvariantResult
from honeyledger.tools import ToolCallRecord

Preset = Literal["vulnerable", "hardened"]
Variant = Literal["attack", "benign"]
AttackStatus = Literal["exposed_resisted", "exposed_violated", "not_exposed"]

PRESETS: tuple[Preset, ...] = ("vulnerable", "hardened")
VARIANTS: tuple[Variant, ...] = ("attack", "benign")


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class OutgoingTransfer(_Model):
    id: str
    kind: str
    from_account_id: str | None
    to_pix_key: str | None
    amount_cents: int
    authorization_id: str | None
    actor: str
    created_at: datetime


class CellMetrics(_Model):
    steps: int
    stopped: str
    tool_calls: int
    ok_calls: int
    denied_calls: int
    failed_calls: int
    injected_steps: int


class CellResult(_Model):
    preset: Preset
    variant: Variant
    session_id: str
    payload_exposed: bool | None  # attack runs only
    status: AttackStatus | None  # attack runs only
    utility_exact: bool | None  # benign runs only
    utility_subset: bool | None  # attack runs only
    invariants: list[InvariantResult]
    outgoing_transfers: list[OutgoingTransfer]
    agent_steps: list[AgentStep]
    trace: list[ToolCallRecord]
    metrics: CellMetrics


class ScenarioResult(_Model):
    scenario_id: str
    name: str
    category: str
    channel: str
    expected_invariants: list[str]
    cells: list[CellResult]

    def cell(self, preset: Preset, variant: Variant) -> CellResult:
        return next(c for c in self.cells if c.preset == preset and c.variant == variant)


class Generator(_Model):
    name: str
    version: str


class AgentDescriptor(_Model):
    name: str
    params: dict[str, object]


class SummaryRow(_Model):
    scenario_id: str
    preset: Preset
    attack_status: AttackStatus | None
    attack_utility_subset: bool | None
    benign_utility_exact: bool | None
    attack_invariants_hold: bool


class SummaryTotals(_Model):
    scenarios: int
    attack_cells: int
    exposed_violated: int
    exposed_resisted: int
    not_exposed: int
    benign_cells: int
    benign_utility_pass: int


class Summary(_Model):
    rows: list[SummaryRow]
    totals: SummaryTotals


class Report(_Model):
    schema_version: Literal[1]
    generator: Generator
    agent: AgentDescriptor
    limitations: list[str]
    summary: Summary
    scenarios: list[ScenarioResult]
