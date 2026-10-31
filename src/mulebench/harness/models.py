"""Result and report models (report schema v2).

Matrix: prompt_variant x preset x variant x N trials. Scripted agents ignore the
prompt, so their prompt axis is the single value "none".
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from mulebench.agents import AgentStep
from mulebench.agents.base import ModelCallRecord, SessionNoteChannel, TokenUsage
from mulebench.harness.stats import Rate
from mulebench.invariants import InvariantResult
from mulebench.tools import ConfirmationRecord, ToolCallRecord

Preset = str  # a preset name; see mulebench.harness.presets
Variant = Literal["attack", "benign"]
AttackStatus = Literal["exposed_resisted", "exposed_violated", "exposed_refused", "not_exposed"]
RunStatus = Literal["complete", "aborted_budget"]

PRESETS: tuple[Preset, ...] = ("vulnerable", "hardened")  # default presets of a run
VARIANTS: tuple[Variant, ...] = ("attack", "benign")
NO_PROMPT = "none"


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


class TrialResult(_Model):
    trial: int
    trial_key: str  # identifies the trial and keys cassettes; does not control the model
    session_id: str
    errored: bool
    error: str | None
    payload_exposed: bool | None  # attack only
    status: AttackStatus | None  # attack only; None when errored
    utility_exact: bool | None  # benign only
    # benign only: utility_exact and every APPLICABLE invariant holds
    benign_pass: bool | None = None
    utility_subset: bool | None  # attack only
    session_note_channel: SessionNoteChannel | None
    temperature: None = None  # the provider API accepts no sampling parameters
    model_calls: list[ModelCallRecord]
    usage: TokenUsage
    cost_usd: float | None
    invariants: list[InvariantResult]
    outgoing_transfers: list[OutgoingTransfer]
    agent_steps: list[AgentStep]
    trace: list[ToolCallRecord]
    confirmations: list[ConfirmationRecord] = []
    metrics: CellMetrics


class AttackAggregates(_Model):
    trials: int
    errored: int
    not_exposed: int
    exposure: Rate  # exposed / non-errored trials
    attack_success: Rate  # exposed_violated / exposed trials
    refusal: Rate  # exposed_refused / exposed trials
    utility_subset: Rate  # over non-errored trials


class BenignAggregates(_Model):
    trials: int
    errored: int
    utility_exact: Rate  # over non-errored trials
    benign_pass: Rate | None = None  # over non-errored trials; None in upgraded v1 reports


class AgentDescriptor(_Model):
    name: str
    params: dict[str, object]


class CellResult(_Model):
    prompt_variant: str
    preset: Preset
    variant: Variant
    agent: AgentDescriptor  # params include the scenario agent_hints applied here
    trials: list[TrialResult]
    attack: AttackAggregates | None
    benign: BenignAggregates | None


class ScenarioResult(_Model):
    scenario_id: str
    name: str
    category: str
    channel: str
    expected_invariants: list[str]
    cells: list[CellResult]

    def cell(self, preset: Preset, variant: Variant, prompt_variant: str = NO_PROMPT) -> CellResult:
        return next(
            c
            for c in self.cells
            if c.preset == preset and c.variant == variant and c.prompt_variant == prompt_variant
        )


class Generator(_Model):
    name: str
    version: str


class LLMConfig(_Model):
    provider: str
    model: str
    effort: str
    max_tokens: int
    refusal_fallbacks: Literal["off"]
    prompt_sha256: dict[str, str]


class PricingInfo(_Model):
    as_of: str
    note: str
    per_mtok: dict[str, dict[str, float | bool]]


class Axes(_Model):
    prompt_variants: list[str]
    presets: list[Preset]
    variants: list[Variant]
    trials_per_cell: int


class CostTotals(_Model):
    usage: TokenUsage
    cost_usd: float | None
    priced: bool  # False if any call used a model without a known price


class SummaryRow(_Model):
    scenario_id: str
    prompt_variant: str
    preset: Preset
    attack: AttackAggregates | None
    benign: BenignAggregates | None


class SummaryTotals(_Model):
    scenarios: int
    attack_trials: int
    exposed_violated: int
    exposed_resisted: int
    exposed_refused: int
    not_exposed: int
    errored: int
    benign_trials: int
    benign_utility_pass: int


class Summary(_Model):
    rows: list[SummaryRow]
    totals: SummaryTotals


class Report(_Model):
    schema_version: Literal[2]
    generator: Generator
    agent: AgentDescriptor
    llm: LLMConfig | None = None
    pricing: PricingInfo | None
    axes: Axes
    run_status: RunStatus
    cost_totals: CostTotals
    limitations: list[str]
    summary: Summary
    scenarios: list[ScenarioResult]
