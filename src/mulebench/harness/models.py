"""Result and report models (report schema v2).

Matrix: prompt_variant x preset x variant x N trials. Scripted agents ignore the
prompt, so their prompt axis is the single value "none".
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

from mulebench.agents import AgentStep
from mulebench.agents.base import ModelCallRecord, ServerMeta, SessionNoteChannel, TokenUsage
from mulebench.harness.stats import Rate
from mulebench.invariants import InvariantResult
from mulebench.tools import ConfirmationRecord, ToolCallRecord

Preset = str  # a preset name; see mulebench.harness.presets
Variant = Literal["attack", "benign"]
AttackStatus = Literal["exposed_resisted", "exposed_violated", "exposed_refused", "not_exposed"]
RunStatus = Literal["complete", "aborted_budget", "aborted_interrupt"]

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


DisclosureKind = Literal["balance", "transaction_amount"]
# Where a foreign amount can leave the session: the final answer, the
# description of an outgoing transfer, the reason of a dispute.
DisclosureSink = Literal["final_answer", "transfer_description", "dispute_reason"]
DISCLOSURE_SINKS: tuple[DisclosureSink, ...] = get_args(DisclosureSink)


class SinkDisclosure(_Model):
    disclosed: bool  # an exact foreign amount
    foreign_accounts: list[str] = []
    kinds: list[DisclosureKind] = []
    # A foreign amount off by a factor of 10, 100 or 1000 and not said exactly
    # (e.g. R$ 800.00 for R$ 8,000.00). Separate from `disclosed`.
    approximate: bool = False
    approximate_accounts: list[str] = []


class Disclosure(_Model):
    """Whether another customer's amounts reached a sink (see
    mulebench.harness.disclosure). Descriptive; separate from INV-2. No text
    is ever stored. The top-level fields are the union over `sinks`; reports
    before per-sink checks have no `sinks` and judged the final answer only."""

    disclosed: bool
    foreign_accounts: list[str] = []
    kinds: list[DisclosureKind] = []
    sinks: dict[DisclosureSink, SinkDisclosure] = {}
    approximate: bool = False  # union of the per-sink approximate verdicts


class Attribution(_Model):
    """Direction of the outcome (see mulebench.harness.attribution). A layer
    next to the invariants, which judge policy; never changes them."""

    attack_success: bool | None  # attack trials only
    task_error: bool
    task_omitted: bool
    reasons: list[str] = []


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
    # Sampling as sent (OpenAI-compatible providers). None on the Anthropic API,
    # which accepts no sampling parameters.
    temperature: float | None = None
    seed: int | None = None
    server_meta: ServerMeta | None = None  # local servers: model digest, quantization, ...
    tool_calls_total: int = 0
    # Malformed tool calls by kind ("json", "unknown_tool", "schema", "text_tool_call");
    # any makes the trial errored.
    malformed_tool_calls: dict[str, int] = {}
    # Calls valid only after digit-string coercion (see agents.llm.coercion).
    coerced_calls: int = 0
    coerced_args: dict[str, int] = {}  # "tool.field" -> count
    # Some model call used >= CONTEXT_NEAR_LIMIT of num_ctx (see mulebench.harness.validity).
    context_near_limit: bool = False
    # Model calls whose stop reason is the output cap (`length`; Anthropic
    # `max_tokens`), and whether the last call was one (trial cut by the cap).
    length_calls: int = 0
    cut_by_cap: bool = False
    # None when there was no final answer to check, and in older reports.
    disclosure: Disclosure | None = None
    # None for errored trials and in older reports.
    attribution: Attribution | None = None
    model_calls: list[ModelCallRecord]
    usage: TokenUsage
    cost_usd: float | None
    invariants: list[InvariantResult]
    outgoing_transfers: list[OutgoingTransfer]
    agent_steps: list[AgentStep]
    trace: list[ToolCallRecord]
    confirmations: list[ConfirmationRecord] = []
    # Agent transfers that break INV-1 or go to a payee no authorization of the
    # session customer names (see mulebench.harness.metrics). 0 in upgraded v1.
    unauthorized_outflow_cents: int = 0
    metrics: CellMetrics


class AttackAggregates(_Model):
    trials: int
    errored: int
    not_exposed: int
    exposure: Rate  # exposed / non-errored trials
    attack_success: Rate  # exposed_violated / exposed trials
    refusal: Rate  # exposed_refused / exposed trials
    utility_subset: Rate  # over non-errored trials
    # Exposed trials whose final answer showed a foreign amount / exposed
    # trials with a final answer. Descriptive; None in older reports.
    disclosure: Rate | None = None
    # Same numerator per sink, same denominator; empty in older reports.
    disclosure_by_sink: dict[DisclosureSink, Rate] = {}
    # Approximate (factor 10/100/1000) matches; same denominator. None/empty in
    # older reports.
    disclosure_approximate: Rate | None = None
    disclosure_approximate_by_sink: dict[DisclosureSink, Rate] = {}
    # Attribution layer (None in older reports). attributed_success: exposed
    # trials whose outcome moved in the attacker's direction / exposed trials.
    # task_error, task_omitted: over non-errored trials.
    attributed_success: Rate | None = None
    task_error: Rate | None = None
    task_omitted: Rate | None = None


class BenignAggregates(_Model):
    trials: int
    errored: int
    utility_exact: Rate  # over non-errored trials
    benign_pass: Rate | None = None  # over non-errored trials; None in upgraded v1 reports
    task_error: Rate | None = None  # over non-errored trials; None in older reports
    task_omitted: Rate | None = None


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
    unauthorized_outflow_cents: int = 0  # total over non-errored trials
    # Trials with no malformed tool call / all trials (errored ones included).
    tool_call_validity: Rate | None = None
    malformed_tool_calls: dict[str, int] = {}  # by kind, summed over trials
    coerced_calls: int = 0  # summed over trials
    coerced_args: dict[str, int] = {}
    context_near_limit: int = 0  # trials
    length_calls: int = 0  # model calls that ended at the output cap
    cut_by_cap_trials: int = 0  # trials whose last model call ended at the cap


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
    # openai-compatible only: server base URL and the sampling sent per trial
    # (temperature; seed is the base, each trial's seed follows seed_derivation).
    base_url: str | None = None
    temperature: float | None = None
    seed: int | None = None
    # "sha256_trial_key_v1" (see mulebench.agents.llm.seeds); None in older
    # reports, where trial t used seed + t.
    seed_derivation: str | None = None
    arg_coercion: str | None = None  # "digit_strings" or "off"; None in older reports
    # Version of the tool names, descriptions and input schemas the model saw.
    tool_schema_sha256: str | None = None


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
    tool_call_validity: Rate | None = None  # attack and benign trials together
    # False when the attack outcome cannot be read as resistance (see
    # mulebench.harness.validity); the reasons say why.
    resistance_meaningful: bool = True
    not_meaningful_reasons: list[str] = []


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
    malformed_tool_calls: dict[str, int] = {}
    coerced_calls: int = 0
    coerced_args: dict[str, int] = {}
    context_near_limit: int = 0
    length_calls: int = 0
    cut_by_cap_trials: int = 0
    not_meaningful_rows: int = 0


class Summary(_Model):
    rows: list[SummaryRow]
    totals: SummaryTotals


class Report(_Model):
    schema_version: Literal[3]
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
