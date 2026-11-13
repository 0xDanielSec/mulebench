"""Run benign workloads under guard presets and measure friction.

Each (workload, preset) runs once with the same machinery as attack trials:
fresh seeded ledger, ticking clock, recording confirmer, every invariant
(INV-1 to INV-4) evaluated. Friction is observable: guard denials (with the
denying guard) and confirmation requests (from the customer channel's records).
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from mulebench.agents import Agent, AgentTask, render_session_note
from mulebench.harness.confirmer import OracleConfirmer, RecordingConfirmer, RequestConfirmer
from mulebench.harness.delegation import HandoffArtifact
from mulebench.harness.metrics import unauthorized_outflow_cents
from mulebench.harness.presets import build_guard_set, preset_guard_names
from mulebench.harness.runner import (
    INVARIANTS,
    _run_delegation,
    _TickingClient,
    call_evidence,
    confirmation_evidence,
    utility,
)
from mulebench.harness.seed import seed_setup
from mulebench.invariants import InvariantContext, InvariantResult
from mulebench.tools import Confirmer, ToolContext, TraceRecorder
from mulebench.tools.memory import MemoryStore
from mulebench.workloads import Workload


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DeniedCall(_Model):
    seq: int
    tool: str
    guard: str
    code: str | None


class WorkloadTrial(_Model):
    workload_id: str
    guard_set: str
    trial_key: str
    errored: bool
    error: str | None
    completed: bool  # expected outcome matched exactly (utility_exact)
    denied: list[DeniedCall]
    confirmations_requested: int
    confirmations_approved: int
    tool_calls: int
    unauthorized_outflow_cents: int
    invariants: list[InvariantResult]
    # Delegation workloads only.
    handoff: HandoffArtifact | None = None


def workload_key(workload_id: str, preset: str) -> str:
    return f"workload/{workload_id}/{preset}/t000"


def run_workload(workload: Workload, preset: str, agent: Agent) -> WorkloadTrial:
    key = workload_key(workload.id, preset)
    ledger, clock, note = seed_setup(workload.setup, workload.user_task)
    customer = workload.user_task.customer
    request = workload.user_task.request
    trace = TraceRecorder()
    customer_side: Confirmer = (
        OracleConfirmer(
            [
                (e.from_account, e.to_pix_key, e.amount_cents)
                for e in workload.expected_outcome.transfers
            ]
        )
        if "oracle_confirmation" in preset_guard_names(preset)
        else RequestConfirmer(request)
    )
    confirmer = RecordingConfirmer(customer_side, trace, clock)
    guard_set = build_guard_set(preset, confirmer, key)
    ctx = ToolContext(
        customer_id=customer,
        session_id=key,
        ledger=ledger,
        guards=guard_set.guards,
        transformers=guard_set.transformers,
        trace=trace,
        memory=MemoryStore() if workload.memory else None,
    )
    task = AgentTask(
        customer_id=customer,
        request=request,
        session_note=render_session_note(note),
        trial_key=key,
    )
    handoff: HandoffArtifact | None = None
    try:
        if workload.topology is None:
            run = agent.run(task, _TickingClient(ctx, clock))
        else:
            run, handoff = _run_delegation(
                workload.topology, None, agent, task, ctx, clock, guard_set, note
            )
        snapshot = ledger.snapshot()
        records = list(trace.records())
        confirmations = list(trace.confirmations())
    finally:
        ledger.close()
    inv_ctx = InvariantContext(
        session_customer_id=customer,
        calls=call_evidence(records),
        confirmations=confirmation_evidence(confirmations, key),
        enforced_confirmation_cents=guard_set.enforced_confirmation_cents,
        params=workload.invariant_params,
    )
    exact, _ = utility(workload.expected_outcome, snapshot, records, customer)
    return WorkloadTrial(
        workload_id=workload.id,
        guard_set=preset,
        trial_key=key,
        errored=run.stopped == "errored",
        error=run.error,
        completed=exact,
        denied=[
            DeniedCall(seq=r.seq, tool=r.tool, guard=d.guard, code=d.code)
            for r in records
            if r.outcome == "denied"
            for d in r.guard_decisions
            if not d.allowed
        ],
        confirmations_requested=len(confirmations),
        confirmations_approved=sum(c.approved for c in confirmations),
        tool_calls=len(records),
        unauthorized_outflow_cents=unauthorized_outflow_cents(snapshot, inv_ctx),
        invariants=[inv.check(snapshot, inv_ctx) for inv in INVARIANTS.values()],
        handoff=handoff,
    )


def run_workloads(
    workloads: Sequence[Workload], agent: Agent, presets: Sequence[str]
) -> list[WorkloadTrial]:
    for p in presets:
        preset_guard_names(p)  # raises UnknownPreset before any trial runs
    return [
        run_workload(w, p, agent) for w in sorted(workloads, key=lambda w: w.id) for p in presets
    ]
