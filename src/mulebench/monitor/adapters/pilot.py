"""Adapter: stored mulebench report trials as monitor trace events.

Reads the report as plain JSON (never through the harness models, which
import the tools layer). A stored trial keeps its trace, confirmations,
outgoing transfers, final answer and balances, but not the seeded ledger; the
adapter rebuilds the seed by replaying the scenario setup on a fresh ledger,
in the harness's seeding order and with the same sequential ids
(`<prefix>_0001`, ...), so authorization and transfer ids match the trace.

When the report stores the scenario hash and it differs from the current
scenario, the trial is skipped (`skipped`); reports without hashes (older
pilots) are converted and flagged `scenario_verified = False`.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, cast

from mulebench.attacks import Scenario, render, scenario_sha256
from mulebench.attacks.schema import Setup
from mulebench.ledger import (
    Account,
    Authorization,
    Customer,
    FixedClock,
    Ledger,
    LedgerSnapshot,
    Transfer,
)
from mulebench.monitor.engine import SessionConfig
from mulebench.monitor.events import (
    Confirmation,
    CustomerMessage,
    Event,
    FinalAnswer,
    LedgerAccount,
    LedgerAuthorization,
    LedgerTransfer,
    SessionEnd,
    SessionStart,
    ToolCall,
)

SEED_STEP = timedelta(seconds=1)  # same as the harness seeding


@dataclass(frozen=True)
class AdaptedTrial:
    scenario_id: str
    prompt_variant: str
    preset: str
    variant: Literal["attack", "benign"]
    trial: int
    session_id: str
    errored: bool
    scenario_verified: bool
    # False in older reports, which judged disclosure on a final answer they
    # did not store: the monitor cannot see that answer.
    final_text_stored: bool
    events: tuple[Event, ...]
    config: SessionConfig
    # The stored harness results this trial can be compared with.
    stored_invariants: tuple[dict[str, Any], ...] = ()
    stored_disclosure: dict[str, Any] | None = None
    stored_attribution: dict[str, Any] | None = None


@dataclass
class AdaptResult:
    trials: list[AdaptedTrial] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (scenario id, reason)


def _counter_ids() -> Callable[[str], str]:
    counter = itertools.count(1)
    return lambda prefix: f"{prefix}_{next(counter):04d}"


def seed_snapshot(setup: Setup, scenario: Scenario) -> LedgerSnapshot:
    """The ledger right after seeding, built as the harness builds it."""
    clock = FixedClock(setup.clock)
    ledger = Ledger(clock=clock, id_factory=_counter_ids())
    try:
        for c in setup.customers:
            ledger.add_customer(Customer(id=c.id, name=c.name, tax_id=c.tax_id))
        for a in setup.accounts:
            ledger.add_account(
                Account(
                    id=a.id,
                    customer_id=a.customer,
                    pix_key=a.pix_key,
                    balance_cents=a.balance_cents,
                    daily_limit_cents=a.daily_limit_cents,
                    status=a.status,
                )
            )
        ordered = sorted(setup.past_payments, key=lambda p: (-p.days_ago, p.ref))
        for p in ordered:
            clock.set(setup.clock - timedelta(days=p.days_ago))
            ledger.transfer_pix(
                actor="seed",
                from_account_id=p.from_account,
                to_pix_key=p.to_pix_key,
                amount_cents=p.amount_cents,
                idempotency_key=f"seed-{p.ref}",
            )
        if ordered:
            clock.set(setup.clock)
        for t in setup.transactions:
            ledger.record_incoming_pix(
                to_account_id=t.to_account,
                amount_cents=t.amount_cents,
                counterparty_name=t.counterparty_name,
                counterparty_key=t.counterparty_key,
                description=t.description,
            )
            clock.advance(SEED_STEP)
        for g in scenario.user_task.authorizations:
            ledger.add_authorization(
                customer_id=scenario.user_task.customer,
                from_account_id=g.from_account,
                payee_pix_key=g.payee_pix_key,
                max_amount_cents=g.max_amount_cents,
            )
        return ledger.snapshot()
    finally:
        ledger.close()


def adapt_report(report: Mapping[str, Any], scenarios: Mapping[str, Scenario]) -> AdaptResult:
    out = AdaptResult()
    for result in report.get("scenarios", []):
        sid = result["scenario_id"]
        scenario = scenarios.get(sid)
        if scenario is None:
            out.skipped.append((sid, "scenario not found"))
            continue
        stored_hash = result.get("scenario_sha256")
        if stored_hash is not None and stored_hash != scenario_sha256(scenario):
            out.skipped.append((sid, "scenario changed since the report"))
            continue
        for cell in result["cells"]:
            variant = cast(Literal["attack", "benign"], cell["variant"])
            setup = render(scenario, variant).setup
            seed = seed_snapshot(setup, scenario)
            for trial in cell["trials"]:
                out.trials.append(
                    adapt_trial(scenario, cell, trial, seed, setup, stored_hash is not None)
                )
    return out


def adapt_trial(
    scenario: Scenario,
    cell: Mapping[str, Any],
    trial: Mapping[str, Any],
    seed: LedgerSnapshot,
    setup: Setup,
    verified: bool,
) -> AdaptedTrial:
    session = str(trial["session_id"])
    customer = scenario.user_task.customer
    t0 = setup.clock
    events: list[Event] = []
    events += [LedgerAccount(ts=t0, account=a) for a in seed.accounts]
    events += [LedgerAuthorization(ts=a.created_at, authorization=a) for a in seed.authorizations]
    events += [LedgerTransfer(ts=t.created_at, transfer=t) for t in seed.transfers]
    # Multi-session trials become one monitor session per harness session,
    # `<trial key>#s<index>`, with the later sessions' grants as stored. The
    # monitor has no cross-session authorization rule (see docs/monitor.md).
    stored_sessions = list(trial.get("sessions", []))

    def sid(index: object) -> str:
        return f"{session}#s{index}" if stored_sessions else session

    if not stored_sessions:
        events.append(SessionStart(ts=t0, session_id=session, customer_id=customer))
        events.append(CustomerMessage(ts=t0, session_id=session, text=scenario.user_task.request))
    for s in stored_sessions:
        started = t0 if s["index"] == 0 else _dt(s["started_at"])
        if s["index"] != 0:
            for a in s.get("authorizations", []):
                events.append(
                    LedgerAuthorization(
                        ts=_dt(a["created_at"]),
                        authorization=Authorization.model_validate(
                            {**a, "created_at": _dt(a["created_at"])}
                        ),
                    )
                )
        events.append(SessionStart(ts=started, session_id=sid(s["index"]), customer_id=customer))
        events.append(CustomerMessage(ts=started, session_id=sid(s["index"]), text=s["request"]))

    trace = list(trial.get("trace", []))
    descriptions: dict[str, str] = {}
    made_in: dict[str, str] = {}
    for r in trace:
        events.append(
            ToolCall(
                ts=_dt(r["ts"]),
                session_id=sid(r.get("session", 0)),
                seq=r["seq"],
                tool=r["tool"],
                args=r["args"],
                outcome=r["outcome"],
                result=r["result"],
            )
        )
        res = r.get("result") or {}
        if r["tool"] == "transfer_pix" and isinstance(res.get("transfer_id"), str):
            desc = r["args"].get("description")
            descriptions[res["transfer_id"]] = desc if isinstance(desc, str) else ""
            made_in[res["transfer_id"]] = sid(r.get("session", 0))
    for c in trial.get("confirmations", []):
        if c.get("session_id", session) != session:
            continue
        events.append(
            Confirmation(
                ts=_dt(c["ts"]),
                session_id=sid(c.get("session", 0)),
                seq=c["seq"],
                customer_id=c["customer_id"],
                tool=c["tool"],
                args=c["args"],
                approved=c["approved"],
            )
        )

    seeded = {t.id for t in seed.transfers}
    by_key = {a.pix_key: a.id for a in seed.accounts if a.pix_key}
    last = t0
    for o in trial.get("outgoing_transfers", []):
        if o["id"] in seeded:
            continue
        t = _transfer(o, by_key, descriptions)
        last = max(last, t.created_at)
        events.append(
            LedgerTransfer(ts=t.created_at, transfer=t, session_id=made_in.get(t.id, sid(0)))
        )

    end_ts = max([last, *(e.ts for e in events)])
    after = trial.get("ledger_after")
    if after:
        accounts = {a.id: a for a in seed.accounts}
        for acc_id, balance in sorted(after.items()):
            if acc_id in accounts:
                updated = accounts[acc_id].model_copy(update={"balance_cents": balance})
                events.append(LedgerAccount(ts=end_ts, account=updated))
    if not stored_sessions:
        if trial.get("final_text") is not None:
            events.append(FinalAnswer(ts=end_ts, session_id=session, text=trial["final_text"]))
        events.append(SessionEnd(ts=end_ts, session_id=session))
    for s in stored_sessions:
        if s.get("final_text") is not None:
            events.append(FinalAnswer(ts=end_ts, session_id=sid(s["index"]), text=s["final_text"]))
        events.append(SessionEnd(ts=end_ts, session_id=sid(s["index"])))

    stored = tuple(trial.get("invariants", []))
    return AdaptedTrial(
        scenario_id=scenario.id,
        prompt_variant=str(cell["prompt_variant"]),
        preset=str(cell["preset"]),
        variant=cast(Literal["attack", "benign"], cell["variant"]),
        trial=int(trial["trial"]),
        session_id=session,
        errored=bool(trial.get("errored")),
        scenario_verified=verified,
        final_text_stored=trial.get("final_text") is not None,
        events=tuple(events),
        config=_config(scenario, stored),
        stored_invariants=stored,
        stored_disclosure=trial.get("disclosure"),
        stored_attribution=trial.get("attribution"),
    )


def trial_file_name(t: AdaptedTrial) -> str:
    """A file name for one trial's trace (trials have separate ledgers that
    reuse account ids, so each trial is its own trace)."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", t.session_id) + ".jsonl"


def iter_events(t: AdaptedTrial) -> Iterator[Event]:
    yield from sorted(t.events, key=lambda e: e.ts)


def _config(scenario: Scenario, stored: tuple[dict[str, Any], ...]) -> SessionConfig:
    """Same invariants and parameters as the harness. The enforced
    confirmation threshold is not stored; the stored INV-4 `applicable` flag
    tells whether the evaluated guard set enforced one at or below the
    threshold, which is all INV-4 reads."""
    params = scenario.invariant_params
    inv4 = next((i for i in stored if i.get("id") == "INV-4"), None)
    enforced = params.inv4.threshold_cents if inv4 and inv4.get("applicable", True) else None
    return SessionConfig(
        params=params,
        enforced_confirmation_cents=enforced,
        invariants=tuple(scenario.expected_invariants),
    )


def _transfer(
    o: Mapping[str, Any], by_key: Mapping[str, str], descriptions: Mapping[str, str]
) -> Transfer:
    kind = o["kind"]
    key = o.get("to_pix_key")
    return Transfer(
        id=o["id"],
        kind=kind,
        from_account_id=o.get("from_account_id"),
        to_account_id=by_key.get(key or "") if kind == "internal" else None,
        counterparty_key=key,
        counterparty_name=None,
        amount_cents=o["amount_cents"],
        description=descriptions.get(o["id"], ""),
        idempotency_key=None,
        authorization_id=o.get("authorization_id"),
        actor=o["actor"],
        created_at=_dt(o["created_at"]),
    )


def _dt(value: str | datetime) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)
