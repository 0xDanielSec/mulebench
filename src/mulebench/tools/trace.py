"""Append-only record of every tool call made in a session."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

CallOutcome = Literal["ok", "unknown_tool", "invalid_input", "denied", "ledger_error"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class GuardDecision(_Model):
    """A guard verdict. `code` and `reason` are detailed and stay in the trace;
    only `public_code` is shown to the agent."""

    guard: str
    allowed: bool
    code: str | None = None
    reason: str | None = None
    public_code: str | None = None

    @classmethod
    def allow(cls, guard: str, reason: str | None = None) -> GuardDecision:
        return cls(guard=guard, allowed=True, reason=reason)

    @classmethod
    def deny(
        cls, guard: str, code: str, reason: str, *, public_code: str | None = None
    ) -> GuardDecision:
        return cls(
            guard=guard,
            allowed=False,
            code=code,
            reason=reason,
            public_code=public_code or code,
        )


class ToolCallRecord(_Model):
    seq: int
    ts: datetime
    session_id: str
    session_customer_id: str
    tool: str
    args: dict[str, object]
    outcome: CallOutcome
    result: dict[str, object] | None
    # What the agent saw, when a result transformer changed it; None means the
    # agent saw `result` unchanged. Invariants never read this field.
    agent_result: dict[str, object] | None = None
    error: dict[str, object] | None
    guard_decisions: list[GuardDecision]
    untrusted_paths: list[str]


class ConfirmationRecord(_Model):
    """One answer from the customer channel to a confirmation request.

    Written by the harness's recording confirmer, never by guards.
    """

    seq: int
    ts: datetime
    session_id: str
    customer_id: str
    tool: str
    args: dict[str, object]
    approved: bool


class TraceRecorder:
    """Collects `ToolCallRecord`s. There is no way to edit or remove a record."""

    def __init__(self) -> None:
        self._records: list[ToolCallRecord] = []
        self._confirmations: list[ConfirmationRecord] = []

    def record(
        self,
        *,
        ts: datetime,
        session_id: str,
        session_customer_id: str,
        tool: str,
        args: dict[str, object],
        outcome: CallOutcome,
        result: dict[str, object] | None = None,
        agent_result: dict[str, object] | None = None,
        error: dict[str, object] | None = None,
        guard_decisions: list[GuardDecision] | None = None,
        untrusted_paths: list[str] | None = None,
    ) -> ToolCallRecord:
        rec = ToolCallRecord(
            seq=len(self._records) + 1,
            ts=ts,
            session_id=session_id,
            session_customer_id=session_customer_id,
            tool=tool,
            args=args,
            outcome=outcome,
            result=result,
            agent_result=agent_result,
            error=error,
            guard_decisions=guard_decisions or [],
            untrusted_paths=untrusted_paths or [],
        )
        self._records.append(rec)
        return rec

    def records(self) -> tuple[ToolCallRecord, ...]:
        return tuple(self._records)

    def record_confirmation(
        self,
        *,
        ts: datetime,
        session_id: str,
        customer_id: str,
        tool: str,
        args: dict[str, object],
        approved: bool,
    ) -> ConfirmationRecord:
        rec = ConfirmationRecord(
            seq=len(self._confirmations) + 1,
            ts=ts,
            session_id=session_id,
            customer_id=customer_id,
            tool=tool,
            args=args,
            approved=approved,
        )
        self._confirmations.append(rec)
        return rec

    def confirmations(self) -> tuple[ConfirmationRecord, ...]:
        return tuple(self._confirmations)
