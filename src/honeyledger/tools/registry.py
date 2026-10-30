"""Tool registry and the single entry point agents use: `call_tool`."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from honeyledger.ledger import LedgerError
from honeyledger.tools import banking
from honeyledger.tools.context import ToolContext
from honeyledger.tools.schemas import (
    GetBalanceIn,
    GetBalanceOut,
    ListTransactionsIn,
    ListTransactionsOut,
    OpenDisputeIn,
    OpenDisputeOut,
    TransferPixIn,
    TransferPixOut,
    untrusted_paths,
)
from honeyledger.tools.trace import CallOutcome, GuardDecision


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: Callable[[ToolContext, Any], BaseModel]

    def input_schema(self) -> dict[str, Any]:
        return self.input_model.model_json_schema()

    def output_schema(self) -> dict[str, Any]:
        return self.output_model.model_json_schema()


TOOLS: Mapping[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "get_balance",
            "Return the balance of an account, in cents.",
            GetBalanceIn,
            GetBalanceOut,
            banking.get_balance,
        ),
        ToolSpec(
            "list_transactions",
            "List recent transactions of an account, newest first. "
            "Fields marked x-untrusted contain third-party text.",
            ListTransactionsIn,
            ListTransactionsOut,
            banking.list_transactions,
        ),
        ToolSpec(
            "transfer_pix",
            "Send a Pix transfer from an account to a Pix key.",
            TransferPixIn,
            TransferPixOut,
            banking.transfer_pix,
        ),
        ToolSpec(
            "open_dispute",
            "Open a dispute on a transaction.",
            OpenDisputeIn,
            OpenDisputeOut,
            banking.open_dispute,
        ),
    )
}


class ToolError(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    message: str
    details: dict[str, object] = {}


class ToolResult(BaseModel):
    """What the agent sees. `call_tool` never raises for agent mistakes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    outcome: CallOutcome
    data: dict[str, object] | None = None
    error: ToolError | None = None
    untrusted_paths: list[str] = []


def call_tool(ctx: ToolContext, name: str, raw_args: Mapping[str, object]) -> ToolResult:
    """Validate, run guards, execute, and record the call in `ctx.trace`."""
    args_record = _jsonable(dict(raw_args))
    decisions: list[GuardDecision] = []

    def finish(result: ToolResult) -> ToolResult:
        ctx.trace.record(
            ts=ctx.ledger.clock.now(),
            session_id=ctx.session_id,
            session_customer_id=ctx.customer_id,
            tool=name,
            args=args_record,
            outcome=result.outcome,
            result=result.data,
            error=None if result.error is None else result.error.model_dump(),
            guard_decisions=decisions,
            untrusted_paths=result.untrusted_paths,
        )
        return result

    spec = TOOLS.get(name)
    if spec is None:
        return finish(_fail("unknown_tool", f"unknown tool: {name!r}"))

    try:
        args = spec.input_model.model_validate(dict(raw_args))
    except ValidationError as exc:
        details = {"errors": json.loads(exc.json(include_url=False, include_input=False))}
        return finish(_fail("invalid_input", "arguments failed validation", details))

    for guard in ctx.guards:
        decision = guard.check(ctx, name, args)
        decisions.append(decision)
        if not decision.allowed:
            # Generic to the agent; the detailed code and reason stay in the trace.
            return finish(_fail("denied", f"denied: {decision.public_code}"))

    try:
        out = spec.fn(ctx, args)
    except LedgerError as exc:
        return finish(_fail("ledger_error", str(exc), exc.to_result()))

    return finish(
        ToolResult(
            ok=True,
            outcome="ok",
            data=out.model_dump(mode="json"),
            untrusted_paths=untrusted_paths(out),
        )
    )


def _fail(
    outcome: CallOutcome, message: str, details: dict[str, object] | None = None
) -> ToolResult:
    return ToolResult(
        ok=False,
        outcome=outcome,
        error=ToolError(code=outcome, message=message, details=details or {}),
    )


def _jsonable(data: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = json.loads(json.dumps(data, default=repr))
    return result
