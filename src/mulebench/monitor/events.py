"""Trace events: the documented JSONL input of the monitor (format v1).

One JSON object per line. Every event has `v` (format version), `type` and
`ts` (RFC 3339 with an offset). Session events carry `session_id`; ledger
events describe ledger state and belong to no session. A ledger snapshot is
the same `ledger.*` events at the start of the stream; a later event with the
same id replaces the earlier one (upsert).

The batch engine does not depend on line order; the streaming engine tolerates
lateness up to its grace period. `tool_call.result` is the tool's real output,
not what the agent may have seen after a transformer. `final_answer.text` is
read for disclosure only and never copied into alerts.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter

from mulebench.ledger import Account, Authorization, Transfer

FORMAT_VERSION = 1


class _Event(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: Literal[1] = 1
    ts: AwareDatetime


class _SessionEvent(_Event):
    session_id: str = Field(min_length=1)


class SessionStart(_SessionEvent):
    """Opens a session for an authenticated customer."""

    type: Literal["session_start"] = "session_start"
    customer_id: str = Field(min_length=1)


class ToolCall(_SessionEvent):
    """One tool call. `seq` orders calls within the session and is shared with
    confirmations."""

    type: Literal["tool_call"] = "tool_call"
    seq: int = Field(ge=1)
    tool: str = Field(min_length=1)
    args: dict[str, object] = {}
    outcome: str = Field(min_length=1)  # "ok", "denied", "error", ...
    result: dict[str, object] | None = None


class Confirmation(_SessionEvent):
    """A customer's answer, through the customer channel, to a confirmation
    request for `tool` with `args`."""

    type: Literal["confirmation"] = "confirmation"
    seq: int = Field(ge=1)
    customer_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: dict[str, object] = {}
    approved: bool


class CustomerMessage(_SessionEvent):
    """A message from the customer. Amounts in it are visible to the customer
    and never count as disclosed."""

    type: Literal["customer_message"] = "customer_message"
    text: str


class FinalAnswer(_SessionEvent):
    """The agent's final answer to the customer."""

    type: Literal["final_answer"] = "final_answer"
    text: str


class Handoff(_SessionEvent):
    """A message from one agent to another in a delegation (Reader -> Payer).
    Agent-written: it may carry content injected into what the Reader read.
    `seq` is the seq of the last tool call before the handoff (0 if none), so
    calls with a higher seq came after it."""

    type: Literal["handoff"] = "handoff"
    seq: int = Field(ge=0)
    text: str


class MemoryContext(_SessionEvent):
    """Memory the application put into the session's context, outside any
    tool call (harness-managed automatic memory). It may hold text extracted
    from earlier tool output, so it is untrusted."""

    type: Literal["memory_context"] = "memory_context"
    text: str


class MemoryWrite(_SessionEvent):
    """One entry the application's memory extractor wrote for the session
    (harness-managed automatic memory), before any later session reads it.
    This is where a poisoned memory is decided. `seq` is the seq of the last
    tool call of the session before the write (0 if none). `source` names what
    the extractor read (e.g. "conversation"), when known. The text is
    extractor-written and may carry injected content."""

    type: Literal["memory_write"] = "memory_write"
    seq: int = Field(ge=0)
    text: str
    source: str | None = None


class SessionEnd(_SessionEvent):
    type: Literal["session_end"] = "session_end"


class LedgerAccount(_Event):
    type: Literal["ledger.account"] = "ledger.account"
    account: Account


class LedgerAuthorization(_Event):
    type: Literal["ledger.authorization"] = "ledger.authorization"
    authorization: Authorization


class LedgerTransfer(_Event):
    """A transfer as booked. `session_id` names the session that initiated it,
    when the ledger knows; otherwise the monitor links it through an ok
    `transfer_pix` call whose result has the same `transfer_id`."""

    type: Literal["ledger.transfer"] = "ledger.transfer"
    transfer: Transfer
    session_id: str | None = None


SessionEventT = (
    SessionStart
    | ToolCall
    | Confirmation
    | CustomerMessage
    | FinalAnswer
    | Handoff
    | MemoryContext
    | MemoryWrite
    | SessionEnd
)
LedgerEventT = LedgerAccount | LedgerAuthorization | LedgerTransfer
Event = Annotated[SessionEventT | LedgerEventT, Field(discriminator="type")]
EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)


def trace_json_schema() -> dict[str, object]:
    schema = EVENT_ADAPTER.json_schema()
    schema["title"] = f"mulebench monitor trace event (format v{FORMAT_VERSION})"
    return schema
