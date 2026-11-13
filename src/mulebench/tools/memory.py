"""Agent memory: free-text notes the agent writes and reads back later.

Notes live in a store owned by the harness, keyed per customer, never in the
ledger. Every note is agent-written: its provenance says so, and `read_notes`
marks the text untrusted, because an agent may have copied it from untrusted
tool output. Whether it did (taint) is judged by the harness, not here.

The memory tools exist only in a session whose `ToolContext.memory` is set
(scenarios with `memory: true`); otherwise they are unknown tools and absent
from the tool list models see.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from mulebench.tools.schemas import (
    NoteOut,
    ReadNotesIn,
    ReadNotesOut,
    SaveNoteIn,
    SaveNoteOut,
)

if TYPE_CHECKING:
    from mulebench.tools.context import ToolContext

Provenance = Literal["agent_written"]


class NoteRecord(BaseModel):
    """A stored note. `seq` is the trace seq of the save_note call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    note_id: str
    customer_id: str
    session: int
    seq: int
    saved_at: datetime
    text: str
    provenance: Provenance = "agent_written"


class MemoryStore:
    """Append-only notes per customer. A customer only ever reads their own."""

    def __init__(self) -> None:
        self._notes: list[NoteRecord] = []

    def save(
        self, *, customer_id: str, session: int, seq: int, saved_at: datetime, text: str
    ) -> NoteRecord:
        note = NoteRecord(
            note_id=f"note_{len(self._notes) + 1:04d}",
            customer_id=customer_id,
            session=session,
            seq=seq,
            saved_at=saved_at,
            text=text,
        )
        self._notes.append(note)
        return note

    def notes(self, customer_id: str) -> tuple[NoteRecord, ...]:
        return tuple(n for n in self._notes if n.customer_id == customer_id)

    def all(self) -> tuple[NoteRecord, ...]:
        return tuple(self._notes)


def _store(ctx: ToolContext) -> MemoryStore:
    if ctx.memory is None:  # pragma: no cover - registry hides the tools
        raise RuntimeError("memory tools called without a memory store")
    return ctx.memory


def save_note(ctx: ToolContext, args: SaveNoteIn) -> SaveNoteOut:
    note = _store(ctx).save(
        customer_id=ctx.customer_id,
        session=ctx.session_index,
        seq=len(ctx.trace.records()) + 1,
        saved_at=ctx.ledger.clock.now(),
        text=args.text,
    )
    return SaveNoteOut(note_id=note.note_id)


def read_notes(ctx: ToolContext, args: ReadNotesIn) -> ReadNotesOut:
    return ReadNotesOut(
        notes=[
            NoteOut(
                note_id=n.note_id,
                session=n.session,
                saved_at=n.saved_at,
                provenance=n.provenance,
                text=n.text,
            )
            for n in _store(ctx).notes(ctx.customer_id)
        ]
    )
