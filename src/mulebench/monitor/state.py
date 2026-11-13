"""Monitor state: ledger view and per-session evidence built from events.

Ledger events upsert by id. A transfer belongs to the session its event
names, else to the session with an ok `transfer_pix` call whose result has
the same `transfer_id`. `apply` returns the sessions whose verdicts the event
can change, which the streaming engine re-evaluates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from mulebench.invariants import CallEvidence, ConfirmationEvidence
from mulebench.invariants.authorization import in_scope
from mulebench.ledger import Account, Authorization, LedgerSnapshot, Transfer
from mulebench.monitor.events import (
    Confirmation,
    CustomerMessage,
    Event,
    FinalAnswer,
    Handoff,
    LedgerAccount,
    LedgerAuthorization,
    LedgerTransfer,
    SessionEnd,
    SessionStart,
    ToolCall,
)


@dataclass
class SessionState:
    session_id: str
    customer_id: str | None = None
    calls: dict[int, ToolCall] = field(default_factory=dict)
    confirmations: dict[int, Confirmation] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)
    final_text: str | None = None
    handoffs: list[Handoff] = field(default_factory=list)
    ended: bool = False
    last_ts: datetime | None = None

    def touch(self, ts: datetime) -> None:
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts

    def ordered_calls(self) -> list[ToolCall]:
        return [self.calls[s] for s in sorted(self.calls)]

    def call_evidence(self) -> tuple[CallEvidence, ...]:
        return tuple(
            CallEvidence(seq=c.seq, tool=c.tool, outcome=c.outcome, args=c.args, result=c.result)
            for c in self.ordered_calls()
        )

    def confirmation_evidence(self) -> tuple[ConfirmationEvidence, ...]:
        """Same conversion as the harness: wrong-typed arguments become None,
        which matches no transfer (fail closed)."""

        def text(value: object) -> str | None:
            return value if isinstance(value, str) else None

        def cents(value: object) -> int | None:
            return value if isinstance(value, int) and not isinstance(value, bool) else None

        return tuple(
            ConfirmationEvidence(
                seq=c.seq,
                ts=c.ts,
                customer_id=c.customer_id,
                from_account_id=text(c.args.get("from_account_id")),
                to_pix_key=text(c.args.get("to_pix_key")),
                amount_cents=cents(c.args.get("amount_cents")),
                approved=c.approved,
            )
            for c in (self.confirmations[s] for s in sorted(self.confirmations))
            if c.tool == "transfer_pix"
        )


class MonitorState:
    def __init__(self) -> None:
        self.accounts: dict[str, Account] = {}
        self.authorizations: dict[str, Authorization] = {}
        self.transfers: dict[str, Transfer] = {}
        self.transfer_ts: dict[str, datetime] = {}
        self.explicit_session: dict[str, str] = {}
        self.call_link: dict[str, str] = {}  # transfer id -> session, via ok call result
        self.sessions: dict[str, SessionState] = {}
        self.max_ts: datetime | None = None

    # ------------------------------------------------------------ apply

    def session(self, session_id: str) -> SessionState:
        s = self.sessions.get(session_id)
        if s is None:
            s = self.sessions[session_id] = SessionState(session_id)
        return s

    def apply(self, e: Event) -> set[str]:
        if self.max_ts is None or e.ts > self.max_ts:
            self.max_ts = e.ts
        if isinstance(e, LedgerAccount):
            self.accounts[e.account.id] = e.account
            return set(self.sessions)
        if isinstance(e, LedgerAuthorization):
            self.authorizations[e.authorization.id] = e.authorization
            return set(self.sessions)
        if isinstance(e, LedgerTransfer):
            t = e.transfer
            self.transfers[t.id] = t
            self.transfer_ts[t.id] = e.ts
            if e.session_id is not None:
                self.explicit_session[t.id] = e.session_id
                self.session(e.session_id).touch(e.ts)
            return self._sessions_touching(t)
        s = self.session(e.session_id)
        s.touch(e.ts)
        if isinstance(e, SessionStart):
            s.customer_id = e.customer_id
        elif isinstance(e, ToolCall):
            s.calls[e.seq] = e
            tid = linked_transfer_id(e)
            if tid is not None:
                self.call_link.setdefault(tid, e.session_id)
                linked = self.transfers.get(tid)
                if linked is not None:
                    return {e.session_id} | self._sessions_touching(linked)
        elif isinstance(e, Confirmation):
            s.confirmations[e.seq] = e
        elif isinstance(e, CustomerMessage):
            s.messages.append(e.text)
        elif isinstance(e, FinalAnswer):
            s.final_text = e.text
        elif isinstance(e, Handoff):
            s.handoffs.append(e)
        elif isinstance(e, SessionEnd):
            s.ended = True
        return {e.session_id}

    def _sessions_touching(self, t: Transfer) -> set[str]:
        """The transfer's session, plus sessions owning agent transfers from the
        same account (INV-3 daily totals and structuring span sessions)."""
        out: set[str] = set()
        own = self.session_of(t.id)
        if own is not None:
            out.add(own)
        if t.from_account_id is not None:
            for other in self.transfers.values():
                if other.from_account_id == t.from_account_id:
                    sid = self.session_of(other.id)
                    if sid is not None:
                        out.add(sid)
        return out

    # ------------------------------------------------------------ views

    def session_of(self, transfer_id: str) -> str | None:
        return self.explicit_session.get(transfer_id) or self.call_link.get(transfer_id)

    def session_transfers(self, session_id: str) -> set[str]:
        return {tid for tid in self.transfers if self.session_of(tid) == session_id}

    def orphan_transfers(self) -> list[Transfer]:
        return sorted(
            (t for t in self.transfers.values() if in_scope(t) and self.session_of(t.id) is None),
            key=lambda t: (t.created_at, t.id),
        )

    def snapshot(self) -> LedgerSnapshot:
        return LedgerSnapshot(
            accounts=tuple(self.accounts[k] for k in sorted(self.accounts)),
            transfers=tuple(sorted(self.transfers.values(), key=lambda t: (t.created_at, t.id))),
            authorizations=tuple(self.authorizations[k] for k in sorted(self.authorizations)),
        )


def linked_transfer_id(call: ToolCall) -> str | None:
    if call.tool != "transfer_pix" or call.outcome != "ok" or call.result is None:
        return None
    tid = call.result.get("transfer_id")
    return tid if isinstance(tid, str) else None
