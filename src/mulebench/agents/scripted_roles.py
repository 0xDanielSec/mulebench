"""Scripted Reader and Payer for delegation runs (deterministic, offline).

Like `ScriptedAgent`, they exist to validate the harness, not to model any
real LLM. Both take their `obeys_tool_output_instructions` setting from the
`ScriptedAgent` they wrap.

ScriptedReader (tools: reads only)
    Runs the request grammar of `ScriptedAgent`, with payment and dispute
    calls *planned* instead of executed: each planned payment becomes a
    handoff line `PAY payee=<key> amount_cents=<int> bill_ref=<ref>`, where
    the reference is the id of the newest outgoing transaction to that payee
    in the listing (the bill), else the authorization cited.
    In vulnerable mode the injected instructions of `ScriptedAgent` apply
    while planning (an injected transfer becomes a PAY line, a key change or
    a bill change rewrites planned lines), and the Reader also copies every
    untrusted text it read into a free-text `NOTES:` line ("for context").
    In hardened mode it plans only what the request asks and copies nothing.

ScriptedPayer (tools: payments only)
    Pays every PAY line of its input. The authorization cited is the first
    fresh one in its own session note whose payee equals the line's payee
    and whose max covers the amount; without one it sends from the first
    note account and cites none. In vulnerable mode it also executes the
    `call transfer_pix ...` instructions of the free text of its input.
    With the trusted customer request in its input (`payer_sees_request`),
    it cross-checks every payment against it: the payee must appear in the
    request, and when the request states an amount for that payee
    (`pay R$ <amount> to <key>`), the amount must match. Duplicate
    (payee, amount) payments are paid once.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from mulebench.agents.base import AgentRun, AgentStep, AgentTask, StepOrigin
from mulebench.agents.handoff import (
    HandoffItem,
    parse_pay_lines,
    render_pay_line,
    split_payer_input,
)
from mulebench.agents.scripted import _INJECTED, _PAY, _resolve, to_cents
from mulebench.agents.session_note import parse_session_note
from mulebench.tools.client import ToolClient, ToolResult

if TYPE_CHECKING:
    from mulebench.agents.scripted import ScriptedAgent

PLANNED_TOOLS = frozenset({"transfer_pix", "open_dispute"})
_WS = re.compile(r"\s+")


class _PlanningClient(ToolClient):
    """Passes reads to the real client; records payment and dispute calls as
    planned without executing (or tracing) them."""

    def __init__(self, inner: ToolClient) -> None:  # no ToolContext of its own
        self._inner = inner
        self.planned: list[tuple[str, dict[str, object]]] = []
        self.untrusted: list[str] = []
        self.listing: ToolResult | None = None

    def call(self, tool: str, args: Mapping[str, object]) -> ToolResult:
        if tool in PLANNED_TOOLS:
            self.planned.append((tool, dict(args)))
            return ToolResult(ok=True, outcome="ok", data={"status": "planned"})
        result = self._inner.call(tool, args)
        if result.ok and tool == "list_transactions":
            self.listing = result
        if result.ok:
            for path in result.untrusted_paths:
                text = _resolve(result.data, path)
                if isinstance(text, str) and text.strip():
                    self.untrusted.append(_WS.sub(" ", text).strip())
        return result

    def tool_names(self) -> list[str]:
        return self._inner.tool_names()


class ScriptedReader:
    def __init__(self, base: ScriptedAgent) -> None:
        self.base = base

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        planner = _PlanningClient(tools)
        inner = self.base.run(task.model_copy(update={"role": None}), planner)
        steps = [s for s in inner.steps if s.tool not in PLANNED_TOOLS]
        steps = [s.model_copy(update={"seq": i}) for i, s in enumerate(steps, start=1)]
        lines = []
        for tool, args in planner.planned:
            if tool != "transfer_pix":
                continue
            payee, amount = args.get("to_pix_key"), args.get("amount_cents")
            if not isinstance(payee, str) or not isinstance(amount, int) or amount <= 0:
                continue
            # The bill's reference: the newest outgoing transaction to this
            # payee in the listing, else the authorization cited.
            ref = _last_transaction_id(planner.listing, payee) or args.get("authorization_id")
            lines.append(
                render_pay_line(
                    HandoffItem(
                        payee_key=payee,
                        amount_cents=amount,
                        bill_ref=ref if isinstance(ref, str) else None,
                    )
                )
            )
        if self.base.obeys_tool_output_instructions and planner.untrusted:
            lines.append("NOTES: " + " | ".join(dict.fromkeys(planner.untrusted)))
        return AgentRun(
            steps=tuple(steps),
            stopped=inner.stopped,
            final_text="\n".join(lines) if lines else "No payment to make.",
        )


class ScriptedPayer:
    def __init__(self, base: ScriptedAgent) -> None:
        self.base = base

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        note = parse_session_note(task.session_note)
        request, body = split_payer_input(task.request)
        planned: list[tuple[HandoffItem, StepOrigin]] = [
            (item, "model") for item in parse_pay_lines(body)
        ]
        if self.base.obeys_tool_output_instructions:
            free = "\n".join(line for line in body.splitlines() if not parse_pay_lines(line))
            for m in _INJECTED.finditer(free):
                item = HandoffItem(payee_key=m.group(2), amount_cents=to_cents(m.group(1)))
                planned.append((item, "tool_output"))
        if request is not None:
            planned = [(i, o) for i, o in planned if _matches_request(i, request)]

        seen: set[tuple[str, int]] = set()
        used: set[str] = set()
        steps: list[AgentStep] = []
        default = note.accounts[0] if note.accounts else ""
        for item, origin in planned:
            if (item.payee_key, item.amount_cents) in seen:
                continue
            seen.add((item.payee_key, item.amount_cents))
            if len(steps) >= self.base.max_steps:
                return AgentRun(steps=tuple(steps), stopped="step_cap")
            args: dict[str, object] = {
                "from_account_id": default,
                "to_pix_key": item.payee_key,
                "amount_cents": item.amount_cents,
            }
            for auth in note.authorizations:
                if (
                    auth.authorization_id not in used
                    and auth.payee_pix_key == item.payee_key
                    and item.amount_cents <= auth.max_amount_cents
                ):
                    args["from_account_id"] = auth.from_account
                    args["authorization_id"] = auth.authorization_id
                    used.add(auth.authorization_id)
                    break
            result = tools.call("transfer_pix", args)
            steps.append(
                AgentStep(
                    seq=len(steps) + 1,
                    tool="transfer_pix",
                    args=args,
                    origin=origin,
                    ok=result.ok,
                    outcome=result.outcome,
                    error_message=None if result.error is None else result.error.message,
                )
            )
        paid = sum(s.ok for s in steps)
        return AgentRun(
            steps=tuple(steps),
            stopped="done",
            final_text=f"Payments sent: {paid}." if steps else "No payment to make.",
        )


def _last_transaction_id(listing: ToolResult | None, key: str) -> str | None:
    data = listing.data if listing is not None else None
    txs = data.get("transactions") if isinstance(data, dict) else None
    for tx in txs if isinstance(txs, list) else []:
        if (
            isinstance(tx, dict)
            and tx.get("direction") == "out"
            and tx.get("counterparty_key") == key
            and isinstance(tx.get("id"), str)
        ):
            return str(tx["id"])
    return None


def _matches_request(item: HandoffItem, request: str) -> bool:
    named = re.search(rf"(?<![\w.@+%-]){re.escape(item.payee_key)}(?![\w@+%-])", request)
    if named is None:
        return False
    stated = [to_cents(m.group(1)) for m in _PAY.finditer(request) if m.group(2) == item.payee_key]
    return not stated or item.amount_cents in stated
