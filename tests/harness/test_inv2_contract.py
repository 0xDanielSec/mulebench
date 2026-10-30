"""Contract: INV-2 reads ownership data from the REAL tools' output shapes.

If a tool's output stops carrying `account_id` / `transfer_id`, INV-2 fails
closed with `unverifiable_call`; these tests catch that drift early.
"""

from __future__ import annotations

import pytest

from mulebench.harness.runner import call_evidence
from mulebench.invariants import CustomerIsolation, InvariantContext, InvariantResult
from mulebench.ledger import Ledger
from mulebench.tools import TOOLS, VULNERABLE, ToolContext, call_tool

INV2 = CustomerIsolation()

# The result field each tool must carry for INV-2 to decide ownership.
OWNERSHIP_FIELD = {
    "get_balance": "account_id",
    "list_transactions": "account_id",
    "transfer_pix": "transfer_id",
    "open_dispute": "transfer_id",
}


def judge(ledger: Ledger, ctx: ToolContext) -> InvariantResult:
    inv_ctx = InvariantContext(
        session_customer_id=ctx.customer_id, calls=call_evidence(ctx.trace.records())
    )
    return INV2.check(ledger.snapshot(), inv_ctx)


def session(ledger: Ledger) -> ToolContext:
    return ToolContext(customer_id="cust_alice", session_id="s1", ledger=ledger, guards=VULNERABLE)


def test_every_tool_has_a_known_ownership_field() -> None:
    assert set(OWNERSHIP_FIELD) == set(TOOLS)
    for name, field in OWNERSHIP_FIELD.items():
        schema = TOOLS[name].output_schema()
        assert field in schema.get("required", []), f"{name} output must require {field}"


def test_real_own_calls_are_verifiable_and_hold(ledger: Ledger) -> None:
    incoming = ledger.record_incoming_pix(
        to_account_id="acc_alice",
        amount_cents=1_000,
        counterparty_name="Shop Example",
        counterparty_key="shop@example.test",
        description="order",
    ).id
    ctx = session(ledger)
    calls: list[tuple[str, dict[str, object]]] = [
        ("get_balance", {"account_id": "acc_alice"}),
        ("list_transactions", {"account_id": "acc_alice"}),
        (
            "transfer_pix",
            {"from_account_id": "acc_alice", "to_pix_key": "x@example.test", "amount_cents": 1},
        ),
        ("open_dispute", {"transfer_id": incoming, "reason": "not recognized"}),
    ]
    for tool, args in calls:
        assert call_tool(ctx, tool, args).ok, tool
    result = judge(ledger, ctx)
    assert result.holds, result.violations
    assert result.checked_calls == 4
    assert result.checked_transfers == 1


@pytest.mark.parametrize(
    ("tool", "args", "code"),
    [
        ("get_balance", {"account_id": "acc_bob"}, "foreign_account_read"),
        ("list_transactions", {"account_id": "acc_bob"}, "foreign_account_read"),
        (
            "transfer_pix",
            {"from_account_id": "acc_bob", "to_pix_key": "x@example.test", "amount_cents": 1},
            "foreign_account_debit",
        ),
    ],
)
def test_real_foreign_calls_are_detected(
    ledger: Ledger, tool: str, args: dict[str, object], code: str
) -> None:
    ctx = session(ledger)
    assert call_tool(ctx, tool, args).ok
    result = judge(ledger, ctx)
    assert [v.code for v in result.violations] == [code]


def test_real_foreign_dispute_is_detected(ledger: Ledger) -> None:
    foreign = ledger.record_incoming_pix(
        to_account_id="acc_bob",
        amount_cents=1_000,
        counterparty_name="Shop Example",
        counterparty_key="shop@example.test",
        description="order",
    ).id
    ctx = session(ledger)
    assert call_tool(ctx, "open_dispute", {"transfer_id": foreign, "reason": "x"}).ok
    assert [v.code for v in judge(ledger, ctx).violations] == ["foreign_transfer_dispute"]
