"""Delegation roles: tool scoping, trace role, per-role schema hash, and the
Payer-only payee allowlist."""

from __future__ import annotations

from mulebench.attacks import load_builtin
from mulebench.attacks.schema import PAYER_TOOLS, READER_TOOLS
from mulebench.ledger import Ledger
from mulebench.tools import PayerPayeeAllowlist, ToolContext, call_tool
from mulebench.tools.client import ToolClient, model_tool_schemas, tool_schema_sha256
from tests.tools.test_memory import frozen_pilot_hash

READER = frozenset(READER_TOOLS)
PAYER = frozenset(PAYER_TOOLS)
PAY = {"from_account_id": "acc_alice", "to_pix_key": "mule@example.test", "amount_cents": 100}


def ctx(
    ledger: Ledger,
    role: str | None,
    allowed: frozenset[str] | None,
    payees: frozenset[str] | None = None,
) -> ToolContext:
    return ToolContext(
        customer_id="cust_alice",
        session_id="s1",
        ledger=ledger,
        guards=(PayerPayeeAllowlist(),),
        role=role,
        allowed_tools=allowed,
        note_payees=payees,
    )


def test_reader_cannot_pay_and_denial_is_traced(ledger: Ledger) -> None:
    c = ctx(ledger, "reader", READER)
    before = len(ledger.snapshot().transfers)
    r = call_tool(c, "transfer_pix", PAY)
    assert (r.ok, r.outcome) == (False, "denied")
    assert r.error is not None
    assert r.error.message == "denied: role_scope"
    rec = c.trace.records()[-1]
    assert rec.role == "reader"
    assert rec.guard_decisions[-1].code == "role_scope"
    assert len(ledger.snapshot().transfers) == before


def test_payer_cannot_read(ledger: Ledger) -> None:
    c = ctx(ledger, "payer", PAYER)
    assert call_tool(c, "get_balance", {"account_id": "acc_alice"}).outcome == "denied"
    assert call_tool(c, "list_transactions", {"account_id": "acc_alice"}).outcome == "denied"


def test_client_lists_only_role_tools(ledger: Ledger) -> None:
    reader = ToolClient(ctx(ledger, "reader", READER))
    assert reader.tool_names() == ["get_balance", "list_transactions"]
    assert [t["name"] for t in reader.model_tool_schemas()] == reader.tool_names()
    kind, _ = reader.check_call("transfer_pix", PAY) or ("", "")
    assert kind == "unknown_tool"
    payer = ToolClient(ctx(ledger, "payer", PAYER))
    assert payer.tool_names() == ["open_dispute", "transfer_pix"]


def test_role_hashes_differ_and_unscoped_hash_is_the_pilot_hash() -> None:
    assert tool_schema_sha256() == frozen_pilot_hash()
    reader, payer = tool_schema_sha256(tools=READER), tool_schema_sha256(tools=PAYER)
    assert len({reader, payer, frozen_pilot_hash()}) == 3
    assert [t["name"] for t in model_tool_schemas(tools=READER)] == sorted(READER)


def test_single_agent_scenarios_keep_their_tool_schema_hash() -> None:
    # 001-014 have no topology: their hash is the one recorded before delegation.
    single = [s for s in load_builtin() if s.topology is None]
    assert len(single) >= 14
    assert {tool_schema_sha256(memory=False) for s in single if not s.memory} == {
        frozen_pilot_hash()
    }


def test_trace_role_is_none_outside_delegation(ledger: Ledger) -> None:
    c = ctx(ledger, None, None)
    call_tool(c, "get_balance", {"account_id": "acc_alice"})
    assert c.trace.records()[-1].role is None


# ------------------------------------------------------------ payee allowlist


def test_allowlist_refuses_payee_absent_from_payer_note(ledger: Ledger) -> None:
    c = ctx(ledger, "payer", PAYER, frozenset({"energy@example.test"}))
    r = call_tool(c, "transfer_pix", PAY)
    assert r.outcome == "denied"
    d = c.trace.records()[-1].guard_decisions[-1]
    assert (d.guard, d.code) == ("payer_payee_allowlist", "payee_not_in_session_note")


def test_allowlist_accepts_note_payee(ledger: Ledger) -> None:
    c = ctx(ledger, "payer", PAYER, frozenset({"mule@example.test"}))
    call_tool(c, "transfer_pix", PAY)
    d = c.trace.records()[-1].guard_decisions[-1]
    assert d.allowed


def test_allowlist_ignores_other_roles_and_single_agent_runs(ledger: Ledger) -> None:
    for role in (None, "reader"):
        c = ctx(ledger, role, None, frozenset())
        call_tool(c, "transfer_pix", PAY)
        assert c.trace.records()[-1].guard_decisions[-1].allowed
