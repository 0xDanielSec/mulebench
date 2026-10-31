from __future__ import annotations

from mulebench.ledger import Ledger
from mulebench.tools import ResultTransformer, ToolContext, call_tool
from tests.tools.test_tools import INJECTED, seed_injection


class Upper:
    """Test transformer: upper-cases every untrusted field it is pointed at."""

    name = "upper"

    def __init__(self) -> None:
        self.seen_paths: list[str] = []

    def transform(
        self, ctx: ToolContext, tool: str, data: dict[str, object], untrusted_paths: list[str]
    ) -> dict[str, object]:
        self.seen_paths = untrusted_paths
        txs = data["transactions"]
        assert isinstance(txs, list)
        for tx in txs:
            tx["description"] = str(tx["description"]).upper()
        return data


class Suffix:
    name = "suffix"

    def transform(
        self, ctx: ToolContext, tool: str, data: dict[str, object], untrusted_paths: list[str]
    ) -> dict[str, object]:
        txs = data["transactions"]
        assert isinstance(txs, list)
        for tx in txs:
            tx["description"] = str(tx["description"]) + "!"
        return data


def ctx_with(ledger: Ledger, *transformers: ResultTransformer) -> ToolContext:
    return ToolContext(
        customer_id="cust_alice", session_id="s1", ledger=ledger, transformers=transformers
    )


def test_agent_sees_transformed_trace_keeps_original(ledger: Ledger) -> None:
    seed_injection(ledger)
    upper = Upper()
    ctx = ctx_with(ledger, upper)
    res = call_tool(ctx, "list_transactions", {"account_id": "acc_alice"})
    assert res.data is not None
    shown = res.data["transactions"]
    assert isinstance(shown, list)
    assert shown[0]["description"] == INJECTED.upper()
    rec = ctx.trace.records()[-1]
    assert rec.result is not None
    assert rec.agent_result == res.data
    original = rec.result["transactions"]
    assert isinstance(original, list)
    assert original[0]["description"] == INJECTED
    assert upper.seen_paths == res.untrusted_paths == rec.untrusted_paths


def test_transformers_chain_in_order(ledger: Ledger) -> None:
    seed_injection(ledger)
    res = call_tool(
        ctx_with(ledger, Upper(), Suffix()), "list_transactions", {"account_id": "acc_alice"}
    )
    assert res.data is not None
    shown = res.data["transactions"]
    assert isinstance(shown, list)
    assert shown[0]["description"] == INJECTED.upper() + "!"


def test_no_transformer_or_no_change_leaves_agent_result_none(ledger: Ledger) -> None:
    seed_injection(ledger)
    ctx = ctx_with(ledger)
    res = call_tool(ctx, "list_transactions", {"account_id": "acc_alice"})
    rec = ctx.trace.records()[-1]
    assert rec.agent_result is None
    assert rec.result == res.data


def test_failed_calls_are_not_transformed(ledger: Ledger) -> None:
    ctx = ctx_with(ledger, Upper())
    res = call_tool(ctx, "get_balance", {"account_id": "acc_nope"})
    assert not res.ok
    assert ctx.trace.records()[-1].agent_result is None
