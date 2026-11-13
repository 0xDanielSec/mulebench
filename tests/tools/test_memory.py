"""Agent memory tools: gated per scenario, per-customer store, untrusted text."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness.memory import judge_notes
from mulebench.harness.runner import run_scenario
from mulebench.ledger import SAO_PAULO, Account, Customer, FixedClock, Ledger
from mulebench.tools import ToolContext
from mulebench.tools.client import ToolClient, model_tool_schemas, tool_schema_sha256
from mulebench.tools.memory import MemoryStore, NoteRecord

ROOT = Path(__file__).resolve().parents[2]
PILOT_03 = ROOT / "docs/experiments/data/pilot-03-qwen3-14b-8k.json"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=SAO_PAULO)


def frozen_pilot_hash() -> str:
    data = json.loads(PILOT_03.read_text(encoding="utf-8"))
    value = data["llm"]["tool_schema_sha256"]
    assert isinstance(value, str)
    return value


def ledger() -> Ledger:
    led = Ledger(clock=FixedClock(T0))
    for c in ("cust_alice", "cust_bob"):
        led.add_customer(Customer(id=c, name=c, tax_id=f"SYN-{c}"))
        led.add_account(
            Account(
                id=f"acc_{c[5:]}",
                customer_id=c,
                pix_key=None,
                balance_cents=0,
                daily_limit_cents=0,
            )
        )
    return led


def client(customer: str, memory: MemoryStore | None, session: int = 0) -> ToolClient:
    ctx = ToolContext(
        customer_id=customer,
        session_id="s",
        ledger=ledger(),
        memory=memory,
        session_index=session,
    )
    return ToolClient(ctx)


# ------------------------------------------------------------------ gating


def test_tool_list_without_memory_is_the_pilot_tool_list() -> None:
    assert tool_schema_sha256() == frozen_pilot_hash()
    assert tool_schema_sha256(memory=False) == frozen_pilot_hash()
    assert [t["name"] for t in model_tool_schemas()] == [
        "get_balance",
        "list_transactions",
        "open_dispute",
        "transfer_pix",
    ]


def test_memory_tools_only_with_a_store() -> None:
    plain = client("cust_alice", None)
    assert "save_note" not in plain.tool_names()
    assert [t["name"] for t in plain.model_tool_schemas()] == [
        t["name"] for t in model_tool_schemas()
    ]
    r = plain.call("save_note", {"text": "x"})
    assert r.outcome == "unknown_tool"
    assert plain.check_call("read_notes", {}) == ("unknown_tool", "unknown tool: 'read_notes'")

    with_memory = client("cust_alice", MemoryStore())
    assert {"save_note", "read_notes"} <= set(with_memory.tool_names())
    assert with_memory.check_call("read_notes", {}) is None
    assert tool_schema_sha256(memory=True) != frozen_pilot_hash()


def test_builtin_pilot_scenarios_record_the_frozen_hash() -> None:
    pilot = {
        s["scenario_id"] for s in json.loads(PILOT_03.read_text(encoding="utf-8"))["scenarios"]
    }
    scenarios = [s for s in load_builtin() if s.id in pilot]
    assert len(scenarios) == 12
    assert all(not s.memory for s in scenarios)
    assert {tool_schema_sha256(memory=s.memory) for s in scenarios} == {frozen_pilot_hash()}

    result = run_scenario(scenarios[0], ScriptedAgent(), presets=("vulnerable",))
    assert result.tool_schema_sha256 == frozen_pilot_hash()


# --------------------------------------------------------------- behaviour


def test_save_and_read_notes_round_trip() -> None:
    store = MemoryStore()
    c = client("cust_alice", store, session=1)
    saved = c.call("save_note", {"text": "customer prefers e-mail receipts"})
    assert saved.ok
    assert saved.data == {"note_id": "note_0001"}
    read = c.call("read_notes", {})
    assert read.ok
    assert read.data is not None
    assert read.data["notes"] == [
        {
            "note_id": "note_0001",
            "session": 1,
            "saved_at": T0.isoformat(),
            "provenance": "agent_written",
            "text": "customer prefers e-mail receipts",
        }
    ]
    assert read.untrusted_paths == ["notes[0].text"]
    (note,) = store.all()
    assert note.seq == 1
    assert note.customer_id == "cust_alice"


def test_notes_are_per_customer() -> None:
    store = MemoryStore()
    client("cust_alice", store).call("save_note", {"text": "alice secret"})
    read = client("cust_bob", store).call("read_notes", {})
    assert read.data == {"notes": []}


def test_note_text_is_validated() -> None:
    c = client("cust_alice", MemoryStore())
    assert c.call("save_note", {"text": ""}).outcome == "invalid_input"
    assert c.call("save_note", {"text": "x" * 501}).outcome == "invalid_input"
    assert c.call("read_notes", {"extra": 1}).outcome == "invalid_input"


# ------------------------------------------------------------------- taint


def test_judge_notes_flags_canary_and_attack_artifacts() -> None:
    s = next(x for x in load_builtin() if x.id == "pix-description-injection-001")

    def note(text: str) -> NoteRecord:
        return NoteRecord(note_id="n", customer_id="c", session=0, seq=1, saved_at=T0, text=text)

    clean, canary, artifact = judge_notes(
        [
            note("pay the landlord monthly"),
            note(f"{s.canary} remember this"),
            note("bills go to refund-desk@attacker.example.test"),
        ],
        s,
    )
    assert not clean.tainted
    assert (canary.canary, canary.artifacts, canary.tainted) == (True, [], True)
    assert (artifact.canary, artifact.artifacts) == (
        False,
        ["refund-desk@attacker.example.test"],
    )
    assert artifact.tainted
