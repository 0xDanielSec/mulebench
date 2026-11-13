from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mulebench.agents import ScriptedAgent
from mulebench.harness import UnknownPreset
from mulebench.harness.workloads import run_workload, run_workloads, workload_key
from mulebench.workloads import (
    BUILTIN_WORKLOADS_DIR,
    WorkloadError,
    load_workloads,
    parse_workload,
)

EXPECTED_IDS = [
    "at-daily-limit",
    "first-payment-new-payee",
    "high-value",
    "legitimate-dispute",
    "read-only",
    "remember-refund-reference",
    "repeated-same-payee",
    "routine-known-payee",
    "several-bills",
]


def base() -> dict[str, object]:
    text = (BUILTIN_WORKLOADS_DIR / "routine-known-payee.yaml").read_text(encoding="utf-8")
    data: dict[str, object] = yaml.safe_load(text)
    return data


def errors(doc: dict[str, object]) -> str:
    with pytest.raises(WorkloadError) as info:
        parse_workload(yaml.safe_dump(doc, sort_keys=False))
    return "; ".join(info.value.errors)


def test_builtin_workloads_load() -> None:
    assert [w.id for w in load_workloads()] == EXPECTED_IDS


def test_unknown_key_rejected() -> None:
    doc = base()
    doc["injection"] = {"transaction": "x", "payload": "y"}
    assert "injection" in errors(doc)


def test_references_must_resolve() -> None:
    doc = base()
    doc["user_task"]["authorizations"][0]["from_account"] = "acc_ghost"  # type: ignore[index]
    assert "authorization auth_gym: unknown account 'acc_ghost'" in errors(doc)


def test_incoming_transactions_rejected() -> None:
    doc = base()
    doc["setup"]["transactions"] = [  # type: ignore[index]
        {
            "ref": "tx",
            "to_account": "acc_alice",
            "amount_cents": 1,
            "counterparty_name": "X",
            "counterparty_key": "x@example.test",
        }
    ]
    assert "no incoming payload carriers" in errors(doc)


def test_duplicate_workload_ids_rejected(tmp_path: Path) -> None:
    text = (BUILTIN_WORKLOADS_DIR / "read-only.yaml").read_text(encoding="utf-8")
    (tmp_path / "a.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(WorkloadError, match="duplicate workload id"):
        load_workloads(tmp_path)


def test_every_workload_completes_without_guards() -> None:
    trials = run_workloads(load_workloads(), ScriptedAgent(), ["none"])
    assert [t.workload_id for t in trials] == EXPECTED_IDS
    for t in trials:
        assert t.completed, t.workload_id
        assert not t.errored
        assert t.denied == []
        assert t.confirmations_requested == 0
        assert [i.id for i in t.invariants] == ["INV-1", "INV-2", "INV-3", "INV-4"]


def test_trial_records_denials_and_confirmations() -> None:
    (high,) = [w for w in load_workloads() if w.id == "high-value"]
    capped = run_workload(high, "only:session_spend_cap", ScriptedAgent())
    assert not capped.completed
    assert [(d.tool, d.guard, d.code) for d in capped.denied] == [
        ("transfer_pix", "session_spend_cap", "session_cap_exceeded")
    ]
    confirmed = run_workload(high, "only:human_confirmation", ScriptedAgent())
    assert confirmed.completed
    assert (confirmed.confirmations_requested, confirmed.confirmations_approved) == (1, 1)
    assert confirmed.trial_key == workload_key("high-value", "only:human_confirmation")


def test_unknown_preset_rejected_before_running() -> None:
    with pytest.raises(UnknownPreset):
        run_workloads(load_workloads(), ScriptedAgent(), ["nope"])


def test_memory_workload_may_seed_transactions_without_slots() -> None:
    doc = base()
    doc["memory"] = True
    tx = {
        "ref": "tx",
        "to_account": "acc_alice",
        "amount_cents": 1,
        "counterparty_name": "X",
        "counterparty_key": "x@example.test",
    }
    doc["setup"]["transactions"] = [tx]  # type: ignore[index]
    assert parse_workload(yaml.safe_dump(doc, sort_keys=False)).memory
    doc["setup"]["transactions"] = [{**tx, "description": "{{payload}}"}]  # type: ignore[index]
    assert "no {{payload}} slot" in errors(doc)
    doc["setup"]["transactions"] = [{**tx, "to_account": "acc_ghost"}]  # type: ignore[index]
    assert "transaction tx: unknown account 'acc_ghost'" in errors(doc)


def test_memory_tools_in_workload_need_memory_flag() -> None:
    doc = base()
    doc["expected_outcome"]["tool_calls"] = ["save_note"]  # type: ignore[index]
    assert "expected tool 'save_note' needs memory: true" in errors(doc)
