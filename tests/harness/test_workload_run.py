"""`mulebench workloads`: N trials per (workload, prompt, preset), resumable."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from anthropic.types import TextBlock

from mulebench.agents import ScriptedAgent
from mulebench.agents.llm.transport import FakeTransport
from mulebench.cli import main
from mulebench.harness.runner import describe_agent
from mulebench.harness.workload_run import WorkloadCheckpoint, fingerprint, run_workload_matrix
from mulebench.harness.workloads import workload_key
from mulebench.workloads import load_workloads
from tests.llm.test_llm_agent import agent as llm_agent
from tests.llm.test_llm_agent import msg, use

WID = "delegation-first-payment-new-payee"


def test_scripted_key_format_is_unchanged() -> None:
    assert workload_key("x", "vulnerable") == "workload/x/vulnerable/t000"
    assert workload_key("x", "vulnerable", 7, "baseline") == "workload/x/baseline/vulnerable/t007"


def test_cli_runs_trials_per_preset_and_removes_checkpoint(tmp_path: Path) -> None:
    out = tmp_path / "w.json"
    code = main(
        [
            "workloads",
            "--workload",
            WID,
            "--preset",
            "vulnerable",
            "--preset",
            "only:provenance_bound_handoff",
            "--trials",
            "2",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["kind"] == "workload-run"
    assert report["run_status"] == "complete"
    got = [(t["guard_set"], t["trial"], t["completed"]) for t in report["trials"]]
    assert got == [
        ("vulnerable", 0, True),
        ("vulnerable", 1, True),
        ("only:provenance_bound_handoff", 0, False),
        ("only:provenance_bound_handoff", 1, False),
    ]
    assert not (tmp_path / "w.json.checkpoint.jsonl").exists()


def test_unknown_workload_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["workloads", "--workload", "nope", "--out", "x.json"]) == 2
    assert "unknown workload" in capsys.readouterr().err


def test_resume_skips_finished_trials(tmp_path: Path) -> None:
    (w,) = [x for x in load_workloads() if x.id == WID]
    agent = ScriptedAgent()
    fp = fingerprint({"k": 1}, [w])
    path = tmp_path / "c.jsonl"
    cp = WorkloadCheckpoint.open(path, fp, resume=False)
    first = run_workload_matrix(
        [w],
        agent,
        describe_agent(agent, {}),
        prompt_variants=["none"],
        presets=["vulnerable"],
        trials=1,
        on_trial=cp.write,
    )
    cp.close()
    cp = WorkloadCheckpoint.open(path, fp, resume=True)
    calls: list[str] = []
    second = run_workload_matrix(
        [w],
        agent,
        describe_agent(agent, {}),
        prompt_variants=["none"],
        presets=["vulnerable"],
        trials=2,
        completed=cp.completed,
        on_trial=lambda t: calls.append(t.trial_key),
    )
    cp.close()
    assert calls == [workload_key(WID, "vulnerable", 1)]
    assert second.trials[0] == first.trials[0]
    with pytest.raises(ValueError, match="different configuration"):
        WorkloadCheckpoint.open(path, fingerprint({"k": 2}, [w]), resume=True)
    with pytest.raises(ValueError, match="exists"):
        WorkloadCheckpoint.open(path, fp, resume=False)


def _text(value: str) -> dict[str, Any]:
    return msg(TextBlock(type="text", text=value, citations=None), stop="end_turn")


def test_llm_workload_trials_use_distinct_keys_per_role_and_trial() -> None:
    (w,) = [x for x in load_workloads() if x.id == WID]
    pay = use(
        1,
        "transfer_pix",
        from_account_id="acc_alice",
        to_pix_key="newshop@example.test",
        amount_cents=25000,
        authorization_id="auth_0008",
    )
    handoff = "PAY payee=newshop@example.test amount_cents=25000 bill_ref=newshop-1"
    fake = FakeTransport([_text(handoff), msg(pay), _text("Paid.")] * 2)
    agent = llm_agent(fake)
    report = run_workload_matrix(
        [w],
        agent,
        describe_agent(agent, {}),
        prompt_variants=["baseline"],
        presets=["vulnerable"],
        trials=2,
    )
    keys = [k for k, _ in fake.requests]
    assert keys == [
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t000#reader",
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t000#payer",
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t000#payer",
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t001#reader",
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t001#payer",
        "workload/delegation-first-payment-new-payee/baseline/vulnerable/t001#payer",
    ]
    assert [t.prompt_variant for t in report.trials] == ["baseline", "baseline"]
    assert all(len(t.model_calls) == 3 for t in report.trials)
    assert [t.completed for t in report.trials] == [True, True]
