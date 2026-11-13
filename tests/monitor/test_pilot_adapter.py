from __future__ import annotations

from typing import Any

import pytest

from mulebench.agents import ScriptedAgent
from mulebench.attacks import Scenario, load_builtin, render
from mulebench.harness import run_scenario
from mulebench.harness.seed import seed_cell
from mulebench.monitor.adapters.pilot import adapt_report, seed_snapshot
from mulebench.monitor.alerts import Alert
from mulebench.monitor.engine import constant_config, run_batch

SCENARIOS = load_builtin()
BY_ID = {s.id: s for s in SCENARIOS}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
@pytest.mark.parametrize("variant", ["attack", "benign"])
def test_seed_replay_matches_harness_seeding(scenario: Scenario, variant: str) -> None:
    rendered = render(scenario, variant)  # type: ignore[arg-type]
    ledger, _clock, _note = seed_cell(scenario, rendered)
    try:
        expected = ledger.snapshot()
    finally:
        ledger.close()
    assert seed_snapshot(rendered.setup, scenario) == expected


def alert_key(a: Alert) -> tuple[str, tuple[object, ...]]:
    if a.evidence.transfer_ids:
        return a.code, tuple(a.evidence.transfer_ids)
    return a.code, tuple(a.evidence.call_seq)


def stored_key(v: dict[str, Any]) -> tuple[str, tuple[object, ...]]:
    tids = list(v["transfer_ids"]) or ([v["transfer_id"]] if v["transfer_id"] else [])
    if tids:
        return v["code"], tuple(sorted(tids))
    return v["code"], (v["call_seq"],)


@pytest.fixture(scope="module")
def scripted_report() -> dict[str, Any]:
    results = [run_scenario(s, ScriptedAgent()).model_dump(mode="json") for s in SCENARIOS]
    return {"scenarios": results}


def test_monitor_reproduces_stored_invariants_and_disclosure(
    scripted_report: dict[str, Any],
) -> None:
    adapted = adapt_report(scripted_report, BY_ID)
    assert adapted.skipped == []
    assert len(adapted.trials) == sum(
        len(c["trials"]) for s in scripted_report["scenarios"] for c in s["cells"]
    )
    violated = 0
    for t in adapted.trials:
        assert t.scenario_verified
        alerts = run_batch(t.events, constant_config(t.config))
        for inv in t.stored_invariants:
            mine = [a for a in alerts if a.family == inv["id"]]
            assert sorted(map(alert_key, mine)) == sorted(map(stored_key, inv["violations"])), (
                t.session_id,
                inv["id"],
            )
            assert all(a.applicable == inv["applicable"] for a in mine)
            violated += bool(mine)
        d = t.stored_disclosure
        if d is not None:
            for sink, verdict in d["sinks"].items():
                fired = {a.rule_id for a in alerts if a.family == "DISCLOSURE"}
                assert (f"MB-DISC-exact-{sink}" in fired) == verdict["disclosed"], t.session_id
                assert (f"MB-DISC-approx-{sink}" in fired) == verdict["approximate"]
        assert not [a for a in alerts if a.family == "MONITOR"], t.session_id
    assert violated > 0  # the scripted vulnerable agent breaks something


def test_changed_scenario_is_skipped(scripted_report: dict[str, Any]) -> None:
    first = dict(scripted_report["scenarios"][0], scenario_sha256="0" * 64)
    adapted = adapt_report({"scenarios": [first]}, BY_ID)
    assert adapted.trials == []
    assert adapted.skipped == [(first["scenario_id"], "scenario changed since the report")]


def test_report_without_hash_is_converted_unverified(scripted_report: dict[str, Any]) -> None:
    first = dict(scripted_report["scenarios"][0])
    first.pop("scenario_sha256", None)
    adapted = adapt_report({"scenarios": [first]}, BY_ID)
    assert adapted.trials
    assert not any(t.scenario_verified for t in adapted.trials)


def test_unknown_scenario_is_skipped() -> None:
    adapted = adapt_report({"scenarios": [{"scenario_id": "nope", "cells": []}]}, BY_ID)
    assert adapted.skipped == [("nope", "scenario not found")]


def test_cli_adapt_writes_one_trace_per_trial(
    scripted_report: dict[str, Any], tmp_path: pytest.TempPathFactory
) -> None:
    import json
    from pathlib import Path

    from mulebench.cli import main

    root = Path(str(tmp_path))
    first = scripted_report["scenarios"][0]
    (root / "r.json").write_text(json.dumps({"scenarios": [first]}), encoding="utf-8")
    assert main(["monitor", "adapt", str(root / "r.json"), "--out", str(root / "out")]) == 0
    traces = sorted((root / "out").glob("*.jsonl"))
    assert len(traces) == sum(len(c["trials"]) for c in first["cells"])
    assert main(["monitor", "run", "--in", str(traces[0]), "--out", str(root / "a.jsonl")]) in (
        0,
        1,
    )
