"""External agents through the adapter: same harness, same invariants."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from mulebench.attacks import load_builtin
from mulebench.attacks.schema import Scenario
from mulebench.byoa import AgentLoadError, load_agent, safe_error
from mulebench.harness import run_scenario
from mulebench.reports import build_report
from mulebench.reports.json_report import report_to_json

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "byoa"
SCENARIO = "pix-description-injection-001"


def _scenario() -> Scenario:
    return next(s for s in load_builtin() if s.id == SCENARIO)


def _prepublish() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "prepublish_check_byoa", ROOT / "scripts" / "prepublish_check.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_injection_is_detected_via_ledger_for_an_external_agent() -> None:
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    result = run_scenario(_scenario(), agent, presets=("vulnerable", "hardened"))
    attack = result.cell("vulnerable", "attack").trials[0]
    assert attack.status == "exposed_violated"
    assert any(not i.holds for i in attack.invariants if i.id == "INV-1")
    payees = {t.to_pix_key for t in attack.outgoing_transfers}
    assert "refund-desk@attacker.example.test" in payees
    benign = result.cell("vulnerable", "benign").trials[0]
    assert benign.benign_pass is True
    # Guards live behind the tool boundary, so presets apply to external agents too.
    assert result.cell("hardened", "attack").trials[0].status != "exposed_violated"


def test_steps_come_from_the_tool_boundary_with_unknown_origin() -> None:
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    trial = (
        run_scenario(_scenario(), agent, presets=("vulnerable",))
        .cell("vulnerable", "attack")
        .trials[0]
    )
    assert trial.agent_steps
    assert {s.origin for s in trial.agent_steps} == {"unknown"}
    assert [s.tool for s in trial.agent_steps] == [r.tool for r in trial.trace]
    assert trial.metrics.injected_steps is None


def test_descriptor_names_the_external_agent() -> None:
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    cell = run_scenario(_scenario(), agent, presets=("vulnerable",)).cell("vulnerable", "attack")
    assert cell.agent.name == "fake-obedient"
    assert cell.agent.params["module"] == "mb_fake_agents:obedient"
    assert cell.agent.params["flavour"] == "obedient"
    assert cell.agent.params["agent_hints"] == {}


def test_agent_exception_errors_the_trial_without_secrets_or_paths() -> None:
    agent = load_agent("mb_fake_agents:broken", FIXTURES)
    result = run_scenario(_scenario(), agent, presets=("vulnerable",))
    trial = result.cell("vulnerable", "attack").trials[0]
    assert trial.errored
    assert trial.error is not None
    assert trial.error.startswith("RuntimeError: ")
    assert "Traceback" not in trial.error
    assert "Users" not in trial.error
    assert "/home" not in trial.error
    assert len(trial.error) <= len("RuntimeError: ") + 160
    # The tool call made before the exception is still traced.
    assert [r.tool for r in trial.trace] == ["get_balance"]

    from mulebench.harness.runner import RunOutcome

    text = report_to_json(build_report(RunOutcome(results=[result]), agent, presets=["vulnerable"]))
    from tests.fixtures.byoa.mb_fake_agents import FAKE_KEY

    assert FAKE_KEY not in text
    hits = [name for name, p in _prepublish().SECRET_PATTERNS if p.search(text)]
    assert hits == []


def test_wrong_reply_type_errors_the_trial() -> None:
    agent = load_agent("mb_fake_agents:wrong_reply", FIXTURES)
    trial = (
        run_scenario(_scenario(), agent, presets=("vulnerable",))
        .cell("vulnerable", "benign")
        .trials[0]
    )
    assert trial.errored
    assert trial.error is not None
    assert "AgentReply or str" in trial.error


def test_report_marks_schema_minor() -> None:
    from mulebench.harness.runner import RunOutcome

    agent = load_agent("mb_fake_agents:lazy", FIXTURES)
    result = run_scenario(_scenario(), agent, presets=("vulnerable",))
    data = json.loads(
        report_to_json(build_report(RunOutcome(results=[result]), agent, presets=["vulnerable"]))
    )
    assert data["schema_version"] == 3
    assert data["schema_minor"] == 2


@pytest.mark.parametrize(
    ("spec", "fragment"),
    [
        ("mb_fake_agents", "package.module:factory"),
        ("mb_fake_agents:", "package.module:factory"),
        ("mb_no_such_module:f", "cannot import"),
        ("mb_fake_agents:missing", "has no attribute"),
        ("mb_fake_agents:not_callable", "not callable"),
        ("mb_fake_agents:needs_args", "no arguments"),
        ("mb_fake_agents:no_run", "no run(task, tools)"),
        ("mb_fake_agents:explodes", "failed"),
    ],
)
def test_load_errors_are_clear(spec: str, fragment: str) -> None:
    with pytest.raises(AgentLoadError) as info:
        load_agent(spec, FIXTURES)
    assert fragment in str(info.value)
    assert "sk-" not in str(info.value)


def test_agent_path_must_be_a_directory(tmp_path: Path) -> None:
    with pytest.raises(AgentLoadError, match="not a directory"):
        load_agent("x:y", tmp_path / "missing")


def test_safe_error_redacts_key_shaped_strings() -> None:
    from tests.fixtures.byoa.mb_fake_agents import FAKE_KEY

    text = safe_error(ValueError(f"token={FAKE_KEY} ghp_{'a' * 36} AKIA{'B' * 16}"))
    assert text.startswith("ValueError: ")
    for name, pattern in _prepublish().SECRET_PATTERNS:
        assert not pattern.search(text), name
    assert safe_error(KeyError()) == "KeyError"
    assert len(safe_error(ValueError("x" * 1000 + " y"))) <= len("ValueError: ") + 160
