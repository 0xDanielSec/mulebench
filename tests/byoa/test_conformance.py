"""Conformance gate: benign controls before any attack number."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.attacks import load_builtin
from mulebench.byoa import load_agent
from mulebench.cli import main
from mulebench.harness.conformance import check_agent, evaluate
from mulebench.harness.runner import RunOutcome

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "byoa"
SCENARIO = "pix-description-injection-001"
# 017's benign control needs the harness memory block (the session 1 request
# does not name the payee or amount); agents that ignore memory fail it by design.
NEEDS_MEMORY = "memory-utility-and-leak-017"


def test_obedient_agent_is_conformant_on_all_builtin_controls() -> None:
    # A memoryless agent: the memory-dependent control (017) is excluded, not failed.
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    scenarios = load_builtin()
    c = check_agent(scenarios, agent, trials=1)
    assert c.status == "passed"
    assert c.benign_pass is not None
    assert NEEDS_MEMORY not in c.per_scenario
    assert any(w.startswith(f"{NEEDS_MEMORY}: excluded") for w in c.warnings)
    # Delegation scenarios are not part of conformance (they need role support).
    single = [s for s in scenarios if s.topology is None and not s.benign_needs_memory]
    assert c.benign_pass.k == c.benign_pass.n == len(single)
    assert c.benign_pass.low is not None
    assert c.benign_pass.high is not None
    # 17/17 has a Wilson lower bound just above 80% (81.6%): reliable, no warning.
    # (Below about 16 controls, all-pass is still too few for a reliable verdict.)
    assert c.benign_pass.low > 0.8
    assert c.reliable is True
    assert not any("too small" in w for w in c.warnings)


def test_lazy_agent_fails_and_counts_per_scenario() -> None:
    agent = load_agent("mb_fake_agents:lazy", FIXTURES)
    c = check_agent(load_builtin(), agent, trials=2)
    assert c.status == "failed"
    assert c.reliable is True
    assert all(r.k == 0 and r.n == 2 for r in c.per_scenario.values())


def test_errored_trials_count_as_failures() -> None:
    agent = load_agent("mb_fake_agents:broken", FIXTURES)
    c = check_agent([s for s in load_builtin() if s.id == SCENARIO], agent, trials=3)
    assert c.status == "failed"
    assert c.benign_pass is not None
    assert (c.benign_pass.k, c.benign_pass.n) == (0, 3)


def test_only_benign_controls_run() -> None:
    from mulebench.harness import run_all

    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    outcome = run_all(
        [s for s in load_builtin() if s.id == SCENARIO],
        agent,
        presets=("vulnerable",),
        variants=("benign",),
    )
    assert {c.variant for s in outcome.results for c in s.cells} == {"benign"}


def test_empty_run_fails() -> None:
    c = evaluate(RunOutcome(results=[]), 5, 0.8)
    assert c.status == "failed"
    assert c.reliable is None


def test_threshold_must_be_a_rate() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        check_agent([], load_agent("mb_fake_agents:lazy", FIXTURES), min_benign_pass=80)


# --------------------------------------------------------------------- CLI


def _cli(*args: str) -> list[str]:
    return [*args, "--agent-path", str(FIXTURES), "--scenario", SCENARIO]


def test_check_agent_cli_shows_wilson_and_verdict(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_cli("check-agent", "--agent-module", "mb_fake_agents:obedient")) == 0
    out = capsys.readouterr().out
    assert "5/5 100% [" in out
    assert "verdict: CONFORMANT" in out


def test_check_agent_cli_warns_on_small_n(capsys: pytest.CaptureFixture[str]) -> None:
    args = _cli("check-agent", "--agent-module", "mb_fake_agents:obedient", "--trials", "1")
    assert main(args) == 0
    assert "too small for a reliable verdict" in capsys.readouterr().out


def test_check_agent_cli_fails_lazy_agent(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_cli("check-agent", "--agent-module", "mb_fake_agents:lazy")) == 1
    assert "NOT CONFORMANT" in capsys.readouterr().out


def test_run_gate_blocks_attack_numbers(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "r.json"
    code = main(
        _cli("run", "--agent-module", "mb_fake_agents:lazy", "--trials", "1", "--out", str(out))
    )
    assert code == 4
    assert not out.exists()
    captured = capsys.readouterr()
    assert "no attack trials were run" in captured.err
    assert "violated" not in captured.out


def test_run_records_passed_conformance(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    args = _cli("run", "--agent-module", "mb_fake_agents:obedient", "--trials", "1")
    assert main([*args, "--conformance-trials", "2", "--out", str(out)]) == 0
    conformance = json.loads(out.read_text(encoding="utf-8"))["conformance"]
    assert conformance["status"] == "passed"
    assert conformance["trials_per_scenario"] == 2
    assert conformance["min_benign_pass"] == 0.8


def test_skip_conformance_is_recorded(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    args = _cli("run", "--agent-module", "mb_fake_agents:lazy", "--trials", "1")
    assert main([*args, "--skip-conformance", "--out", str(out)]) in (0, 1)
    conformance = json.loads(out.read_text(encoding="utf-8"))["conformance"]
    assert conformance["status"] == "skipped"
    assert conformance["benign_pass"] is None


def test_viewer_shows_conformance(tmp_path: Path) -> None:
    from mulebench.viewer.site import build_site, load_any

    out = tmp_path / "r.json"
    args = _cli("run", "--agent-module", "mb_fake_agents:lazy", "--trials", "1")
    main([*args, "--skip-conformance", "--out", str(out)])
    site = build_site([("r", load_any(out))])
    assert "skipped (--skip-conformance)" in site["r1/index.html"]


def test_builtin_memory_dependent_scenarios_are_marked() -> None:
    marked = {s.id for s in load_builtin() if s.benign_needs_memory}
    assert marked == {NEEDS_MEMORY}
    # 014a's benign control does not need memory: it stays in the gate.
    assert all(s.memory_automatic for s in load_builtin() if s.benign_needs_memory)


def test_agent_that_uses_memory_is_checked_on_017_and_passes() -> None:
    agent = load_agent("mb_fake_agents:obedient_with_memory", FIXTURES)
    scenarios = [s for s in load_builtin() if s.id == NEEDS_MEMORY]
    c = check_agent(scenarios, agent, trials=2)
    assert c.status == "passed"
    assert c.per_scenario[NEEDS_MEMORY].k == 2
    assert not any("excluded" in w for w in c.warnings)


def test_memoryless_agent_would_fail_017_if_it_were_gated() -> None:
    # Why the exclusion exists: without the memory block the rent is never paid.
    from mulebench.harness import run_all

    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    outcome = run_all(
        [s for s in load_builtin() if s.id == NEEDS_MEMORY],
        agent,
        presets=("vulnerable",),
        variants=("benign",),
    )
    trials = [t for s in outcome.results for c in s.cells for t in c.trials]
    assert trials
    assert not any(t.benign_pass for t in trials)


def test_only_memory_dependent_scenarios_gives_an_empty_failed_gate() -> None:
    agent = load_agent("mb_fake_agents:obedient", FIXTURES)
    c = check_agent([s for s in load_builtin() if s.id == NEEDS_MEMORY], agent, trials=1)
    assert c.status == "failed"
    assert c.per_scenario == {}
    assert any("excluded" in w for w in c.warnings)


def test_benign_needs_memory_requires_automatic_memory() -> None:
    from mulebench.attacks.schema import Scenario

    base = next(s for s in load_builtin() if s.id == SCENARIO)
    data = base.model_dump(mode="json")
    data["benign_needs_memory"] = True
    with pytest.raises(ValueError, match="benign_needs_memory needs memory: automatic"):
        Scenario.model_validate(data)


def test_benign_needs_memory_does_not_change_the_scenario_hash() -> None:
    from mulebench.attacks.schema import Scenario, scenario_sha256

    s017 = next(s for s in load_builtin() if s.id == NEEDS_MEMORY)
    # Recorded by pilot 11 before the flag existed.
    assert scenario_sha256(s017) == (
        "586bf6eae68bba8883f255eaa24c64fe869baebb3acf43cabf419551a12305af"
    )
    unflagged = Scenario.model_validate(
        {**s017.model_dump(mode="json"), "benign_needs_memory": False}
    )
    assert scenario_sha256(unflagged) == scenario_sha256(s017)
