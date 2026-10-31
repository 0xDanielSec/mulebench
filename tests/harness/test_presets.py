from __future__ import annotations

import pytest

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.cli import main
from mulebench.harness import (
    GUARD_NAMES,
    UnknownPreset,
    ablation_presets,
    build_guard_set,
    preset_guard_names,
    run_all,
)
from mulebench.tools import AlwaysApprove, UntrustedContentMarking, marking_nonce


def test_named_presets() -> None:
    assert preset_guard_names("vulnerable") == ()
    assert preset_guard_names("hardened") == (
        "account_ownership",
        "require_authorization",
        "human_confirmation",
    )
    assert preset_guard_names("strict") == GUARD_NAMES
    assert preset_guard_names("all") == GUARD_NAMES
    assert preset_guard_names("none") == ()


def test_generated_presets_keep_canonical_order() -> None:
    assert preset_guard_names("only:velocity") == ("velocity",)
    minus = preset_guard_names("all-minus:velocity")
    assert minus == tuple(g for g in GUARD_NAMES if g != "velocity")


def test_ablation_presets_cover_every_set_once() -> None:
    names = ablation_presets()
    assert len(names) == 2 + 2 * len(GUARD_NAMES)
    assert len(set(names)) == len(names)
    assert names[0] == "none"
    assert names[-1] == "all"


@pytest.mark.parametrize("bad", ["", "paranoid", "only:", "only:nope", "all-minus:nope"])
def test_unknown_preset(bad: str) -> None:
    with pytest.raises(UnknownPreset):
        preset_guard_names(bad)


def test_hardened_guard_set_matches_previous_composition() -> None:
    gs = build_guard_set("hardened", AlwaysApprove(), "k")
    assert [g.name for g in gs.guards] == [
        "account_ownership",
        "require_authorization",
        "human_confirmation",
    ]
    assert gs.transformers == ()


def test_marking_nonce_comes_from_trial_key() -> None:
    gs = build_guard_set("only:untrusted_content_marking", AlwaysApprove(), "trial/a")
    assert gs.guards == ()
    (marking,) = gs.transformers
    assert isinstance(marking, UntrustedContentMarking)
    assert marking.nonce == marking_nonce("trial/a")


def test_run_all_rejects_unknown_preset_before_running() -> None:
    with pytest.raises(UnknownPreset):
        run_all(load_builtin(), ScriptedAgent(), presets=["hardened", "nope"])


def test_run_all_with_strict_preset() -> None:
    results = run_all(load_builtin(), ScriptedAgent(), presets=["strict"]).results
    for s in results:
        assert {c.preset for c in s.cells} == {"strict"}
        assert s.cell("strict", "attack").trials[0].status == "exposed_resisted"
        assert s.cell("strict", "benign").trials[0].utility_exact is True


def test_cli_preset_option(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--preset", "strict", "--preset", "only:velocity"]) in (0, 1)
    out = capsys.readouterr().out
    assert "strict" in out
    assert "only:velocity" in out


def test_cli_unknown_preset(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--preset", "nope"]) == 2
    assert "unknown preset" in capsys.readouterr().err
