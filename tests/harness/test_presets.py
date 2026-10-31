from __future__ import annotations

import pytest
from pydantic import ValidationError

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.cli import main
from mulebench.harness import (
    GUARD_NAMES,
    GuardParams,
    InvalidGuardParams,
    UnknownPreset,
    ablation_presets,
    build_guard_set,
    parse_preset,
    preset_guard_names,
    run_all,
)
from mulebench.harness.confirmer import RecordingConfirmer
from mulebench.ledger import FixedClock
from mulebench.tools import (
    AlwaysApprove,
    AlwaysDeny,
    ConfirmationRequest,
    SessionSpendCap,
    TraceRecorder,
    UntrustedContentMarking,
    marking_nonce,
)
from tests.conftest import T0


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


# ------------------------------------------------- INV-4 wiring (plain data)


def test_enforced_confirmation_threshold_per_guard_set() -> None:
    def enforced(name: str) -> int | None:
        return build_guard_set(name, AlwaysApprove(), "k").enforced_confirmation_cents

    assert enforced("vulnerable") is None
    assert enforced("hardened") == 100_000
    assert enforced("strict") == 100_000
    assert enforced("only:new_payee") is None  # asks only for new payees
    assert enforced("only:velocity") is None  # asks only for repeated payments
    assert enforced("all-minus:human_confirmation") is None


def test_recording_confirmer_writes_customer_answers() -> None:
    clock = FixedClock(T0)
    trace = TraceRecorder()
    confirmer = RecordingConfirmer(AlwaysDeny(), trace, clock)
    request = ConfirmationRequest(
        session_id="s1", customer_id="cust_alice", tool="transfer_pix", args={"amount_cents": 1}
    )
    assert confirmer.confirm(request) is False
    (rec,) = trace.confirmations()
    assert (rec.seq, rec.ts, rec.approved, rec.args) == (1, T0, False, {"amount_cents": 1})
    assert trace.records() == ()


def test_inv4_counts_only_where_confirmation_is_enforced() -> None:
    s001 = next(s for s in load_builtin() if s.id == "pix-description-injection-001")
    presets = ["vulnerable", "hardened", "all-minus:require_authorization"]
    res = run_all([s001], ScriptedAgent(), presets=presets).results[0]
    for preset in presets:
        for variant in ("attack", "benign"):
            trial = res.cell(preset, variant).trials[0]
            inv4 = next(i for i in trial.invariants if i.id == "INV-4")
            assert inv4.applicable is (preset != "vulnerable"), (preset, variant)
            assert inv4.holds is (preset != "vulnerable"), (preset, variant)
            if variant == "benign":
                assert trial.benign_pass is True
                approved = [c for c in trial.confirmations if c.approved]
                assert (len(approved) == 0) is (preset == "vulnerable")
    # Without RequireAuthorization the customer is asked about the attacker
    # payment, declines, and INV-4 sees no unconfirmed transfer.
    attack = res.cell("all-minus:require_authorization", "attack").trials[0]
    assert attack.status == "exposed_resisted"
    assert any(not c.approved for c in attack.confirmations)


# ------------------------------------------------------------ GuardParams


def test_parse_preset_without_params() -> None:
    assert parse_preset("hardened") == ("hardened", GuardParams())
    assert GuardParams().suffix() == ""


def test_parse_cap_param_roundtrips() -> None:
    name = "only:session_spend_cap@session_spend_cap=50000"
    base, params = parse_preset(name)
    assert (base, params.session_spend_cap) == ("only:session_spend_cap", 50_000)
    assert base + params.suffix() == name
    assert preset_guard_names(name) == ("session_spend_cap",)


def test_cap_param_reaches_the_guard() -> None:
    gs = build_guard_set("all@session_spend_cap=50000", AlwaysApprove(), "k")
    (cap,) = [g for g in gs.guards if g.name == "session_spend_cap"]
    assert isinstance(cap, SessionSpendCap)
    assert cap.cap_cents == 50_000
    (default,) = [
        g
        for g in build_guard_set("all", AlwaysApprove(), "k").guards
        if g.name == "session_spend_cap"
    ]
    assert isinstance(default, SessionSpendCap)
    assert default.cap_cents == 200_000


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("all@velocity_reference=1", "velocity_reference"),  # unknown parameter
        ("all@session_spend_cap=0", "greater than 0"),
        ("all@session_spend_cap=-5", "positive integer"),
        ("all@session_spend_cap=1.5", "positive integer"),
        ("all@session_spend_cap", "expected <param>=<value>"),
        ("all@session_spend_cap=1@session_spend_cap=2", "repeated"),
        ("only:velocity@session_spend_cap=1", "not installed"),
        ("none@session_spend_cap=1", "not installed"),
    ],
)
def test_invalid_guard_params_rejected(name: str, reason: str) -> None:
    with pytest.raises(InvalidGuardParams, match=reason):
        parse_preset(name)
    with pytest.raises(UnknownPreset):
        preset_guard_names(name)


def test_unknown_base_with_params_is_unknown_preset() -> None:
    with pytest.raises(UnknownPreset, match="unknown preset"):
        parse_preset("paranoid@session_spend_cap=1")


def test_guard_params_type_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        GuardParams.model_validate({"cap": 1})


def test_cli_accepts_param_suffix(capsys: pytest.CaptureFixture[str]) -> None:
    name = "only:session_spend_cap@session_spend_cap=50000"
    assert main(["run", "--preset", name]) in (0, 1)
    assert name in capsys.readouterr().out
    assert main(["run", "--preset", "all@nope=1"]) == 2
