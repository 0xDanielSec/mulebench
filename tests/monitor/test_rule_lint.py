"""Tell lint: rules must not depend on scenario-specific tells."""

from __future__ import annotations

from pathlib import Path

import pytest

from mulebench.attacks import BUILTIN_SCENARIOS_DIR, load_builtin
from mulebench.cli import main
from mulebench.monitor.lint import lint_paths, lint_text, tells_from

ROOT = Path(__file__).resolve().parents[2]
RULE_DIRS = [ROOT / "docs" / "monitor-rules", ROOT / "docs" / "monitor-kql"]
TELLS = tells_from(load_builtin())


def kinds(text: str) -> set[str]:
    return {f.kind for f in lint_text(text, "rule.yml", TELLS)}


# ---------------------------------------------------------------- positive


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ('| where Text contains_cs "MB-CANARY-A14A"', "canary"),
        ("detection: {text|contains: MB-CANARY-NEW-ONE}", "canary"),  # by pattern
        ('| where tostring(Args.account_id) == "acc_bob"', "identifier"),
        ("selection: {args.to_pix_key: cust_alice}", "identifier"),
        ('| where Text contains_cs "pp_energy"', "identifier"),
        ('| where Text endswith "example.test"', "domain"),
        ("fire when the key is on attacker.example.test", "domain"),
        ("fire when the key host is attacker.lab-host", "domain"),
        ('| where Text contains_cs "include the balance of"', "payload"),
        ("correlation: text has 'IN EVERY   FUTURE answer'", "payload"),
        ("| where AmountCents == 45000", "amount"),
        ("text|contains: '450,00'", "amount"),
        ("| where Balance == 734512", "amount"),
    ],
)
def test_each_tell_class_is_rejected(text: str, kind: str) -> None:
    assert kind in kinds(text)


def test_finding_names_file_line_and_tell() -> None:
    (f,) = lint_text('ok line\n| where A == "acc_bob"\n', "x/r.kql", TELLS)
    assert (f.path, f.line, f.kind, f.tell) == ("x/r.kql", 2, "identifier", "acc_bob")


# ---------------------------------------------------------------- negative


@pytest.mark.parametrize(
    "text",
    [
        '| where Tool == "transfer_pix" and isnotempty(tostring(Args.authorization_id))',
        "let ReferenceCents = 100000;",
        "let ThresholdCents = 300000;",  # a parameter line, even if a scenario uses it
        "A foreign amount off by a factor of 10, 100 or 1000 appears",
        "written as 123.45, 123,45 or 12345",
        "Join tool_call.result.account_id to ledger.account.account.id",
        "references: [docs/monitor.md, docs/invariants.md]",
        "acc_bobby is a different token than any scenario id",
    ],
)
def test_generic_rule_text_passes(text: str) -> None:
    assert kinds(text) == set()


def test_every_committed_rule_passes() -> None:
    assert lint_paths(RULE_DIRS, TELLS) == []


def test_cli_passes_on_committed_rules_and_fails_on_a_tell(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["detect", "lint", *map(str, RULE_DIRS)]) == 0
    bad = tmp_path / "bad.yml"
    bad.write_text("detection: {text|contains: MB-CANARY-A14A}\n", encoding="utf-8")
    assert main(["detect", "lint", str(bad)]) == 1
    assert "canary: MB-CANARY-A14A" in capsys.readouterr().out
    assert main(["detect", "lint", str(tmp_path / "missing")]) == 2


# -------------------------------------------------------------- regression


def test_a_new_scenario_is_covered_without_editing_the_lint(tmp_path: Path) -> None:
    source = (BUILTIN_SCENARIOS_DIR / "memory-auto-persistent-exfiltration-014a.yaml").read_text(
        encoding="utf-8"
    )
    fresh = (
        source.replace("memory-auto-persistent-exfiltration-014a", "lint-regression-999")
        .replace("acc_bob", "acc_zeta_lint")
        .replace("bob@example.test", "zeta@lintlab.example.test")
        .replace("MB-CANARY-A14A", "MB-CANARY-L999")
        .replace("include the balance of", "quietly copy the ledger of")
    )
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    (scenarios / "lint-regression-999.yaml").write_text(fresh, encoding="utf-8")
    rule = tmp_path / "rule.kql"
    rule.write_text(
        '| where Args.account_id == "acc_zeta_lint"\n'
        '| where Text contains_cs "quietly copy the ledger"\n',
        encoding="utf-8",
    )
    assert main(["detect", "lint", str(rule)]) == 0  # unknown before the scenario exists
    assert main(["detect", "lint", str(rule), "--scenarios", str(scenarios)]) == 1
    from mulebench.attacks import load_all

    found = lint_paths([rule], tells_from([*load_builtin(), *load_all(scenarios)]))
    assert {f.kind for f in found} == {"identifier", "payload"}
