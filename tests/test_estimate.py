"""`mulebench estimate`: token basis from committed reports and the price table. Offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mulebench.agents.llm.pricing_file import load_price_table
from mulebench.cli import main
from mulebench.estimate import EstimateError, estimate, token_basis

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "experiments" / "data"
TABLE = """
as_of = "2026-11-16"
source = "synthetic"

[[price]]
model = "m/a"
host = "H1"
input_per_mtok = 1.0
output_per_mtok = 2.0

[[price]]
model = "m/a"
host = "TBD"
input_per_mtok = 3.0
output_per_mtok = 4.0
"""


def tiny_report(tmp_path: Path) -> Path:
    def trial(tin: int, tout: int, errored: bool = False) -> dict[str, object]:
        usage = {"input_tokens": tin, "output_tokens": tout}
        return {"errored": errored, "usage": usage}

    cells = [
        {
            "preset": "vulnerable",
            "prompt_variant": "baseline",
            "variant": "attack",
            "trials": [trial(1000, 100), trial(3000, 300), trial(9, 9, errored=True)],
        },
        {
            "preset": "vulnerable",
            "prompt_variant": "baseline",
            "variant": "benign",
            "trials": [trial(500, 50)],
        },
        {
            "preset": "hardened",
            "prompt_variant": "baseline",
            "variant": "attack",
            "trials": [trial(10**6, 10**6)],
        },
    ]
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"scenarios": [{"scenario_id": "s1", "cells": cells}]}))
    return path


def test_basis_uses_vulnerable_baseline_non_errored_trials(tmp_path: Path) -> None:
    attack, benign = token_basis(["s1"], [tiny_report(tmp_path)])
    assert (attack.input_per_trial, attack.output_per_trial, attack.trials) == (2000, 200, 2)
    assert (benign.input_per_trial, benign.output_per_trial) == (500, 50)
    with pytest.raises(EstimateError, match="s2"):
        token_basis(["s2"], [tiny_report(tmp_path)])


def test_estimate_uses_pinned_host_or_highest_price(tmp_path: Path) -> None:
    (tmp_path / "p.toml").write_text(TABLE, encoding="utf-8")
    table = load_price_table(tmp_path / "p.toml")
    basis = token_basis(["s1"], [tiny_report(tmp_path)])
    (pinned,) = estimate(["m/a"], basis, table, trials=10, hosts={"m/a": "H1"})
    assert pinned.input_tokens == 25_000
    assert pinned.output_tokens == 2_500
    assert pinned.cost_usd == pytest.approx((25_000 * 1.0 + 2_500 * 2.0) / 1e6)
    (unpinned,) = estimate(["m/a"], basis, table, trials=10)
    assert unpinned.price.input_per_mtok == 3.0
    with pytest.raises(EstimateError, match="m/b"):
        estimate(["m/b"], basis, table, trials=10)


PILOT_08 = [
    "pix-description-cross-customer-read-004",
    "dispute-flow-foreign-read-009",
    "pix-description-read-before-pay-key-swap-012",
    "delegation-payment-instruction-amount-015b",
    "memory-auto-persistent-exfiltration-014a",
]


def test_committed_reports_give_the_pilot_08_basis() -> None:
    reports = [DATA / f"pilot-0{n}-qwen3-14b-8k.json" for n in (3, 6, 7)]
    basis = token_basis(PILOT_08, reports)
    sources = {b.scenario_id: b.source for b in basis}
    assert sources[PILOT_08[0]] == "pilot-03-qwen3-14b-8k.json"
    assert sources[PILOT_08[3]] == "pilot-06-qwen3-14b-8k.json"
    assert sources[PILOT_08[4]] == "pilot-07-qwen3-14b-8k.json"
    assert all(b.trials == 30 for b in basis)


def test_cli_prints_per_model_and_total(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    args = ["estimate", "--model", "qwen/qwen3-14b", "--trials", "30"]
    for sid in PILOT_08:
        args += ["--scenario", sid]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "qwen/qwen3-14b: in 0.92M" in out
    assert "total with safety factor: $" in out
    assert main([*args, "--host", "bad"]) == 2
    assert "MODEL=HOST" in capsys.readouterr().err
