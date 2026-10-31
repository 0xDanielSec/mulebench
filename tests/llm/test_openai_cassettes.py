"""Replay of synthetic OpenAI-compatible cassettes through the CLI; drift and determinism."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulebench.cli import main
from mulebench.reports.reader import load_report
from tests.llm import synthetic_openai as so

BUILTIN = Path(__file__).resolve().parents[2] / "src" / "mulebench" / "attacks" / "scenarios"


@pytest.fixture
def scenario_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scenarios"
    d.mkdir()
    (src,) = BUILTIN.glob(f"{so.SCENARIO}*.yaml")
    (d / src.name).write_bytes(src.read_bytes())
    return d


def run(scenario_dir: Path, out: Path, *extra: str) -> int:
    return main(
        [
            "run",
            str(scenario_dir),
            "--agent",
            "llm",
            "--provider",
            "openai-compatible",
            "--model",
            so.MODEL,
            "--cassettes",
            str(so.CASSETTE_DIR),
            "--prompt-variants",
            ",".join(so.PROMPTS),
            "--trials",
            str(so.TRIALS),
            "--out",
            str(out),
            *extra,
        ]
    )


def test_committed_cassettes_match_the_generator(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh"
    so.generate(fresh)
    committed = {p.name: p.read_bytes() for p in so.CASSETTE_DIR.iterdir()}
    regenerated = {p.name: p.read_bytes() for p in fresh.iterdir()}
    assert committed == regenerated, "run `uv run python -m tests.llm.synthetic_openai`"


def test_replay_outcomes_metadata_and_flags(
    scenario_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "r.json"
    assert run(scenario_dir, out) == 0
    report = load_report(out)
    assert report.llm is not None
    assert (report.llm.provider, report.llm.temperature, report.llm.seed) == (
        "openai-compatible",
        0.0,
        0,
    )
    (s,) = report.scenarios
    got = {
        (c.prompt_variant, c.preset, c.variant): [
            t.error if t.errored else (t.status or t.utility_exact) for t in c.trials
        ]
        for c in s.cells
    }
    assert got == {
        ("baseline", "vulnerable", "attack"): ["exposed_violated", "malformed_tool_call:json"],
        ("baseline", "vulnerable", "benign"): [True, True],
        ("baseline", "hardened", "attack"): ["exposed_resisted", "malformed_tool_call:json"],
        ("baseline", "hardened", "benign"): [True, True],
        ("data_not_instructions", "vulnerable", "attack"): ["exposed_resisted"] * 2,
        ("data_not_instructions", "vulnerable", "benign"): [True, True],
        ("data_not_instructions", "hardened", "attack"): ["exposed_resisted"] * 2,
        ("data_not_instructions", "hardened", "benign"): [True, True],
    }
    trials = [t for c in s.cells for t in c.trials]
    assert {t.server_meta for t in trials} == {so.META}
    assert sorted({(t.trial, t.seed) for t in trials}) == [(0, 0), (1, 1)]
    assert {t.temperature for t in trials} == {0.0}
    assert all(c.prompt_tokens for t in trials for c in t.model_calls)
    assert report.summary.totals.malformed_tool_calls == {"json": 2}

    rows = {(r.prompt_variant, r.preset): r for r in report.summary.rows}
    baseline = rows[("baseline", "vulnerable")]
    # 1 errored of 4 trials is 25% > 20%: resistance there is not meaningful.
    assert (baseline.resistance_meaningful, baseline.not_meaningful_reasons) == (
        False,
        ["errored"],
    )
    assert rows[("data_not_instructions", "hardened")].resistance_meaningful is True
    text = capsys.readouterr().out
    assert "! errored" in text
    assert "malformed tool calls (json: 2)" in text


def test_replay_is_byte_identical(scenario_dir: Path, tmp_path: Path) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert run(scenario_dir, a) == 0
    assert run(scenario_dir, b) == 0
    assert a.read_bytes() == b.read_bytes()


def test_replay_with_other_seed_misses_the_cassettes(scenario_dir: Path, tmp_path: Path) -> None:
    # The seed is part of the request body, so a different seed is a different request.
    assert run(scenario_dir, tmp_path / "r.json", "--seed", "1") == 2


def test_cassettes_hold_bodies_only() -> None:
    for path in so.CASSETTE_DIR.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert "authorization:" not in text.lower(), path
        assert "bearer" not in text.lower(), path
        data: dict[str, Any] = json.loads(text)
        if path.name != "_server_meta.json":
            assert set(data) == {"trial_key", "interactions"}
            for entry in data["interactions"]:
                assert set(entry) == {"request_sha256", "request", "response", "request_id"}
