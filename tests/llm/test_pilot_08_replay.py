"""Pilot 08 replays offline from the committed cassette archive (no key, no network).

For each model, scenarios 012 and 014a (attack and benign, first 3 trials) are
replayed with the frozen pilot 08 settings and compared trial by trial with the
committed report. 014a also proves that the default `--extractor-context none`
sends the memory extraction requests of pilot 08 byte for byte.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mulebench.cli import main

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "docs" / "experiments" / "data"
SCENARIOS = (
    "pix-description-read-before-pay-key-swap-012",
    "memory-auto-persistent-exfiltration-014a",
)
TRIALS = 3
MODELS = {
    "qwen3-14b": ("qwen/qwen3-14b", "DeepInfra", "fp8"),
    "gpt-oss-20b": ("openai/gpt-oss-20b", "DekaLLM", "bf16"),
    "gemma-4-26b": ("google/gemma-4-26b-a4b-it", "DeepInfra", "fp8"),
    "mistral-small-3.2": ("mistralai/mistral-small-3.2-24b-instruct", "DeepInfra", "fp8"),
}
COMPARED = (
    "status",
    "errored",
    "error",
    "payload_exposed",
    "utility_exact",
    "attribution",
    "agent_steps",
    "final_text",
    "ledger_after",
    "outgoing_transfers",
    "unauthorized_outflow_cents",
    "seed",
)


@pytest.fixture(scope="module")
def cassettes(tmp_path_factory: pytest.TempPathFactory) -> Path:
    spec = importlib.util.spec_from_file_location(
        "cassette_archive_for_replay", ROOT / "scripts" / "cassette_archive.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    dest = tmp_path_factory.mktemp("cassettes")
    assert module.extract(dest=dest, prefix="pilot-08-") == 1915
    return dest


def trials_by_key(report: Any) -> dict[str, dict[str, Any]]:
    """Every trial record in a report, by trial key."""
    out: dict[str, dict[str, Any]] = {}
    stack = [report]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "trial_key" in node and "attribution" in node:
                out[node["trial_key"]] = node
            else:
                stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("name", sorted(MODELS))
def test_pilot_08_replays_offline_and_matches_the_committed_report(
    name: str, scenario: str, cassettes: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    monkeypatch.delenv("MB_OPENROUTER_API_KEY", raising=False)
    model, host, quant = MODELS[name]
    out = tmp_path / "replay.json"
    code = main(
        [
            "run", "--builtin", "--scenario", scenario,
            "--agent", "llm", "--provider", "openrouter", "--model", model,
            "--openrouter-host", host, "--openrouter-quantization", quant, "--allow-remote",
            "--preset", "vulnerable", "--prompt-variants", "baseline",
            "--trials", str(TRIALS), "--temperature", "0.7", "--seed", "7000",
            "--max-tokens", "4096", "--arg-coercion", "digit_strings",
            "--max-cost-usd", "1.00",
            "--cassettes", str(cassettes / f"pilot-08-{name}"), "--out", str(out),
        ]
    )  # fmt: skip
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["llm"]["extractor_context"] == "none"
    replayed = trials_by_key(report)
    committed = trials_by_key(
        json.loads((DATA / f"pilot-08-{name}.json").read_text(encoding="utf-8"))
    )
    assert len(replayed) == 2 * TRIALS
    for key, trial in replayed.items():
        for field in COMPARED:
            assert trial[field] == committed[key][field], (name, key, field)
