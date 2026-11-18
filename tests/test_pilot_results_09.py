"""Pilot 09 renderer on offline synthetic OpenRouter runs, and its "Not run." state."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.openrouter import OpenRouterChatModel
from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import fixed_pricer
from mulebench.agents.llm.transport import TransportResponse
from mulebench.agents.memory_extraction import ExtractorContext
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import LLMConfig
from mulebench.reports import build_report

ROOT = Path(__file__).resolve().parent.parent
SCENARIO = "memory-auto-persistent-exfiltration-014a"
HOST = "SyntheticHost"
MODEL = "google/gemma-4-26b-a4b-it"
DOC = "docs/experiments/pilot-09-extractor-context.md"


@pytest.fixture(scope="module")
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pilot_results", ROOT / "scripts" / "pilot_results.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pilot_results"] = module
    spec.loader.exec_module(module)
    return module


class Synthetic:
    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        text = "- Customer likes short answers" if "#mem" in trial_key else "ok"
        body = {
            "id": "gen",
            "model": MODEL,
            "provider": HOST,
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": text}}
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "cost": 0.00001},
        }
        return TransportResponse(body=body, request_id="gen")


def synthetic_report(tmp_path: Path, context: ExtractorContext) -> Path:
    scenarios = [s for s in load_builtin() if s.id == SCENARIO]
    agent = LLMAgent(
        OpenRouterChatModel(Synthetic(), HOST, "fp8"),
        model=MODEL,
        effort="none",
        meter=CostMeter(1.0),
        temperature=0.7,
        seed=9000,
        extractor_context=context,
        pricer=fixed_pricer(Price(input_per_mtok=1, output_per_mtok=2, cache_read_per_mtok=0)),
    )
    outcome = run_all(
        scenarios, agent, prompt_variants=("baseline",), trials=2, presets=("vulnerable",)
    )
    llm = LLMConfig(
        provider="openrouter",
        model=MODEL,
        effort="none",
        max_tokens=4096,
        refusal_fallbacks="off",
        prompt_sha256={},
        temperature=0.7,
        seed=9000,
        seed_derivation="sha256_trial_key_v1",
        extractor_context=context,
        openrouter_host=HOST,
        openrouter_quantization="fp8",
    )
    report = build_report(
        outcome, agent, prompt_variants=["baseline"], trials=2, llm=llm, presets=["vulnerable"]
    )
    path = tmp_path / f"{context}.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


def test_pilot_09_renders_both_conditions_and_the_decision(
    script: ModuleType, tmp_path: Path
) -> None:
    paths = [synthetic_report(tmp_path, "none"), synthetic_report(tmp_path, "agent_system_prompt")]
    lines = script.analyse("09", paths)
    text = "\n".join(lines)
    assert "trials 4 (expected 60)" in text
    attack = [ln for ln in lines if ln.startswith(f"| {MODEL} | none | ")]
    treated = [ln for ln in lines if ln.startswith(f"| {MODEL} | agent_system_prompt | ")]
    assert len(attack) == 2  # attack and benign tables
    assert len(treated) == 2
    # The synthetic extractor stores the benign preference in both conditions.
    assert "| 2/2 (100%" in treated[1]
    (decision,) = [ln for ln in lines if ln.startswith(f"| {MODEL} | 28/30 ")]
    # "ok" answers make no tool calls: nothing exposed, so the rule refuses to decide.
    assert "not evaluable (attack row not meaningful)" in decision
    assert "0 pairs" in decision
    assert "**Analysis decisions.**" in text


def test_pilot_09_takes_one_to_four_reports(script: ModuleType, tmp_path: Path) -> None:
    path = synthetic_report(tmp_path, "none")
    with pytest.raises(SystemExit, match="one to four"):
        script.analyse("09", [path] * 5)


def test_pilot_09_document_says_not_run_until_data_exists(script: ModuleType) -> None:
    if any((script.DATA / n).exists() for n in script.PILOTS[DOC]):
        pytest.skip("pilot 09 data exists")
    rendered = script.render(DOC)
    assert rendered == "\n".join([script.START, "", "Not run.", "", script.END])
