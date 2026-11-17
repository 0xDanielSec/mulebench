"""014a (automatic memory) through OpenRouter: the LLM extractor uses the run's hosted
model with the pinned host and quantization, its calls count toward the cost meter and
--max-cost-usd, its transient errors count like any other, and the estimate's token
basis includes extraction. Offline (FakeTransport)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.model import ModelCallError
from mulebench.agents.llm.openrouter import OpenRouterChatModel
from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import fixed_pricer
from mulebench.agents.llm.transport import TransportResponse
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.reports import build_report

ROOT = Path(__file__).resolve().parents[2]
MODEL = "vendor/hosted-model"
HOST = "SyntheticHost"
SCENARIO = "memory-auto-persistent-exfiltration-014a"
PRICE = Price(input_per_mtok=1000.0, output_per_mtok=1000.0, cache_read_per_mtok=0.0)


class Recording:
    def __init__(self, fail_extraction: bool = False) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.fail_extraction = fail_extraction

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        self.requests.append((trial_key, params))
        if self.fail_extraction and trial_key.endswith("#mem0"):
            raise ModelCallError("provider_rate_limited", "HTTP 429 after 6 attempts")
        content = "- prefers short answers" if trial_key.endswith("#mem0") else "ok"
        body = {
            "id": "gen",
            "model": MODEL,
            "provider": HOST,
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": content}}
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10},
        }
        return TransportResponse(body=body)


def run(transport: Recording, cap: float = 10.0, trials: int = 1) -> tuple[Any, LLMAgent]:
    scenario = next(s for s in load_builtin() if s.id == SCENARIO)
    assert scenario.memory is not None
    agent = LLMAgent(
        OpenRouterChatModel(transport, HOST, "fp8"),
        model=MODEL,
        effort="none",
        meter=CostMeter(cap),
        temperature=0.7,
        seed=7000,
        pricer=fixed_pricer(PRICE),
    )
    outcome = run_all(
        [scenario], agent, prompt_variants=("baseline",), trials=trials, presets=("vulnerable",)
    )
    return outcome, agent


def test_extractor_uses_the_hosted_model_with_the_same_pin() -> None:
    transport = Recording()
    outcome, _ = run(transport)
    extraction = [p for k, p in transport.requests if k.endswith("#mem0")]
    sessions = [p for k, p in transport.requests if not k.endswith("#mem0")]
    assert len(extraction) == 2  # one per trial: attack and benign
    for params in extraction + sessions:
        assert params["model"] == MODEL
        assert params["provider"]["order"] == [HOST]
        assert params["provider"]["quantizations"] == ["fp8"]
        assert params["provider"]["allow_fallbacks"] is False
    assert all("tools" in p and p["tools"] == [] for p in extraction)
    trial = outcome.results[0].cells[0].trials[0]
    (record,) = [e for e in trial.memory.extractions]
    assert record.extractor == "llm"
    assert record.model_call is not None
    assert record.model_call.served_provider == HOST
    assert record.model_call in trial.model_calls  # counted in the trial's usage and cost


def test_extraction_calls_count_toward_the_meter_and_the_cap() -> None:
    transport = Recording()
    _, agent = run(transport)
    per_call = (100 * PRICE.input_per_mtok + 10 * PRICE.output_per_mtok) / 1_000_000
    assert agent.meter.spent_usd == round(per_call * len(transport.requests), 6)
    # A cap of exactly the session 0 call: the extraction call that follows is refused.
    capped = Recording()
    outcome, _ = run(capped, cap=per_call)
    assert outcome.status == "aborted_budget"
    assert [k for k, _ in capped.requests] == [f"{SCENARIO}/baseline/vulnerable/attack/t000"]


def test_rate_limited_extraction_counts_as_a_transient_error() -> None:
    outcome, agent = run(Recording(fail_extraction=True), trials=10)
    report = build_report(outcome, agent, prompt_variants=["baseline"], trials=10)
    trials = [t for c in outcome.results[0].cells for t in c.trials]
    assert {t.error for t in trials} == {"memory_extraction:provider_rate_limited"}
    assert report.routing is not None
    assert report.routing.transient_errored_trials == {"provider_rate_limited": 20}
    (row,) = [r for r in report.summary.rows if r.preset == "vulnerable"]
    assert "provider_rate_limited" in row.not_meaningful_reasons


def test_estimate_basis_for_014a_includes_extraction_tokens() -> None:
    report = json.loads(
        (ROOT / "docs/experiments/data/pilot-07-qwen3-14b-8k.json").read_text(encoding="utf-8")
    )
    (scenario,) = [s for s in report["scenarios"] if s["scenario_id"] == SCENARIO]
    checked = 0
    for cell in scenario["cells"]:
        for t in cell["trials"]:
            if t["errored"]:
                continue
            calls = t["model_calls"]
            extraction = [e["model_call"] for e in t["memory"]["extractions"]]
            assert extraction
            assert all(e in calls for e in extraction)
            assert t["usage"]["input_tokens"] == sum(c["usage"]["input_tokens"] for c in calls)
            checked += 1
    assert checked > 0
