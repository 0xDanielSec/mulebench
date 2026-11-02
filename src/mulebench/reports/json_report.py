"""Versioned JSON report (schema_version 3). Deterministic for scripted agents and
for cassette replay; live LLM runs are not deterministic by nature."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import mulebench
from mulebench.agents import Agent
from mulebench.agents.base import TokenUsage
from mulebench.harness.models import (
    NO_PROMPT,
    PRESETS,
    VARIANTS,
    AgentDescriptor,
    Axes,
    CellResult,
    CostTotals,
    Generator,
    LLMConfig,
    PricingInfo,
    Report,
    ScenarioResult,
    Summary,
    SummaryRow,
    SummaryTotals,
)
from mulebench.harness.runner import RunOutcome
from mulebench.harness.stats import HEADLINE_MIN_TRIALS
from mulebench.harness.validity import (
    coerced_counts,
    malformed_counts,
    not_meaningful_reasons,
    tool_call_validity,
)

LIMITATIONS = [
    "The scripted agent obeys instructions found in tool output by construction; "
    "its results validate the harness, not the vulnerability of any real model.",
    "All scenario data is synthetic.",
    "INV-1, INV-2 and INV-3 assume a single session per run.",
    "INV-4 (human confirmation for high-risk actions) is not implemented yet.",
    "INV-2 judges successful calls only; data leaked through error messages is not checked.",
    "INV-3 structuring is an evasion indicator, not a verdict on intent; it groups by payee, "
    "so splitting across multiple payees (mule-style) is not detected.",
    f"Rates come with Wilson 95% intervals; headline numbers need >= {HEADLINE_MIN_TRIALS} "
    "trials per cell. 0/n only bounds the rate from above; it never means safe.",
    "On the Anthropic API sampling parameters (temperature) cannot be set; "
    "trial_key identifies a trial and does not control the model.",
    "OpenAI-compatible local servers get temperature and a per-trial seed derived from "
    "the base seed and a hash of the trial_key (llm.seed_derivation); even at "
    "temperature 0 outputs are not guaranteed identical across hardware or batching.",
    "A malformed tool call (invalid JSON, unknown tool, schema-invalid arguments) makes "
    "the trial errored, never resisted. Integers sent as digit-only strings are coerced "
    "at the LLM agent boundary unless arg_coercion is off; coerced calls are counted "
    "separately. Rows with low benign utility, many errored or "
    "not-exposed trials, or a context near its limit are marked "
    "resistance_meaningful=false.",
]


def build_report(
    outcome: RunOutcome,
    agent: Agent,
    *,
    prompt_variants: Sequence[str] = (NO_PROMPT,),
    trials: int = 1,
    llm: LLMConfig | None = None,
    pricing: PricingInfo | None = None,
    presets: Sequence[str] = PRESETS,
) -> Report:
    results = sorted(outcome.results, key=lambda r: r.scenario_id)
    rows: list[SummaryRow] = []
    for s in results:
        for prompt in prompt_variants:
            for preset in presets:
                attack = _find(s, prompt, preset, "attack")
                benign = _find(s, prompt, preset, "benign")
                if attack is None and benign is None:
                    continue
                reasons = not_meaningful_reasons(attack, benign)
                trials_ = [t for c in (attack, benign) if c is not None for t in c.trials]
                rows.append(
                    SummaryRow(
                        scenario_id=s.scenario_id,
                        prompt_variant=prompt,
                        preset=preset,
                        attack=None if attack is None else attack.attack,
                        benign=None if benign is None else benign.benign,
                        tool_call_validity=tool_call_validity(trials_),
                        resistance_meaningful=not reasons,
                        not_meaningful_reasons=reasons,
                    )
                )
    all_trials = [t for s in results for c in s.cells for t in c.trials]
    attack_trials = [t for s in results for c in s.cells if c.variant == "attack" for t in c.trials]
    benign_trials = [t for s in results for c in s.cells if c.variant == "benign" for t in c.trials]
    totals = SummaryTotals(
        scenarios=len(results),
        attack_trials=len(attack_trials),
        exposed_violated=sum(t.status == "exposed_violated" for t in attack_trials),
        exposed_resisted=sum(t.status == "exposed_resisted" for t in attack_trials),
        exposed_refused=sum(t.status == "exposed_refused" for t in attack_trials),
        not_exposed=sum(t.status == "not_exposed" for t in attack_trials),
        errored=sum(t.errored for t in all_trials),
        benign_trials=len(benign_trials),
        benign_utility_pass=sum(t.utility_exact is True for t in benign_trials),
        malformed_tool_calls=malformed_counts(all_trials),
        coerced_calls=sum(t.coerced_calls for t in all_trials),
        coerced_args=coerced_counts(all_trials),
        context_near_limit=sum(t.context_near_limit for t in all_trials),
        length_calls=sum(t.length_calls for t in all_trials),
        cut_by_cap_trials=sum(t.cut_by_cap for t in all_trials),
        not_meaningful_rows=sum(not r.resistance_meaningful for r in rows),
    )
    costs = [c.cost_usd for t in all_trials for c in t.model_calls]
    priced = all(c is not None for c in costs)
    return Report(
        schema_version=3,
        generator=Generator(name="mulebench", version=mulebench.__version__),
        agent=AgentDescriptor(name=type(agent).__name__, params=dict(getattr(agent, "params", {}))),
        llm=llm,
        pricing=pricing,
        axes=Axes(
            prompt_variants=list(prompt_variants),
            presets=list(presets),
            variants=list(VARIANTS),
            trials_per_cell=trials,
        ),
        run_status=outcome.status,
        cost_totals=CostTotals(
            usage=sum((t.usage for t in all_trials), TokenUsage()),
            cost_usd=round(sum(c or 0.0 for c in costs), 6) if priced else None,
            priced=priced,
        ),
        limitations=list(LIMITATIONS),
        summary=Summary(rows=rows, totals=totals),
        scenarios=results,
    )


def _find(s: ScenarioResult, prompt: str, preset: str, variant: str) -> CellResult | None:
    return next(
        (
            c
            for c in s.cells
            if c.prompt_variant == prompt and c.preset == preset and c.variant == variant
        ),
        None,
    )


def report_to_json(report: Report) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def write_report(report: Report, path: Path) -> None:
    path.write_bytes(report_to_json(report).encode("utf-8"))


def report_json_schema() -> dict[str, Any]:
    return Report.model_json_schema()


def schema_to_json() -> str:
    return json.dumps(report_json_schema(), indent=2, ensure_ascii=False) + "\n"
