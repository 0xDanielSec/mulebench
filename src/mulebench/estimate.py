"""`mulebench estimate`: dry-run cost estimate from tokens of earlier runs.

No network call. For each requested scenario, the mean input and output
tokens per trial (per variant: attack, benign) come from the first given
report that ran it with the `vulnerable` preset and the `baseline` prompt.
Model calls of every session and of memory extraction are included, since
they are all in the trial's usage. Prices come from the local price table:
the pinned host's price when one is given, else the highest price listed
for the model (hosts may still be "TBD"). A safety factor (default 2.0)
covers models that write more than the model of the source reports
(qwen3-14b, whose output includes its reasoning).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import PriceTable

# Committed reports used by default, in lookup order.
DEFAULT_TOKEN_REPORTS = (
    Path("docs/experiments/data/pilot-03-qwen3-14b-8k.json"),
    Path("docs/experiments/data/pilot-06-qwen3-14b-8k.json"),
    Path("docs/experiments/data/pilot-07-qwen3-14b-8k.json"),
)
VARIANTS = ("attack", "benign")
DEFAULT_SAFETY = 2.0


class EstimateError(ValueError):
    pass


@dataclass(frozen=True)
class TokenBasis:
    scenario_id: str
    variant: str
    source: str
    trials: int
    input_per_trial: float
    output_per_trial: float


def token_basis(scenario_ids: list[str], reports: list[Path]) -> list[TokenBasis]:
    """Mean tokens per trial for each scenario and variant; first report wins."""
    loaded = [(p, _load(p)) for p in reports]
    out: list[TokenBasis] = []
    for sid in scenario_ids:
        for variant in VARIANTS:
            found = next(
                (
                    _basis(sid, variant, p, trials)
                    for p, data in loaded
                    if (trials := _trials(data, sid, variant))
                ),
                None,
            )
            if found is None:
                raise EstimateError(
                    f"no vulnerable/baseline {variant} trials of {sid} in the token reports"
                )
            out.append(found)
    return out


def _load(path: Path) -> dict[str, Any]:
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EstimateError(f"cannot read token report {path}: {exc}") from None
    return data


def _trials(report: dict[str, Any], sid: str, variant: str) -> list[dict[str, Any]]:
    trials: list[dict[str, Any]] = []
    for scenario in report.get("scenarios", []):
        if scenario.get("scenario_id") != sid:
            continue
        for cell in scenario.get("cells", []):
            if (
                cell.get("preset") == "vulnerable"
                and cell.get("prompt_variant") == "baseline"
                and cell.get("variant") == variant
            ):
                trials += [t for t in cell.get("trials", []) if not t.get("errored")]
    return trials


def _basis(sid: str, variant: str, path: Path, trials: list[dict[str, Any]]) -> TokenBasis:
    n = len(trials)
    return TokenBasis(
        scenario_id=sid,
        variant=variant,
        source=path.name,
        trials=n,
        input_per_trial=sum(t["usage"]["input_tokens"] for t in trials) / n,
        output_per_trial=sum(t["usage"]["output_tokens"] for t in trials) / n,
    )


@dataclass(frozen=True)
class ModelEstimate:
    model: str
    host: str | None
    price: Price
    input_tokens: float
    output_tokens: float
    cost_usd: float  # before the safety factor


def estimate(
    models: list[str],
    basis: list[TokenBasis],
    table: PriceTable,
    *,
    trials: int,
    hosts: dict[str, str] | None = None,
) -> list[ModelEstimate]:
    hosts = hosts or {}
    out: list[ModelEstimate] = []
    for model in models:
        host = hosts.get(model)
        price = table.price(model, host) if host else table.any_price(model)
        if price is None:
            where = f"host {host!r}" if host else "any host"
            raise EstimateError(f"no price for {model} ({where}) in the price table")
        tin = sum(b.input_per_trial for b in basis) * trials
        tout = sum(b.output_per_trial for b in basis) * trials
        cost = (tin * price.input_per_mtok + tout * price.output_per_mtok) / 1_000_000
        out.append(ModelEstimate(model, host, price, tin, tout, cost))
    return out


def render(
    basis: list[TokenBasis],
    estimates: list[ModelEstimate],
    table: PriceTable,
    *,
    trials: int,
    safety: float,
) -> list[str]:
    lines = [
        f"price table as_of {table.as_of} (sha256 {table.sha256[:12]}); {trials} trials per "
        f"cell; preset vulnerable, prompt baseline; safety factor {safety:g}",
        "",
        "token basis (mean per trial, from earlier runs):",
    ]
    for b in basis:
        lines.append(
            f"  {b.scenario_id} {b.variant}: in {b.input_per_trial:,.0f} out "
            f"{b.output_per_trial:,.0f} ({b.source}, n={b.trials})"
        )
    lines += ["", "per model:"]
    total = 0.0
    for e in estimates:
        safe = e.cost_usd * safety
        total += safe
        priced = f"host {e.host}" if e.host else "highest listed price, host not pinned"
        lines.append(
            f"  {e.model}: in {e.input_tokens / 1e6:.2f}M x ${e.price.input_per_mtok:g} + out "
            f"{e.output_tokens / 1e6:.2f}M x ${e.price.output_per_mtok:g} = "
            f"${e.cost_usd:.2f}; x{safety:g} = ${safe:.2f} ({priced})"
        )
    lines.append(f"total with safety factor: ${total:.2f}")
    return lines
