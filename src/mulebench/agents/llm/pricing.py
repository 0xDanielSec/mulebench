"""Dated per-model prices for cost estimates. Verify before relying on them.

Source: Anthropic first-party API price table as of PRICING_AS_OF. Cache writes
(5-minute TTL) are priced at 1.25x input. Where no cache-read price was listed,
0.1x input is used and the entry is marked estimated.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from mulebench.agents.base import TokenUsage

PRICING_AS_OF = "2026-10-06"


class Price(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float
    cache_read_estimated: bool = False

    @property
    def cache_write_per_mtok(self) -> float:
        return self.input_per_mtok * 1.25


PRICES: dict[str, Price] = {
    "claude-fable-5-1": Price(input_per_mtok=10.0, output_per_mtok=50.0, cache_read_per_mtok=0.25),
    "claude-opus-5-5": Price(input_per_mtok=4.0, output_per_mtok=20.0, cache_read_per_mtok=0.20),
    "claude-opus-5": Price(
        input_per_mtok=5.0, output_per_mtok=25.0, cache_read_per_mtok=0.5, cache_read_estimated=True
    ),
    "claude-sonnet-5-5": Price(input_per_mtok=2.0, output_per_mtok=10.0, cache_read_per_mtok=0.20),
    "claude-haiku-5-5": Price(
        input_per_mtok=0.10,
        output_per_mtok=0.50,
        cache_read_per_mtok=0.01,
        cache_read_estimated=True,
    ),
}


def price_for(model: str) -> Price | None:
    """Exact id first, then the longest known id the model name starts with."""
    if model in PRICES:
        return PRICES[model]
    matches = [k for k in PRICES if model.startswith(k)]
    return PRICES[max(matches, key=len)] if matches else None


def cost_usd(usage: TokenUsage, model: str) -> float | None:
    price = price_for(model)
    if price is None:
        return None
    total = (
        usage.input_tokens * price.input_per_mtok
        + usage.output_tokens * price.output_per_mtok
        + usage.cache_write_tokens * price.cache_write_per_mtok
        + usage.cache_read_tokens * price.cache_read_per_mtok
    ) / 1_000_000
    return round(total, 6)
