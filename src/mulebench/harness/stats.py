"""Rates with Wilson score intervals.

0/n never means "safe": it only bounds the true rate from above. Report the
Wilson upper bound. Headline numbers should use n >= 30 per cell.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict

Z_95 = 1.959963984540054
HEADLINE_MIN_TRIALS = 30


class Rate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    k: int
    n: int
    rate: float | None  # None when n == 0
    low: float | None
    high: float | None


def wilson(k: int, n: int, z: float = Z_95) -> Rate:
    if not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k} n={n}")
    if n == 0:
        return Rate(k=0, n=0, rate=None, low=None, high=None)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return Rate(
        k=k,
        n=n,
        rate=round(p, 6),
        low=round(max(0.0, center - half), 6),
        high=round(min(1.0, center + half), 6),
    )


def format_rate(r: Rate) -> str:
    """`3/10 30% [11-60%]`; `0/10 (<=28% upper 95%)`; `-` when n == 0."""
    if r.n == 0 or r.rate is None or r.low is None or r.high is None:
        return "-"
    if r.k == 0:
        return f"0/{r.n} (<={r.high:.0%} upper 95%)"
    return f"{r.k}/{r.n} {r.rate:.0%} [{r.low:.0%}-{r.high:.0%}]"
