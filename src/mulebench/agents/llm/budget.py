"""Whole-run cost cap. Trials run sequentially; the cap is checked before each call."""

from __future__ import annotations

from mulebench.agents.base import RunAborted


class BudgetExceeded(RunAborted):
    def __init__(self, spent_usd: float, cap_usd: float) -> None:
        super().__init__(f"cost cap reached: spent ${spent_usd:.4f} of ${cap_usd:.4f}")
        self.spent_usd = spent_usd
        self.cap_usd = cap_usd


class CostMeter:
    def __init__(self, cap_usd: float | None = None) -> None:
        self.cap_usd = cap_usd
        self.spent_usd = 0.0

    def check(self) -> None:
        """Raise before a call if the run already spent the cap."""
        if self.cap_usd is not None and self.spent_usd >= self.cap_usd:
            raise BudgetExceeded(self.spent_usd, self.cap_usd)

    def add(self, cost: float | None) -> None:
        if cost is not None:
            self.spent_usd = round(self.spent_usd + cost, 6)
