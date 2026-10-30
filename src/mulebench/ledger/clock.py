"""Injectable clocks and the daily-limit policy hook.

Timezone choice: daily limits use the local calendar day in
America/Sao_Paulo, because Pix limits are defined per Brazilian day. A UTC
window would cut the Brazilian day at 21:00 local time. Timestamps are
stored in UTC; only the window bounds are computed in local time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Protocol
from zoneinfo import ZoneInfo

if TYPE_CHECKING:
    from mulebench.ledger.models import Account

SAO_PAULO: tzinfo = ZoneInfo("America/Sao_Paulo")


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time as a timezone-aware datetime."""
        ...


class SystemClock:
    """Real wall clock. The only place in the package that reads system time."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """Deterministic clock for tests."""

    def __init__(self, at: datetime) -> None:
        _require_aware(at)
        self._at = at

    def now(self) -> datetime:
        return self._at

    def advance(self, delta: timedelta) -> None:
        self._at = self._at + delta

    def set(self, at: datetime) -> None:
        _require_aware(at)
        self._at = at


class LimitPolicy(Protocol):
    """Decides the outgoing limit for an account's current local day.

    Hook for a reduced nighttime limit: an implementation can inspect
    `at_local.time()` and return a lower value at night.
    """

    def limit_cents(self, account: Account, at_local: datetime) -> int: ...


class FlatDailyLimit:
    """Default policy: the account's `daily_limit_cents`, all day long."""

    def limit_cents(self, account: Account, at_local: datetime) -> int:
        return account.daily_limit_cents


def local_day_bounds_utc(at: datetime, tz: tzinfo) -> tuple[datetime, datetime]:
    """Return the [start, end) UTC bounds of the local calendar day containing `at`."""
    _require_aware(at)
    local = at.astimezone(tz)
    start_local = datetime(local.year, local.month, local.day, tzinfo=tz)
    next_day = start_local.date() + timedelta(days=1)
    end_local = datetime(next_day.year, next_day.month, next_day.day, tzinfo=tz)
    return start_local.astimezone(UTC), end_local.astimezone(UTC)


def _require_aware(at: datetime) -> None:
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
