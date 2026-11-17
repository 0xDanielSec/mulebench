"""Retry policy for transient HTTP failures of routed providers (OpenRouter).

HTTP 429 and 5xx answers are retried with exponential backoff and jitter;
`Retry-After` (seconds or an HTTP date) is honoured when present. A retry
resends the same request body: the seed, the messages and every parameter
are unchanged. When the attempts are exhausted the call fails with error
kind `provider_rate_limited` (429) or `provider_unavailable` (5xx); the
trial is then errored (never counted as resisted) and the run continues.

Default schedule: 6 attempts, waits of about 15, 30, 60, 120 and 240 s
("equal jitter": half fixed, half random), each capped at 300 s, so a call
gives up after at most about 10 minutes of waiting.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

RATE_LIMITED = "provider_rate_limited"
UNAVAILABLE = "provider_unavailable"
TRANSIENT_KINDS = frozenset({RATE_LIMITED, UNAVAILABLE})


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 6
    base_s: float = 15.0
    cap_s: float = 300.0

    def delay(self, retry: int, retry_after: str | None, rng: random.Random) -> float:
        """Seconds to wait before retry number `retry` (1-based)."""
        hinted = parse_retry_after(retry_after)
        if hinted is not None:
            return min(self.cap_s, max(0.0, hinted))
        step = min(self.cap_s, self.base_s * 2.0 ** (retry - 1))
        return step / 2 + rng.uniform(0, step / 2)


def is_transient(status: int) -> bool:
    return status == 429 or status >= 500


def exhausted_kind(status: int) -> str:
    return RATE_LIMITED if status == 429 else UNAVAILABLE


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Seconds from a Retry-After header (delta-seconds or HTTP date); None if absent."""
    if not value:
        return None
    text = value.strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return (when - (now or datetime.now(UTC))).total_seconds()
