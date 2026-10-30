"""Per-session state handed to every tool call."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from honeyledger.ledger import Ledger
from honeyledger.tools.trace import TraceRecorder

if TYPE_CHECKING:
    from honeyledger.tools.guards import Guard


class SequentialKeys:
    """Default idempotency-key factory: `<session_id>-<n>`, unique per call."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._counter = itertools.count(1)

    def __call__(self) -> str:
        return f"{self._session_id}-{next(self._counter)}"


@dataclass(frozen=True)
class ToolContext:
    """Session identity plus everything a tool call needs.

    `customer_id` is the authenticated customer of the session. Guards compare
    tool arguments against it; the agent cannot change it.
    """

    customer_id: str
    session_id: str
    ledger: Ledger
    guards: tuple[Guard, ...] = ()
    trace: TraceRecorder = field(default_factory=TraceRecorder)
    key_factory: Callable[[], str] | None = None

    def __post_init__(self) -> None:
        if self.key_factory is None:
            object.__setattr__(self, "key_factory", SequentialKeys(self.session_id))

    def new_idempotency_key(self) -> str:
        if self.key_factory is None:  # pragma: no cover - set in __post_init__
            raise RuntimeError("key_factory not set")
        return self.key_factory()
