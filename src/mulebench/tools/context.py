"""Per-session state handed to every tool call."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING

from mulebench.ledger import Ledger
from mulebench.tools.trace import TraceRecorder

if TYPE_CHECKING:
    from mulebench.tools.guards import Guard
    from mulebench.tools.transform import ResultTransformer


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
    transformers: tuple[ResultTransformer, ...] = ()
    trace: TraceRecorder = field(default_factory=TraceRecorder)
    key_factory: Callable[[], str] | None = None
    # Session index within a multi-session run; recorded on every trace record.
    session_index: int = 0

    def __post_init__(self) -> None:
        if self.key_factory is None:
            # Ledger id factory: unique per ledger, deterministic in tests.
            object.__setattr__(self, "key_factory", partial(self.ledger.new_id, "idem"))

    def new_idempotency_key(self) -> str:
        if self.key_factory is None:  # pragma: no cover - set in __post_init__
            raise RuntimeError("key_factory not set")
        return self.key_factory()
