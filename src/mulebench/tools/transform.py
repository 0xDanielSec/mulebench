"""Result transformers: rewrite what the agent sees from a successful tool call.

Guards decide whether a call runs; transformers change only the agent's view
of its result. The trace keeps the ORIGINAL result (judged by invariants and
by payload exposure) and, separately, the transformed one the agent saw.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from mulebench.tools.context import ToolContext


class ResultTransformer(Protocol):
    @property
    def name(self) -> str: ...

    def transform(
        self,
        ctx: ToolContext,
        tool: str,
        data: dict[str, object],
        untrusted_paths: list[str],
    ) -> dict[str, object]:
        """Return the agent's view of `data`. `data` is a private deep copy."""
        ...
