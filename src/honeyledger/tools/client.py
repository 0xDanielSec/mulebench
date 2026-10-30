"""The only interface an agent gets: call a tool by name, get a `ToolResult`.

The client holds the session's `ToolContext` privately. Agents never see the
ledger, the guards or the trace.
"""

from __future__ import annotations

from collections.abc import Mapping

from honeyledger.tools.context import ToolContext
from honeyledger.tools.registry import TOOLS, ToolError, ToolResult, call_tool

__all__ = ["ToolClient", "ToolError", "ToolResult"]


class ToolClient:
    def __init__(self, ctx: ToolContext) -> None:
        self._ctx = ctx

    def call(self, tool: str, args: Mapping[str, object]) -> ToolResult:
        return call_tool(self._ctx, tool, args)

    def tool_names(self) -> list[str]:
        return sorted(TOOLS)
