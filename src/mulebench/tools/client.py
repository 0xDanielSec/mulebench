"""The only interface an agent gets: call a tool by name, get a `ToolResult`.

The client holds the session's `ToolContext` privately. Agents never see the
ledger, the guards or the trace.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from mulebench.tools.context import ToolContext
from mulebench.tools.registry import TOOLS, ToolError, ToolResult, call_tool
from mulebench.tools.schemas import UNTRUSTED_KEY

__all__ = ["ToolClient", "ToolError", "ToolResult", "strip_untrusted_markers"]


def strip_untrusted_markers(schema: object) -> object:
    """Copy of a JSON schema without `x-untrusted` keys (those are trace-only)."""
    if isinstance(schema, dict):
        return {k: strip_untrusted_markers(v) for k, v in schema.items() if k != UNTRUSTED_KEY}
    if isinstance(schema, list):
        return [strip_untrusted_markers(v) for v in schema]
    return schema


class ToolClient:
    def __init__(self, ctx: ToolContext) -> None:
        self._ctx = ctx

    def call(self, tool: str, args: Mapping[str, object]) -> ToolResult:
        return call_tool(self._ctx, tool, args)

    def check_call(self, tool: str, args: Mapping[str, object]) -> tuple[str, str] | None:
        """(kind, detail) if the call cannot be executed as given, else None.

        Kinds: "unknown_tool", "schema". Nothing is executed or traced.
        """
        spec = TOOLS.get(tool)
        if spec is None:
            return "unknown_tool", f"unknown tool: {tool!r}"
        try:
            spec.input_model.model_validate(dict(args))
        except ValidationError as exc:
            return "schema", f"{exc.error_count()} validation error(s)"
        return None

    def tool_names(self) -> list[str]:
        return sorted(TOOLS)

    def model_tool_schemas(self) -> list[dict[str, Any]]:
        """Tool definitions for a model: name, description, input schema.

        Sorted by name for a stable request prefix. No `x-untrusted` markers.
        """
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": strip_untrusted_markers(spec.input_schema()),  # dict in, dict out
            }
            for spec in sorted(TOOLS.values(), key=lambda s: s.name)
        ]
