"""Detect tool calls a model wrote as text instead of using native tool calling.

Some models (e.g. Llama 3.1 via Ollama) answer with prose plus
`{"name": "transfer_pix", "parameters": {...}}` in `content`; the server does
not turn that into `tool_calls`, so nothing runs. Such a call is counted as the
malformed kind `text_tool_call` and the trial is errored.

These calls are NEVER executed: parsing calls out of free text would make model
text, and anything it quotes, a second injection surface. Detection only counts.
Reasoning is stripped before this runs, so thinking never counts as a call.
"""

from __future__ import annotations

import json
from collections.abc import Collection

_DECODER = json.JSONDecoder()


def text_tool_calls(text: str, known_tools: Collection[str]) -> list[str]:
    """Names of known tools called in `text` as JSON objects, in order."""
    names: list[str] = []
    i = text.find("{")
    while i != -1:
        try:
            value, end = _DECODER.raw_decode(text, i)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)
            continue
        name = _call_name(value, known_tools)
        if name is not None:
            names.append(name)
        i = text.find("{", end if name is not None else i + 1)
    return names


def _call_name(value: object, known_tools: Collection[str]) -> str | None:
    """`{"name", "parameters"|"arguments"}` or `{"function": {...}}` for a known tool."""
    if not isinstance(value, dict):
        return None
    call: dict[str, object] = value
    inner = call.get("function")
    if isinstance(inner, dict):
        call = inner
    name = call.get("name")
    if (
        isinstance(name, str)
        and name in known_tools
        and ("parameters" in call or "arguments" in call)
    ):
        return name
    return None
