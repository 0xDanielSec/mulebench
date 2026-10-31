"""UntrustedContentMarking: wrap untrusted result fields in explicit delimiters.

Every untrusted field becomes

    ⟦untrusted:<nonce>⟧<content>⟦/untrusted:<nonce>⟧

The nonce is per trial (derived from the trial key, so cassettes replay
deterministically) and unknown to whoever wrote the content. Delimiter
characters already present in the content are removed, so content cannot close
the block or open a fake one. Marking only tells a model where untrusted text
starts and ends; it enforces nothing.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mulebench.tools.context import ToolContext

OPEN, CLOSE = "⟦", "⟧"  # mathematical white square brackets
_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def marking_nonce(trial_key: str) -> str:
    return hashlib.sha256(trial_key.encode("utf-8")).hexdigest()[:16]


def wrap(text: str, nonce: str) -> str:
    clean = text.replace(OPEN, "").replace(CLOSE, "")
    return f"{OPEN}untrusted:{nonce}{CLOSE}{clean}{OPEN}/untrusted:{nonce}{CLOSE}"


class UntrustedContentMarking:
    name = "untrusted_content_marking"

    def __init__(self, nonce: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{8,64}", nonce):
            raise ValueError("nonce must be 8-64 lowercase hex characters")
        self.nonce = nonce

    def transform(
        self,
        ctx: ToolContext,
        tool: str,
        data: dict[str, object],
        untrusted_paths: list[str],
    ) -> dict[str, object]:
        for path in untrusted_paths:
            _wrap_at(data, path, self.nonce)
        return data


def _wrap_at(data: object, path: str, nonce: str) -> None:
    parts: list[str | int] = [name or int(index) for name, index in _PART.findall(path)]
    if not parts:
        return
    current = data
    for part in parts[:-1]:
        if isinstance(part, str) and isinstance(current, dict):
            current = current.get(part)
        elif isinstance(part, int) and isinstance(current, list) and part < len(current):
            current = current[part]
        else:
            return
    last = parts[-1]
    if isinstance(last, str) and isinstance(current, dict):
        value = current.get(last)
        if isinstance(value, str):
            current[last] = wrap(value, nonce)
