"""JSONL reading and writing of trace events, with line-numbered errors."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import TextIO

from pydantic import ValidationError

from mulebench.monitor.events import EVENT_ADAPTER, Event


class TraceFormatError(ValueError):
    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


def parse_line(text: str, line: int) -> Event:
    try:
        return EVENT_ADAPTER.validate_json(text)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "<event>"
        raise TraceFormatError(line, f"{where}: {first['msg']}") from None


def read_events(lines: Iterable[str]) -> Iterator[Event]:
    """Events in input order. Blank lines are skipped; a malformed line
    raises `TraceFormatError` with its 1-based line number."""
    for n, raw in enumerate(lines, start=1):
        text = raw.strip()
        if text:
            yield parse_line(text, n)


def dump_event(e: Event) -> str:
    return json.dumps(EVENT_ADAPTER.dump_python(e, mode="json"), sort_keys=True)


def write_events(events: Iterable[Event], out: TextIO) -> int:
    n = 0
    for e in events:
        out.write(dump_event(e) + "\n")
        n += 1
    return n
