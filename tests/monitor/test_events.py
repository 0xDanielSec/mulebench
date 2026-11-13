from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from mulebench.monitor.events import trace_json_schema
from mulebench.monitor.ingest import TraceFormatError, read_events, write_events
from tests.monitor.conftest import unauthorized_session

ROOT = Path(__file__).resolve().parents[2]


def test_round_trip_preserves_events() -> None:
    events = unauthorized_session()
    buf = io.StringIO()
    assert write_events(events, buf) == len(events)
    assert list(read_events(buf.getvalue().splitlines())) == events


def test_blank_lines_are_skipped() -> None:
    line = '{"v":1,"type":"session_end","ts":"2026-01-15T10:00:00-03:00","session_id":"s"}'
    assert len(list(read_events(["", line, "  "]))) == 1


@pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("not json", "line 2"),
        ('{"v":1,"type":"nope","ts":"2026-01-15T10:00:00Z"}', "line 2"),
        ('{"v":2,"type":"session_end","ts":"2026-01-15T10:00:00Z","session_id":"s"}', "v"),
        ('{"v":1,"type":"session_end","ts":"2026-01-15T10:00:00","session_id":"s"}', "ts"),
        ('{"v":1,"type":"session_end","ts":"2026-01-15T10:00:00Z","session_id":"s","x":1}', "x"),
    ],
)
def test_malformed_line_reports_line_number(line: str, needle: str) -> None:
    good = '{"v":1,"type":"session_end","ts":"2026-01-15T10:00:00Z","session_id":"s"}'
    with pytest.raises(TraceFormatError) as exc:
        list(read_events([good, line]))
    assert exc.value.line == 2
    assert needle in str(exc.value)


def test_committed_trace_schema_matches_models() -> None:
    committed = json.loads((ROOT / "docs" / "monitor-trace.schema.json").read_text("utf-8"))
    assert committed == trace_json_schema(), (
        "regenerate: uv run mulebench monitor schema --out docs/monitor-trace.schema.json"
    )
