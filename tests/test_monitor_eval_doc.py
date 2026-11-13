"""The generated block of docs/experiments/monitor-eval-01.md is up to date."""

from __future__ import annotations

from pathlib import Path

from mulebench.harness.monitor_eval import (
    DOC_END,
    DOC_START,
    PILOT_REPORTS,
    evaluate,
    render_markdown,
    replace_block,
)

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "experiments" / "monitor-eval-01.md"
DATA = ROOT / "docs" / "experiments" / "data"


def test_monitor_eval_doc_is_up_to_date() -> None:
    doc = DOC.read_text(encoding="utf-8")
    result = evaluate([DATA / name for name in PILOT_REPORTS])
    assert replace_block(doc, render_markdown(result)) == doc, (
        "regenerate: uv run mulebench monitor eval "
        + " ".join(f"docs/experiments/data/{n}" for n in PILOT_REPORTS)
        + " --doc docs/experiments/monitor-eval-01.md"
    )


def test_pilot_replay_has_no_consistency_mismatch() -> None:
    result = evaluate([DATA / name for name in PILOT_REPORTS])
    for r in result.reports:
        assert all(n == 0 for n in r.consistency.mismatches.values()), r.consistency.examples
        assert r.consistency.streaming_equals_batch == r.consistency.streaming_compared


def test_markers_present() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert doc.count(DOC_START) == doc.count(DOC_END) == 1
