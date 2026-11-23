"""The generated block of docs/experiments/detect-eval-02.md is up to date."""

from __future__ import annotations

from pathlib import Path

from mulebench.harness.detect_eval import (
    DOC_END,
    DOC_START,
    evaluate,
    render_markdown,
    replace_block,
)

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "experiments" / "detect-eval-02.md"
REPORTS = sorted((ROOT / "docs" / "experiments" / "data").glob("pilot-*.json"))


def test_detect_eval_doc_is_up_to_date() -> None:
    doc = DOC.read_text(encoding="utf-8")
    result = evaluate(REPORTS)
    assert replace_block(doc, render_markdown(result)) == doc, (
        "regenerate: uv run mulebench detect eval docs/experiments/data/pilot-*.json "
        "--out detect-eval.json --doc docs/experiments/detect-eval-02.md"
    )


def test_markers_present_and_independent_rules_lead() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert doc.count(DOC_START) == doc.count(DOC_END) == 1
    block = doc[doc.index(DOC_START) : doc.index(DOC_END)]
    assert block.index("### Independent heuristic") < block.index("### Label-coupled")
    assert "design-informed held-out" in block
