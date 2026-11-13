from __future__ import annotations

from pathlib import Path

import yaml

from mulebench.monitor.rules import RULES, VIOLATION_CODES
from mulebench.monitor.sigma import rule_files

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "docs" / "monitor-rules"


def test_committed_rule_documents_are_up_to_date() -> None:
    expected = rule_files()
    committed = {p.name: p.read_text(encoding="utf-8") for p in RULES_DIR.glob("*.yml")}
    assert committed == expected, (
        "regenerate: uv run mulebench monitor rules --out docs/monitor-rules"
    )


def test_every_rule_and_violation_code_has_a_document() -> None:
    docs = [yaml.safe_load(t) for t in rule_files().values()]
    assert {d["name"] for d in docs} == {r.id for r in RULES}
    assert set(VIOLATION_CODES) <= {d["mulebench"]["code"] for d in docs}
    assert len({d["id"] for d in docs}) == len(docs)


def test_documents_have_sigma_shape_and_review_marks() -> None:
    for text in rule_files().values():
        d = yaml.safe_load(text)
        assert {"title", "id", "logsource", "detection", "level", "falsepositives"} <= set(d)
        assert "condition" in d["detection"]
        assert d["mulebench"]["executed"] is False
        assert all("to be reviewed" in v for v in d["mulebench"]["mappings"].values())
