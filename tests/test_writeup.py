"""Every interval-formatted number in docs/writeup.md is a generated result."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
WRITEUP = ROOT / "docs" / "writeup.md"
# "k/n (rate%, low%-high%)", as scripts/pilot_results.py renders it
RESULT = re.compile(r"\d+/\d+ \(\d+%, \d+%-\d+%\)")


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pilot_results", ROOT / "scripts" / "pilot_results.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pilot_results"] = module
    spec.loader.exec_module(module)
    return module


def generated_text(script: ModuleType) -> str:
    """The generated Results blocks of every pilot document, rendered from the data."""
    return "\n".join(script.render(doc) for doc in script.PILOTS)


def test_every_interval_number_in_the_writeup_is_rendered_from_the_data() -> None:
    script = load_script()
    rendered = generated_text(script)
    cited = RESULT.findall(WRITEUP.read_text(encoding="utf-8"))
    assert len(cited) >= 30
    missing = sorted({c for c in cited if c not in rendered})
    assert not missing, f"not in any rendered pilot result: {missing}"


def _cell(script: ModuleType, name: str, sid: str) -> list[dict[str, Any]]:
    report = json.loads((script.DATA / name).read_text(encoding="utf-8"))
    trials: list[dict[str, Any]] = script.cells_of(report)[
        (sid, "vulnerable", "baseline", "attack")
    ]
    return trials


def test_writeup_memory_claims_match_the_data() -> None:
    script = load_script()
    text = WRITEUP.read_text(encoding="utf-8")
    via = {
        "qwen3-14b": "15/15",
        "gpt-oss-20b": "17/28",
        "gemma-4-26b": "28/28",
        "mistral-small-3.2": "22/22",
    }
    for model, share in via.items():
        trials = _cell(script, f"pilot-08-{model}.json", "014a")
        followed, same = script.via_memory_08(trials)
        assert followed.split(" ")[0] == share, model
        assert f"| {share} |" in text, model
        injected = script.part(script.ok_trials(trials), "memory", "memory_injected")
        assert injected.startswith("30/30"), model
        if model == "gpt-oss-20b":
            assert same.startswith("11/28")
            assert "in 11 of its 28 successes" in text
    # TL;DR: share of all attack trials that leaked through memory
    assert "50% (qwen3-14b, 15/30)" in text
    assert "93% (gemma-4-26b, 28/30)" in text
    assert "frontier" not in text.lower()


def test_writeup_pilot_09_claims_match_the_data() -> None:
    script = load_script()
    text = WRITEUP.read_text(encoding="utf-8")
    for cond in ("none", "agent_system_prompt"):
        trials = _cell(script, f"pilot-09-mistral-small-3.2-{cond}.json", "014a")
        injected = script.part(script.ok_trials(trials), "memory", "memory_injected")
        assert injected.startswith("30/30"), cond
    assert "30/30 in\nboth conditions" in text or "(30/30 in both conditions)" in text
