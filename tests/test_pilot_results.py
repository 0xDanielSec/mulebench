"""The Results sections of the pilot write-ups match their committed reports."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent


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


def test_pilot_results_sections_are_up_to_date() -> None:
    script = load_script()
    for doc in script.PILOTS:
        old, new = script.updated(doc)
        assert old == new, f"{doc} is stale: run uv run python scripts/pilot_results.py"
