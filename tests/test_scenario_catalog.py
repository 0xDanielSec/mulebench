"""The scenario catalog in docs/scenarios.md must match real built-in results.

The table between the catalog markers is rendered from `run_all(load_builtin(),
ScriptedAgent())`, the same run as `mulebench run --builtin`. To update it:

    uv run python -m tests.test_scenario_catalog
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import ScenarioResult, TrialResult

DOC = Path(__file__).resolve().parent.parent / "docs" / "scenarios.md"
START = "<!-- catalog:start (generated; checked by tests/test_scenario_catalog.py) -->"
END = "<!-- catalog:end -->"
HEADER = [
    "| Id | Channel | Technique | Expected invariants | vulnerable (attack) "
    "| hardened (attack) | Benign control |",
    "|---|---|---|---|---|---|---|",
]


def outcome(trial: TrialResult) -> str:
    parts = []
    for inv in trial.invariants:
        for code, n in Counter(v.code for v in inv.violations).items():
            parts.append(f"{inv.id} `{code}`" + (f" x{n}" if n > 1 else ""))
    return f"{trial.status}: " + (", ".join(parts) if parts else "all hold")


def row(s: ScenarioResult) -> str:
    def trial(preset: str, variant: str) -> TrialResult:
        return next(c for c in s.cells if c.preset == preset and c.variant == variant).trials[0]

    benign_ok = all(trial(p, "benign").utility_exact for p in ("vulnerable", "hardened"))
    cells = [
        f"`{s.scenario_id}`",
        f"`{s.channel}`",
        s.name,
        ", ".join(s.expected_invariants),
        outcome(trial("vulnerable", "attack")),
        outcome(trial("hardened", "attack")),
        "utility exact (both presets)" if benign_ok else "utility FAILS",
    ]
    return "| " + " | ".join(cells) + " |"


def render() -> str:
    results = run_all(load_builtin(), ScriptedAgent()).results
    return "\n".join([START, *HEADER, *(row(s) for s in results), END])


def documented() -> str:
    text = DOC.read_text(encoding="utf-8")
    return text[text.index(START) : text.index(END) + len(END)]


def test_catalog_matches_builtin_run() -> None:
    expected = render()
    assert documented() == expected, (
        "docs/scenarios.md catalog is out of date; run "
        "`uv run python -m tests.test_scenario_catalog`. Expected:\n" + expected
    )


def main() -> None:
    text = DOC.read_text(encoding="utf-8")
    DOC.write_text(text.replace(documented(), render()), encoding="utf-8")


if __name__ == "__main__":
    main()
