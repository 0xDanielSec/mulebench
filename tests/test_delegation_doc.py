"""The delegation ablation table in docs/delegation.md must match a real run.

Rendered from `run_all` over the delegation scenarios with the scripted
agent. To update it:

    uv run python -m tests.test_delegation_doc
"""

from __future__ import annotations

from pathlib import Path

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import ScenarioResult, TrialResult, Variant

DOC = Path(__file__).resolve().parent.parent / "docs" / "delegation.md"
START = "<!-- delegation-ablation:start (generated; checked by tests/test_delegation_doc.py) -->"
END = "<!-- delegation-ablation:end -->"
PRESETS = (
    "vulnerable",
    "hardened",
    "only:structured_handoff",
    "only:payer_payee_allowlist",
    "only:payer_sees_request",
    "delegation-defences",
)


def cell(t: TrialResult, benign: TrialResult) -> str:
    d = t.delegation
    if d is None:
        return "errored"
    if d.attributed_success:
        text = "**succeeded**" + (", no invariant broken" if t.status != "exposed_violated" else "")
    elif d.crossed_boundary:
        text = "crossed, refused"
    elif d.handoff_tainted:
        text = "tainted, not acted on"
    else:
        text = "not tainted"
    return text if benign.benign_pass else text + " (benign FAILS)"


def row(s: ScenarioResult) -> str:
    def trial(preset: str, variant: Variant) -> TrialResult:
        return s.cell(preset, variant).trials[0]

    cells = [cell(trial(p, "attack"), trial(p, "benign")) for p in PRESETS]
    return f"| `{s.scenario_id}` | " + " | ".join(cells) + " |"


def render() -> str:
    scenarios = [s for s in load_builtin() if s.topology is not None]
    results = run_all(scenarios, ScriptedAgent(), presets=PRESETS).results
    header = "| Scenario | " + " | ".join(f"`{p}`" for p in PRESETS) + " |"
    sep = "|---|" + "---|" * len(PRESETS)
    return "\n".join([START, header, sep, *(row(s) for s in results), END])


def documented() -> str:
    text = DOC.read_text(encoding="utf-8")
    return text[text.index(START) : text.index(END) + len(END)]


def test_delegation_table_matches_run() -> None:
    assert documented() == render(), (
        "docs/delegation.md table is out of date; run `uv run python -m tests.test_delegation_doc`"
    )


def main() -> None:
    text = DOC.read_text(encoding="utf-8")
    DOC.write_text(text.replace(documented(), render()), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
