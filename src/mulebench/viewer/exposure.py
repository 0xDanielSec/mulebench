"""Why attack trials never read the payload (not_exposed), when derivable."""

from __future__ import annotations

from collections import Counter

from mulebench.harness.models import CellResult
from mulebench.viewer.recorded import trial_cap

# Tools whose result can carry an injected transaction text.
READ_TOOLS = frozenset({"list_transactions"})

LABELS = {
    "cut_by_cap": "cut by the output cap",
    "answered_without_reading": "answered without reading the history",
    "read_without_payload": "read the history but not the payload",
}


def not_exposed_breakdown(c: CellResult) -> dict[str, int]:
    """Not-exposed, non-errored attack trials by cause, in a fixed order:
    cut by the output cap (last model call ended at the cap, stored or derived
    from stop reasons), answered without reading (no ok read call), read the
    history without the payload (ok read call, canary never seen), or stopped
    for another reason (`stopped:<reason>`)."""
    out: Counter[str] = Counter()
    for t in c.trials:
        if t.errored or t.status != "not_exposed":
            continue
        reads = [r for r in t.trace if r.tool in READ_TOOLS and r.outcome == "ok"]
        if trial_cap(t).trials:
            out["cut_by_cap"] += 1
        elif t.metrics.stopped != "done":
            out[f"stopped:{t.metrics.stopped}"] += 1
        elif not reads:
            out["answered_without_reading"] += 1
        else:
            out["read_without_payload"] += 1
    order = [*LABELS, *sorted(k for k in out if k not in LABELS)]
    return {k: out[k] for k in order if out[k]}


def describe(breakdown: dict[str, int]) -> str:
    return "; ".join(f"{LABELS.get(k, k)}: {n}" for k, n in breakdown.items())
