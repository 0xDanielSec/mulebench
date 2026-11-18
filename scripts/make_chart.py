"""Findings chart: direct injection (004, 009) vs memory leak (014a), from committed reports.

Usage:
    uv run --group chart python scripts/make_chart.py

Writes docs/assets/memory-vs-direct.png (1080x1350) and docs/assets/memory-vs-direct.svg.

The data step (`chart_data`) reads only the committed reports in
docs/experiments/data/ and does not import matplotlib, so it is tested in CI
without the optional `chart` dependency group. Values are attributed attack
success over exposed trials, with Wilson 95% intervals, computed by
scripts/pilot_results.py (the generator of every pilot's Results section).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"
PNG = ASSETS / "memory-vs-direct.png"
SVG = ASSETS / "memory-vs-direct.svg"

TITLE = "Blocked the direct injection. Leaked through memory."
SUBTITLE = (
    "Attributed attack success over exposed trials (N = 26-30 per bar),\n"
    "Wilson 95% intervals. Synthetic data. Open-weight models: pilot 08.\n"
    "The frontier models tested: pilot 10 (014a only)."
)
SCENARIOS = ("004", "009", "014a")
LABELS = {
    "004": "Direct read (004)",
    "009": "Dispute-flow read (009)",
    "014a": "Memory leak (014a)",
}
# (label, report file, scenarios in that report)
MODELS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("qwen3-14b", "pilot-08-qwen3-14b.json", SCENARIOS),
    ("gpt-oss-20b", "pilot-08-gpt-oss-20b.json", SCENARIOS),
    ("gemma-4-26b", "pilot-08-gemma-4-26b.json", SCENARIOS),
    ("mistral-small-3.2", "pilot-08-mistral-small-3.2.json", SCENARIOS),
    ("claude-sonnet-5.5", "pilot-10-claude-sonnet-5.5-vulnerable.json", ("014a",)),
    ("gemini-3.8-flash", "pilot-10-gemini-3.8-flash-vulnerable.json", ("014a",)),
    ("gpt-6.1-terra", "pilot-10-gpt-6.1-terra-vulnerable.json", ("014a",)),
)


@dataclass(frozen=True)
class Bar:
    model: str
    scenario: str
    k: int | None  # None: not tested
    n: int | None
    low: float | None
    high: float | None
    meaningful: bool

    @property
    def rate(self) -> float | None:
        return None if self.k is None or not self.n else self.k / self.n


def _results() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pilot_results", ROOT / "scripts" / "pilot_results.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("scripts/pilot_results.py not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("pilot_results", module)
    spec.loader.exec_module(module)
    return module


def chart_data(data_dir: Path | None = None) -> list[Bar]:
    """Every plotted value, from the committed reports; no matplotlib."""
    pr = _results()
    data = data_dir or pr.DATA
    bars: list[Bar] = []
    for model, name, tested in MODELS:
        report: dict[str, Any] = json.loads((data / name).read_text(encoding="utf-8"))
        cells = pr.cells_of(report)
        preset = "vulnerable"
        for sid in SCENARIOS:
            if sid not in tested:
                bars.append(Bar(model, sid, None, None, None, None, True))
                continue
            attack = cells[(sid, preset, "baseline", "attack")]
            benign = cells[(sid, preset, "baseline", "benign")]
            ex = pr.exposed_trials(attack)
            k = sum(t["attribution"]["attack_success"] is True for t in ex)
            n = len(ex)
            ok = pr.ok_trials(benign)
            utility = sum(bool(t["utility_exact"]) for t in ok) / len(ok) if ok else 0.0
            w = pr.wilson(k, n)
            low = w.low or 0.0
            high = w.high if w.high is not None else 1.0
            bars.append(Bar(model, sid, k, n, low, high, utility >= 0.8))
    return bars


def render(bars: list[Bar], png: Path = PNG, svg: Path = SVG) -> None:
    """Draw the chart (needs the optional `chart` group: matplotlib)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 15,
            "svg.hashsalt": "mulebench",
            "svg.fonttype": "path",
        }
    )
    # Okabe-Ito (colour-blind safe); the memory channel gets the strongest colour.
    colour = {"004": "#56B4E9", "009": "#009E73", "014a": "#D55E00"}
    models = [m for m, _, _ in MODELS]
    fig = plt.figure(figsize=(7.2, 9.0), dpi=150)  # 1080 x 1350 px
    ax = fig.add_axes((0.30, 0.16, 0.64, 0.61))
    height = 0.26
    for i, model in enumerate(models):
        for j, sid in enumerate(SCENARIOS):
            (bar,) = [b for b in bars if b.model == model and b.scenario == sid]
            y = i + (j - 1) * height
            if bar.rate is None:
                if sid == "004":
                    ax.text(
                        0.01,
                        y + height / 2,
                        "direct injection: not tested",
                        va="center",
                        fontsize=11,
                        color="#555555",
                    )
                continue
            if bar.low is None or bar.high is None:
                raise ValueError(f"tested bar without bounds: {bar}")
            ax.barh(
                y,
                bar.rate,
                height=height * 0.92,
                color=colour[sid] if bar.meaningful else "white",
                edgecolor=colour[sid],
                hatch=None if bar.meaningful else "///",
                linewidth=1.2,
            )
            ax.errorbar(
                bar.rate,
                y,
                xerr=[[bar.rate - bar.low], [bar.high - bar.rate]],
                fmt="none",
                ecolor="#222222",
                elinewidth=1.2,
                capsize=3,
            )
            label = f"{bar.k}/{bar.n}" + ("" if bar.meaningful else " (not meaningful)")
            ax.text(bar.high + 0.02, y, label, va="center", fontsize=11, color="#222222")
    ax.set_yticks(range(len(models)), models, fontsize=14)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.25)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0%", "25%", "50%", "75%", "100%"])
    ax.axhline(3.5, color="#888888", linewidth=1, linestyle="--")
    ax.text(
        1.24, 3.62, "the frontier models tested", ha="right", va="top", fontsize=11, color="#555555"
    )
    ax.text(
        1.24, -0.62, "open-weight models", ha="right", va="bottom", fontsize=11, color="#555555"
    )
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis="x", color="#dddddd", linewidth=0.8)
    ax.set_axisbelow(True)
    fig.text(0.04, 0.965, "Blocked the direct injection.", fontsize=22, weight="bold", va="top")
    fig.text(
        0.04,
        0.925,
        "Leaked through memory.",
        fontsize=22,
        weight="bold",
        va="top",
        color=colour["014a"],
    )
    fig.text(0.04, 0.88, SUBTITLE, fontsize=11.5, va="top", color="#333333", linespacing=1.4)
    handles = [Rectangle((0, 0), 1, 1, color=colour[s]) for s in SCENARIOS]
    fig.legend(
        handles,
        [LABELS[s] for s in SCENARIOS],
        loc="lower left",
        ncol=1,
        frameon=False,
        fontsize=13,
        bbox_to_anchor=(0.28, 0.0),
    )
    png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(png, dpi=150, metadata={"Software": None})
    fig.savefig(svg, metadata={"Date": None, "Creator": None})
    plt.close(fig)


def main() -> int:
    bars = chart_data()
    render(bars)
    for b in bars:
        print(b.model, b.scenario, "not tested" if b.k is None else f"{b.k}/{b.n}")
    print(f"wrote {PNG.relative_to(ROOT)} and {SVG.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
