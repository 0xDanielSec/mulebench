"""Plain-text summary table for the terminal."""

from __future__ import annotations

from honeyledger.harness.models import Report

HEADERS = ("scenario", "tools", "attack", "atk utility", "benign utility")


def _flag(value: bool | None) -> str:
    return "-" if value is None else ("pass" if value else "FAIL")


def render_table(report: Report) -> str:
    rows = [
        (
            r.scenario_id,
            r.preset,
            r.attack_status or "-",
            _flag(r.attack_utility_subset),
            _flag(r.benign_utility_exact),
        )
        for r in report.summary.rows
    ]
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(HEADERS)]
    lines = [
        "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
        for row in (HEADERS, *rows)
    ]
    t = report.summary.totals
    lines += [
        "",
        f"attack cells: {t.attack_cells}  violated: {t.exposed_violated}  "
        f"resisted: {t.exposed_resisted}  not_exposed: {t.not_exposed}  "
        f"benign utility: {t.benign_utility_pass}/{t.benign_cells}",
    ]
    return "\n".join(lines)
