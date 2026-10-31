"""Plain-text summary table for the terminal."""

from __future__ import annotations

from mulebench.harness.models import Report
from mulebench.harness.stats import HEADLINE_MIN_TRIALS, format_rate

HEADERS = (
    "scenario",
    "prompt",
    "tools",
    "exposed",
    "attack success",
    "refused",
    "atk utility",
    "benign utility",
)


LLM_HEADERS = ("tool validity", "meaningful")


def render_table(report: Report) -> str:
    """Benign utility is always shown next to attack success. LLM runs add tool
    call validity and a `!` where attack resistance is not meaningful."""
    llm = report.llm is not None
    headers = HEADERS + LLM_HEADERS if llm else HEADERS
    rows: list[tuple[str, ...]] = []
    for r in report.summary.rows:
        a, b = r.attack, r.benign
        row: tuple[str, ...] = (
            r.scenario_id,
            r.prompt_variant,
            r.preset,
            "-" if a is None else format_rate(a.exposure),
            "-" if a is None else format_rate(a.attack_success),
            "-" if a is None else format_rate(a.refusal),
            "-" if a is None else format_rate(a.utility_subset),
            "-" if b is None else format_rate(b.utility_exact),
        )
        if llm:
            validity = "-" if r.tool_call_validity is None else format_rate(r.tool_call_validity)
            flag = "yes" if r.resistance_meaningful else "! " + ",".join(r.not_meaningful_reasons)
            row += (validity, flag)
        rows.append(row)
    widths = [max([len(h), *(len(row[i]) for row in rows)]) for i, h in enumerate(headers)]
    lines = [
        "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
        for row in (headers, *rows)
    ]
    t = report.summary.totals
    lines += [
        "",
        f"attack trials: {t.attack_trials}  violated: {t.exposed_violated}  "
        f"resisted: {t.exposed_resisted}  refused: {t.exposed_refused}  "
        f"not_exposed: {t.not_exposed}  errored: {t.errored}  "
        f"benign utility: {t.benign_utility_pass}/{t.benign_trials}",
    ]
    if llm:
        kinds = ", ".join(f"{k}: {n}" for k, n in t.malformed_tool_calls.items()) or "none"
        lines.append(
            f"malformed tool calls ({kinds})  context near limit: {t.context_near_limit} trials"
        )
        if t.not_meaningful_rows:
            lines.append(
                f"! attack resistance not meaningful in {t.not_meaningful_rows} row(s): "
                "low benign utility, errored or not-exposed trials, or context near its limit"
            )
    c = report.cost_totals
    if c.usage.input_tokens or c.usage.output_tokens:
        cost = f"${c.cost_usd:.4f}" if c.cost_usd is not None else "unpriced"
        lines.append(
            f"tokens in/out: {c.usage.input_tokens}/{c.usage.output_tokens}  "
            f"cache w/r: {c.usage.cache_write_tokens}/{c.usage.cache_read_tokens}  "
            f"estimated cost: {cost}"
        )
    if report.axes.trials_per_cell < HEADLINE_MIN_TRIALS and report.llm is not None:
        lines.append(
            f"note: {report.axes.trials_per_cell} trials per cell is exploratory; "
            f"use >= {HEADLINE_MIN_TRIALS} for headline numbers."
        )
    if report.run_status != "complete":
        lines.append(f"RUN ABORTED: {report.run_status} (partial results)")
    return "\n".join(lines)
