"""Run report pages: overview matrix and cell drill-down."""

from __future__ import annotations

from mulebench.harness.models import (
    Attribution,
    CellResult,
    Report,
    ScenarioResult,
    TrialResult,
)
from mulebench.viewer.attribution_view import (
    POSTHOC_LABEL,
    Source,
    cell_attribution,
    trial_attribution,
)
from mulebench.viewer.common import badge, brl, dl, page, rate, slug, table
from mulebench.viewer.exposure import LABELS, describe, not_exposed_breakdown
from mulebench.viewer.html import Markup, frag, h
from mulebench.viewer.notes import legacy_disclosure_note, limitation_items
from mulebench.viewer.recorded import (
    cell_cap,
    money,
    recorded,
    report_cap,
    shown,
    trial_cap,
)

STATUS_BADGE: dict[str, tuple[str, str]] = {
    "exposed_violated": ("bad", "violated"),
    "exposed_resisted": ("good", "resisted"),
    "exposed_refused": ("info", "refused"),
    "not_exposed": ("neutral", "not exposed"),
}


def cell_name(s: ScenarioResult, c: CellResult) -> str:
    return "--".join(slug(x) for x in (s.scenario_id, c.prompt_variant, c.preset, c.variant))


def cell_href(s: ScenarioResult, c: CellResult) -> str:
    return f"cell/{cell_name(s, c)}.html"


def trial_href(s: ScenarioResult, c: CellResult, t: TrialResult) -> str:
    return f"trial/{cell_name(s, c)}--{t.trial}.html"


def trial_badges(
    t: TrialResult,
    variant: str,
    attribution: Attribution | None = None,
    source: Source = "stored",
) -> Markup:
    out: list[Markup] = []
    if t.errored:
        out.append(badge("warn", "errored"))
    elif variant == "attack" and t.status is not None:
        kind, text = STATUS_BADGE.get(t.status, ("neutral", t.status))
        out.append(badge(kind, text))
    elif variant == "benign":
        if t.utility_exact is not None:
            out.append(
                badge("good", "utility ok") if t.utility_exact else badge("bad", "utility miss")
            )
        if t.benign_pass is False:
            out.append(badge("bad", "benign fail"))
    a = attribution if attribution is not None else t.attribution
    if a is not None:
        tag = " (post-hoc)" if source == "post-hoc" else ""
        if a.attack_success:
            out.append(badge("bad", "attack (attributed)" + tag))
        if a.task_error:
            out.append(badge("warn", "task error" + tag))
        if a.task_omitted:
            out.append(badge("warn", "task omitted" + tag))
    d = t.disclosure
    if d is not None:
        if d.disclosed:
            out.append(badge("bad", "disclosed"))
        if d.approximate:
            out.append(badge("warn", "disclosed (approx.)"))
    cap = trial_cap(t)
    if cap.trials:
        out.append(badge("warn", "cut by cap" + (" (derived)" if cap.derived else "")))
    if recorded(t, "context_near_limit") and t.context_near_limit:
        out.append(badge("warn", "context near limit"))
    if recorded(t, "unauthorized_outflow_cents") and t.unauthorized_outflow_cents:
        out.append(badge("bad", f"outflow {brl(t.unauthorized_outflow_cents)}"))
    return frag(out)


def _attribution_lines(s: ScenarioResult, c: CellResult) -> list[tuple[str, object]]:
    ca = cell_attribution(s, c)
    tag = "" if ca.source == "stored" else f" ({POSTHOC_LABEL})"
    if ca.source == "unavailable":
        return [("attribution", "not available")]
    lines: list[tuple[str, object]] = []
    if c.variant == "attack":
        lines.append(("attributed success" + tag, rate(ca.attributed_success)))
    lines += [
        ("task error" + tag, rate(ca.task_error)),
        ("task omitted" + tag, rate(ca.task_omitted)),
    ]
    return lines


def _attack_lines(s: ScenarioResult, c: CellResult) -> list[tuple[str, object]]:
    """Headline first: frozen attack success next to the attribution fields."""
    a = c.attack
    if a is None:
        return []
    lines: list[tuple[str, object]] = [
        ("exposure", rate(a.exposure)),
        ("attack success (policy)", rate(a.attack_success)),
        *_attribution_lines(s, c),
        ("refusal", rate(a.refusal)),
        (
            "disclosure",
            frag(rate(a.disclosure), legacy_disclosure_note())
            if a.disclosure is not None and not a.disclosure_by_sink
            else rate(a.disclosure),
        ),
        ("disclosure (approx.)", rate(a.disclosure_approximate)),
        ("utility (subset)", rate(a.utility_subset)),
    ]
    for sink, r in a.disclosure_by_sink.items():
        lines.append((f"disclosure: {sink}", rate(r)))
    return lines


def _benign_lines(s: ScenarioResult, c: CellResult) -> list[tuple[str, object]]:
    b = c.benign
    if b is None:
        return []
    return [
        ("utility (exact)", rate(b.utility_exact)),
        ("benign pass", rate(b.benign_pass)),
        *_attribution_lines(s, c),
    ]


def _cell_flags(c: CellResult) -> list[Markup]:
    out = []
    errored = sum(t.errored for t in c.trials)
    if errored:
        out.append(badge("warn", f"errored {errored}"))
    cap = cell_cap(c)
    if cap.trials:
        out.append(
            badge("warn", f"cut by cap {cap.trials}" + (" (derived)" if cap.derived else ""))
        )
    if recorded(c, "context_near_limit") and c.context_near_limit:
        out.append(badge("warn", f"context near limit {c.context_near_limit}"))
    return out


def _matrix_cell(report: Report, s: ScenarioResult, prompt: str, preset: str) -> Markup:
    cells = [c for c in s.cells if c.prompt_variant == prompt and c.preset == preset]
    if not cells:
        return frag("—")
    row = next(
        (
            r
            for r in report.summary.rows
            if r.scenario_id == s.scenario_id and r.prompt_variant == prompt and r.preset == preset
        ),
        None,
    )
    parts: list[object] = []
    if row is not None and not row.resistance_meaningful:
        parts.append(badge("warn", "not meaningful: " + ", ".join(row.not_meaningful_reasons)))
        attack = next((c for c in cells if c.variant == "attack"), None)
        if "not_exposed" in row.not_meaningful_reasons and attack is not None:
            breakdown = not_exposed_breakdown(attack)
            if breakdown:
                parts.append(h("p", {"class": "muted"}, "not exposed: " + describe(breakdown)))
    for c in sorted(cells, key=lambda x: x.variant):
        lines = _attack_lines(s, c) if c.variant == "attack" else _benign_lines(s, c)
        shown = list(lines)
        parts.append(
            h(
                "div",
                None,
                h("a", {"href": cell_href(s, c)}, f"{c.variant} ({len(c.trials)} trials)"),
                " ",
                _cell_flags(c),
                dl(shown[:5] if c.variant == "attack" else shown[:4]),
            )
        )
    return frag(parts)


def report_index(report: Report, title: str) -> str:
    prompts = report.axes.prompt_variants
    presets = report.axes.presets
    columns = [(p, q) for p in prompts for q in presets]
    llm = report.llm
    meta = [
        ("generator", f"{report.generator.name} {report.generator.version}"),
        ("agent", report.agent.name),
        ("model", "—" if llm is None else f"{llm.provider} {llm.model}"),
        ("max_tokens", "—" if llm is None else str(llm.max_tokens)),
        ("trials per cell", str(report.axes.trials_per_cell)),
        ("run status", report.run_status),
    ]
    t = report.summary.totals
    cap = report_cap(report)
    totals = [
        ("attack trials", t.attack_trials),
        ("violated", t.exposed_violated),
        ("resisted", t.exposed_resisted),
        ("refused", t.exposed_refused),
        ("not exposed", t.not_exposed),
        ("errored", t.errored),
        ("benign utility", f"{t.benign_utility_pass}/{t.benign_trials}"),
        ("model calls cut at max_tokens", cap.label(cap.calls)),
        ("trials cut by cap", cap.label(cap.trials)),
    ]
    rows = [
        [h("a", {"href": f"#s-{slug(s.scenario_id)}"}, s.scenario_id)]
        + [_matrix_cell(report, s, p, q) for p, q in columns]
        for s in report.scenarios
    ]
    details = [
        h(
            "section",
            {"id": f"s-{slug(s.scenario_id)}", "aria-labelledby": f"h-{slug(s.scenario_id)}"},
            h("h3", {"id": f"h-{slug(s.scenario_id)}"}, s.scenario_id),
            h("p", None, s.name),
            dl(
                [
                    ("category", s.category),
                    ("channel", s.channel),
                    ("expected invariants", ", ".join(s.expected_invariants)),
                    ("scenario sha256", s.scenario_sha256 or "not recorded"),
                ]
            ),
            h(
                "ul",
                None,
                [
                    h(
                        "li",
                        None,
                        h(
                            "a",
                            {"href": cell_href(s, c)},
                            f"{c.prompt_variant} / {c.preset} / {c.variant}",
                        ),
                        " ",
                        _cell_flags(c),
                    )
                    for c in s.cells
                ],
            ),
        )
        for s in report.scenarios
    ]
    return page(
        title,
        [("All reports", "../index.html"), (title, None)],
        h("section", None, h("h2", None, "Run"), dl(meta), dl(totals)),
        h(
            "section",
            None,
            h("h2", None, "Overview"),
            h(
                "p",
                {"class": "muted"},
                "Rates are k/n (rate, Wilson 95% interval). Attack success follows the "
                "invariants (policy); attributed success follows the attack goal "
                "(direction). Open a cell for every rate and its trials.",
            ),
            table(
                "Scenario x prompt x preset",
                ["Scenario", *[f"{p} / {q}" for p, q in columns]],
                rows,
            ),
        ),
        h("section", None, h("h2", None, "Scenarios"), details),
        h(
            "section",
            None,
            h("h2", None, "Limitations"),
            h("ul", None, limitation_items(report.limitations)),
        ),
    )


def _not_exposed_section(c: CellResult) -> Markup | None:
    breakdown = not_exposed_breakdown(c) if c.variant == "attack" else {}
    if not breakdown:
        return None
    return h(
        "section",
        None,
        h("h2", None, "Not-exposed trials"),
        h(
            "p",
            {"class": "muted"},
            "Attack trials that never read the payload, by cause. Cut by the output cap "
            "uses the stored count or the stop reasons of the model calls.",
        ),
        table(
            "Not-exposed trials by cause",
            ["Cause", "Trials"],
            [[LABELS.get(k, k), n] for k, n in breakdown.items()],
            numeric=(1,),
        ),
    )


def cell_page(report_title: str, s: ScenarioResult, c: CellResult) -> str:
    title = f"{s.scenario_id} · {c.prompt_variant} · {c.preset} · {c.variant}"
    lines = _attack_lines(s, c) if c.variant == "attack" else _benign_lines(s, c)
    cap = cell_cap(c)
    validity = [
        (
            "tool-call validity",
            "n/a (no tool calls)"
            if c.tool_call_validity is not None and c.tool_call_validity.n == 0
            else rate(c.tool_call_validity),
        ),
        (
            "tool calls per trial",
            shown(c, "tool_calls_per_trial", lambda v: f"{v:g}"),
        ),
        ("unauthorized outflow", shown(c, "unauthorized_outflow_cents", money)),
        ("model calls cut at max_tokens", cap.label(cap.calls)),
        ("trials cut by cap", cap.label(cap.trials)),
        ("context near limit (trials)", shown(c, "context_near_limit")),
        ("agent", c.agent.name),
    ]
    rows = [
        [
            h("a", {"href": f"../{trial_href(s, c, t)}"}, f"trial {t.trial}"),
            trial_badges(t, c.variant, *trial_attribution(s, c, t)),
            shown(t, "unauthorized_outflow_cents", money),
            t.metrics.tool_calls,
            len(t.model_calls),
            t.metrics.stopped,
        ]
        for t in c.trials
    ]
    filter_box = h(
        "p",
        {"id": "filter-box", "hidden": True},
        h("label", {"for": "filter"}, "Filter trials "),
        h("input", {"id": "filter", "type": "search", "autocomplete": "off"}),
        " ",
        h("span", {"id": "filter-count", "aria-live": "polite"}),
    )
    return page(
        title,
        [("All reports", "../../index.html"), (report_title, "../index.html"), (title, None)],
        h("section", None, h("h2", None, "Aggregates"), dl(lines), dl(validity)),
        _not_exposed_section(c),
        h(
            "section",
            None,
            h("h2", None, "Trials"),
            filter_box,
            table(
                f"{len(c.trials)} trials",
                ["Trial", "Outcome", "Outflow", "Tool calls", "Model calls", "Stopped"],
                rows,
                table_id="trials",
                numeric=(2, 3, 4),
            ),
        ),
    )
