"""Ablation report page: the tables of `render_ablation_markdown`, as HTML."""

from __future__ import annotations

from mulebench.reports.ablation import AblationReport
from mulebench.viewer.common import badge, brl, dl, page, table
from mulebench.viewer.html import Markup, frag, h
from mulebench.viewer.notes import limitation_items

ATTACK_BADGE: dict[str, tuple[str, str]] = {
    "stopped": ("good", "stopped"),
    "violated": ("bad", "violated"),
    "not_exposed": ("neutral", "not exposed"),
    "errored": ("warn", "errored"),
    "not_measurable": ("neutral", "not measurable"),
}
WORKLOAD_BADGE: dict[str, tuple[str, str]] = {
    "ok": ("good", "ok"),
    "blocked": ("bad", "blocked"),
    "errored": ("warn", "errored"),
    "not_measurable": ("neutral", "not measurable"),
}


def _n(value: int | None, total: int) -> str:
    return "n/m" if value is None else f"{value}/{total}"


def _matrix(report: AblationReport) -> Markup:
    by_key = {(c.scenario_id, c.guard_set): c for c in report.cells}
    scenarios = [f.scenario_id for f in report.flags]
    rows = []
    for name in report.guard_sets:
        row: list[object] = [name]
        for s in scenarios:
            c = by_key.get((s, name))
            if c is None:
                row.append("-")
                continue
            kind, text = ATTACK_BADGE[c.attack]
            row.append(
                frag(
                    badge(kind, text),
                    " " + ",".join(c.violated_invariants) if c.violated_invariants else None,
                    " " + brl(c.unauthorized_outflow_cents)
                    if c.unauthorized_outflow_cents
                    else None,
                    " ",
                    badge("warn", "false positive") if c.false_positive else None,
                )
            )
        rows.append(row)
    return table("Attack outcome per guard set and scenario", ["Guard set", *scenarios], rows)


def ablation_page(report: AblationReport, title: str) -> str:
    flags = table(
        "Scenario flags",
        [
            "Scenario",
            "Stopped alone by",
            "Sole stopper",
            "Defense in depth",
            "Critical in full set",
        ],
        [
            [
                f.scenario_id,
                ", ".join(f.stopped_alone_by) or "-",
                f.sole_stopper or "-",
                "yes" if f.defense_in_depth else "no",
                ", ".join(f.critical_in_full_set) or "-",
            ]
            for f in report.flags
        ],
    )
    summary = table(
        "Security vs usability per guard set",
        [
            "Guard set",
            "Attacks stopped",
            "Unauthorized outflow",
            "Tasks blocked",
            "Blocked tasks",
            "Confirmations",
        ],
        [
            [
                g.guard_set,
                _n(g.attacks_stopped, g.attacks),
                brl(g.unauthorized_outflow_cents),
                _n(g.tasks_blocked, g.tasks),
                ", ".join(g.blocked_tasks) or "-",
                "n/m" if g.confirmations_requested is None else g.confirmations_requested,
            ]
            for g in report.summary
        ],
        numeric=(2, 5),
    )
    workloads = table(
        "Legitimate workloads per guard set",
        ["Workload", "Guard set", "Outcome", "Blocked by", "Confirmations", "Invariant flags"],
        [
            [
                w.workload_id,
                w.guard_set,
                badge(*WORKLOAD_BADGE[w.outcome]),
                ", ".join(w.blocked_by) or "-",
                "n/m" if w.confirmations_requested is None else w.confirmations_requested,
                ", ".join(w.invariant_flags) or "-",
            ]
            for w in report.workload_cells
        ],
    )
    friction = table(
        "Guard friction",
        ["Guard", "Measurable", "Blocks alone", "Confirmations alone", "Denials in full set"],
        [
            [
                f.guard,
                "yes" if f.measurable else "no",
                ", ".join(f.blocks_alone) or "-",
                "n/m" if f.confirmations_alone is None else f.confirmations_alone,
                ", ".join(f.denials_in_full_set) or "-",
            ]
            for f in report.friction
        ],
    )
    sections: list[object] = [
        h(
            "section",
            None,
            h("h2", None, "Run"),
            dl(
                [
                    ("generator version", report.generator_version),
                    ("agent", report.agent.name),
                    ("guards", ", ".join(report.guards)),
                    ("not measurable", ", ".join(report.not_measurable) or "-"),
                ]
            ),
        ),
        h("section", None, h("h2", None, "Matrix"), _matrix(report), flags),
        h("section", None, h("h2", None, "Security vs usability"), summary, friction),
    ]
    if report.workload_cells:
        sections.append(h("section", None, h("h2", None, "Workloads"), workloads))
    if report.sensitivity:
        scenarios = list(report.sensitivity[0].outflow_by_scenario)
        sections.append(
            h(
                "section",
                None,
                h("h2", None, "Session spend cap sensitivity"),
                table(
                    "Damage and usability per cap",
                    [
                        "Guard set",
                        "Cap",
                        "Unauthorized outflow",
                        "Attacks stopped",
                        "Tasks blocked",
                        "Blocked tasks",
                    ],
                    [
                        [
                            p.guard_set,
                            "-" if p.cap_cents is None else brl(p.cap_cents),
                            brl(p.unauthorized_outflow_cents),
                            f"{p.attacks_stopped}/{p.attacks}",
                            f"{p.tasks_blocked}/{p.tasks}",
                            ", ".join(p.blocked_tasks) or "-",
                        ]
                        for p in report.sensitivity
                    ],
                    numeric=(2,),
                ),
                table(
                    "Unauthorized outflow per scenario",
                    ["Guard set", "Cap", *scenarios],
                    [
                        [
                            p.guard_set,
                            "-" if p.cap_cents is None else brl(p.cap_cents),
                            *[brl(p.outflow_by_scenario[s]) for s in scenarios],
                        ]
                        for p in report.sensitivity
                    ],
                ),
            )
        )
    sections.append(
        h(
            "section",
            None,
            h("h2", None, "Limitations"),
            h("ul", None, limitation_items(report.limitations)),
        )
    )
    return page(title, [("All reports", "../index.html"), (title, None)], *sections)
