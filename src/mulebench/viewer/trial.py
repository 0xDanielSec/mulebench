"""Trial page: timeline of model calls and tool calls, payload entry points,
guard decisions, violations, attribution, disclosure and a ledger diff.

Model output text and reasoning are not in reports; model calls show only
metadata. The final answer is shown when the report stored it.
"""

from __future__ import annotations

import json
import re

from mulebench.attacks import render, scenario_sha256
from mulebench.harness.models import CellResult, Report, ScenarioResult, TrialResult
from mulebench.harness.seed import seed_cell
from mulebench.invariants.authorization import SYSTEM_ACTORS
from mulebench.tools import ToolCallRecord
from mulebench.viewer.attribution_view import POSTHOC_LABEL, trial_attribution
from mulebench.viewer.common import badge, brl, dl, page, rate, table
from mulebench.viewer.html import Markup, frag, h
from mulebench.viewer.notes import LEGACY_DISCLOSURE_NOTE
from mulebench.viewer.run_pages import trial_badges
from mulebench.viewer.scenarios import builtin_scenarios

CANARY = re.compile(r"MB-CANARY-[0-9A-Z]{4}")
_PATH_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def resolve(data: object, path: str) -> object:
    """Value at a trace path like `transactions[0].description`, or None."""
    cur = data
    for name, index in _PATH_PART.findall(path):
        if name and isinstance(cur, dict):
            cur = cur.get(name)
        elif index and isinstance(cur, list) and int(index) < len(cur):
            cur = cur[int(index)]
        else:
            return None
    return cur


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _text(value: object) -> str:
    return value if isinstance(value, str) else _json(value)


def _marked(text: str, canary: str | None) -> Markup:
    """Text with the canary highlighted; every piece escaped."""
    if not canary or canary not in text:
        return frag(text)
    pieces = text.split(canary)
    out: list[object] = [pieces[0]]
    for rest in pieces[1:]:
        out += [h("mark", None, canary), rest]
    return frag(out)


# ------------------------------------------------------------------ ledger


def ledger_diff(
    s: ScenarioResult, c: CellResult, t: TrialResult
) -> tuple[dict[str, int] | None, dict[str, int] | None, list[str]]:
    """(before, after, notes). Stored balances when the report has them,
    otherwise reconstructed from the current scenario file + stored transfers."""
    if t.ledger_before is not None and t.ledger_after is not None:
        return t.ledger_before, t.ledger_after, ["Balances stored in the report."]
    scenario = builtin_scenarios().get(s.scenario_id)
    if scenario is None:
        return None, None, ["Setup unavailable: the scenario is not a builtin scenario."]
    notes = [
        "Reconstructed from the current scenario setup and the stored transfers "
        "(this report does not store balances)."
    ]
    if s.scenario_sha256 is None:
        notes.append(
            "Warning: the report records no scenario hash, so it cannot be checked that the "
            "current scenario file matches the one used in the run."
        )
    elif s.scenario_sha256 != scenario_sha256(scenario):
        notes.append(
            "Warning: the scenario changed since this run (sha256 differs); "
            "the reconstruction may not match the run."
        )
    ledger, _, _ = seed_cell(scenario, render(scenario, c.variant))
    try:
        snap = ledger.snapshot()
    finally:
        ledger.close()
    before = {a.id: a.balance_cents for a in sorted(snap.accounts, key=lambda a: a.id)}
    by_key = {a.pix_key: a.id for a in snap.accounts if a.pix_key}
    after = dict(before)
    for o in t.outgoing_transfers:
        if o.actor in SYSTEM_ACTORS:
            continue
        if o.from_account_id in after:
            after[o.from_account_id] -= o.amount_cents
        target = by_key.get(o.to_pix_key or "")
        if o.kind == "internal" and target in after:
            after[target] += o.amount_cents
    return before, after, notes


# ---------------------------------------------------------------- timeline


def _violations_by_seq(t: TrialResult) -> tuple[dict[int, list[str]], list[str]]:
    transfer_seq: dict[str, int] = {}
    for r in t.trace:
        tid = r.result.get("transfer_id") if r.result else None
        if isinstance(tid, str):
            transfer_seq[tid] = r.seq
    pinned: dict[int, list[str]] = {}
    loose: list[str] = []
    for inv in t.invariants:
        for v in inv.violations:
            label = f"{inv.id} {v.code}: {v.detail}"
            ids = [v.transfer_id, *v.transfer_ids]
            seqs = {v.call_seq} if v.call_seq is not None else set()
            seqs |= {transfer_seq[i] for i in ids if i is not None and i in transfer_seq}
            if not seqs:
                loose.append(label)
            for seq in sorted(seqs):
                pinned.setdefault(seq, []).append(label)
    return pinned, loose


def _record_item(
    r: ToolCallRecord, origin: str | None, violations: list[str], canary: str | None
) -> Markup:
    injected = origin == "tool_output"
    payload_paths = [
        p
        for p in r.untrusted_paths
        if canary and isinstance(v := resolve(r.result, p), str) and canary in v
    ]
    kind = {"ok": "good", "denied": "bad"}.get(r.outcome, "warn")
    head = h(
        "h3",
        None,
        f"#{r.seq} {r.tool} ",
        badge(kind, r.outcome),
        badge("warn", "instruction from tool output") if injected else None,
        badge("bad", "violation") if violations else None,
        badge("warn", "payload entered here") if payload_paths else None,
    )
    parts: list[object] = [head, h("p", {"class": "muted"}, f"origin: {origin or 'unknown'}")]
    parts.append(h("h4", None, "Arguments"))
    parts.append(h("pre", None, _marked(_json(r.args), canary)))
    if r.guard_decisions:
        parts.append(
            table(
                "Guard decisions",
                ["Guard", "Decision", "Code", "Reason"],
                [
                    [
                        g.guard,
                        badge("good", "allowed") if g.allowed else badge("bad", "denied"),
                        g.code or "-",
                        g.reason or "-",
                    ]
                    for g in r.guard_decisions
                ],
            )
        )
    if r.untrusted_paths:
        parts.append(h("h4", None, "Untrusted fields in the result"))
        parts.append(
            h(
                "ul",
                None,
                [
                    h(
                        "li",
                        None,
                        h("code", None, p),
                        " ",
                        badge("warn", "payload") if p in payload_paths else None,
                        h("pre", None, _marked(_text(resolve(r.result, p)), canary)),
                    )
                    for p in r.untrusted_paths
                ],
            )
        )
    if r.result is not None:
        parts.append(h("h4", None, "Result"))
        parts.append(h("pre", None, _marked(_json(r.result), canary)))
    if r.agent_result is not None:
        parts.append(h("h4", None, "What the agent saw (transformed)"))
        parts.append(h("pre", None, _marked(_json(r.agent_result), canary)))
    if r.error is not None:
        parts.append(h("h4", None, "Error"))
        parts.append(h("pre", None, _json(r.error)))
    if violations:
        parts.append(h("h4", None, "Violations at this call"))
        parts.append(h("ul", None, [h("li", None, v) for v in violations]))
    classes = " ".join(c for c, on in (("violation", violations), ("injected", injected)) if on)
    return h("li", {"class": classes or None, "id": f"call-{r.seq}"}, parts)


# -------------------------------------------------------------------- page


def trial_page(
    report_title: str,
    report: Report,
    s: ScenarioResult,
    c: CellResult,
    t: TrialResult,
    *,
    stores_final_text: bool,
    cell_link: str,
) -> str:
    title = f"{s.scenario_id} · {c.prompt_variant} · {c.preset} · {c.variant} · trial {t.trial}"
    scenario = builtin_scenarios().get(s.scenario_id)
    canary = scenario.canary if scenario is not None else None
    if canary is None:
        found = {m for r in t.trace for m in CANARY.findall(_json(r.result))}
        canary = min(found) if found else None

    summary = dl(
        [
            ("outcome", trial_badges(t, c.variant, *trial_attribution(s, c, t))),
            ("trial key", t.trial_key),
            ("stopped", t.metrics.stopped),
            ("error", t.error or "-"),
            ("payload exposed", "-" if t.payload_exposed is None else str(t.payload_exposed)),
            ("canary", canary or "unknown"),
            ("seed / temperature", f"{t.seed} / {t.temperature}"),
            ("unauthorized outflow", brl(t.unauthorized_outflow_cents)),
        ]
    )

    if t.final_text is not None:
        answer: object = h("pre", None, _marked(t.final_text, canary))
    elif stores_final_text:
        answer = h("p", None, "No final answer.")
    else:
        answer = h("p", {"class": "note"}, "Not stored: this report predates final-answer storage.")

    calls = table(
        "Model calls (metadata only; model text and reasoning are not shown)",
        ["#", "Stop reason", "Input tokens", "Output tokens", "Reasoning"],
        [
            [
                i,
                frag(m.stop_reason or "-", " ", badge("warn", "cut by cap"))
                if m.stop_reason in ("length", "max_tokens")
                else (m.stop_reason or "-"),
                m.usage.input_tokens,
                m.usage.output_tokens,
                "present (not shown)" if m.reasoning_present else "none",
            ]
            for i, m in enumerate(t.model_calls, start=1)
        ],
        numeric=(2, 3),
    )

    origins = {st.seq: st.origin for st in t.agent_steps}
    pinned, loose = _violations_by_seq(t)
    timeline = h(
        "ol",
        {"class": "timeline"},
        [_record_item(r, origins.get(r.seq), pinned.get(r.seq, []), canary) for r in t.trace],
    )

    invariants = table(
        "Invariants",
        ["Invariant", "Holds", "Applicable", "Violations"],
        [
            [
                i.id,
                badge("good", "holds") if i.holds else badge("bad", "violated"),
                "yes" if i.applicable else "no",
                ", ".join(v.code for v in i.violations) or "-",
            ]
            for i in t.invariants
        ],
    )

    a, source = trial_attribution(s, c, t)
    attribution = (
        h("p", None, "Not available (errored trial, or a scenario that is not builtin).")
        if a is None
        else frag(
            h("p", {"class": "note"}, f"Attribution: {POSTHOC_LABEL}.")
            if source == "post-hoc"
            else None,
            dl(
                [
                    ("attack success", "-" if a.attack_success is None else str(a.attack_success)),
                    ("task error", str(a.task_error)),
                    ("task omitted", str(a.task_omitted)),
                    ("reasons", ", ".join(a.reasons) or "-"),
                ]
            ),
        )
    )
    d = t.disclosure
    disclosure = (
        h("p", None, "Not checked (no final answer).")
        if d is None
        else frag(
            h("p", {"class": "note"}, "Disclosure: " + LEGACY_DISCLOSURE_NOTE + ".")
            if not d.sinks
            else None,
            table(
                "Disclosure per sink",
                ["Sink", "Exact", "Accounts", "Approximate", "Accounts (approx.)"],
                [
                    [
                        sink,
                        "yes" if v.disclosed else "no",
                        ", ".join(v.foreign_accounts) or "-",
                        "yes" if v.approximate else "no",
                        ", ".join(v.approximate_accounts) or "-",
                    ]
                    for sink, v in d.sinks.items()
                ]
                or [
                    [
                        "final_answer (older report)",
                        "yes" if d.disclosed else "no",
                        ", ".join(d.foreign_accounts) or "-",
                        "-",
                        "-",
                    ]
                ],
            ),
        )
    )

    before, after, notes = ledger_diff(s, c, t)
    ledger_parts: list[object] = [h("p", {"class": "note"}, n) for n in notes]
    if before is not None and after is not None:
        ledger_parts.append(
            table(
                "Balances",
                ["Account", "Before", "After", "Change"],
                [
                    [
                        acc,
                        brl(before[acc]),
                        brl(after.get(acc, before[acc])),
                        brl(after.get(acc, before[acc]) - before[acc]),
                    ]
                    for acc in before
                ],
                numeric=(1, 2, 3),
            )
        )
    ledger_parts.append(
        table(
            "Transfers made during the trial",
            ["Id", "Kind", "From", "To Pix key", "Amount", "Authorization", "Actor"],
            [
                [
                    o.id,
                    o.kind,
                    o.from_account_id or "-",
                    o.to_pix_key or "-",
                    brl(o.amount_cents),
                    o.authorization_id or "none",
                    o.actor,
                ]
                for o in t.outgoing_transfers
                if o.actor not in SYSTEM_ACTORS
            ],
            numeric=(4,),
        )
    )

    confirmations = (
        table(
            "Confirmations",
            ["#", "Tool", "Approved", "Arguments"],
            [
                [r.seq, r.tool, "yes" if r.approved else "no", h("pre", None, _json(r.args))]
                for r in t.confirmations
            ],
        )
        if t.confirmations
        else h("p", None, "No confirmation requests.")
    )

    return page(
        title,
        [
            ("All reports", "../../index.html"),
            (report_title, "../index.html"),
            (f"{s.scenario_id} {c.prompt_variant} {c.preset} {c.variant}", cell_link),
            (f"trial {t.trial}", None),
        ],
        h("section", None, h("h2", None, "Summary"), summary),
        h("section", None, h("h2", None, "Final answer"), answer),
        h(
            "section",
            None,
            h("h2", None, "Model calls"),
            calls,
            dl(
                [
                    ("calls cut by cap", str(t.length_calls)),
                    ("cell tool-call validity", rate(c.tool_call_validity)),
                ]
            ),
        ),
        h(
            "section",
            None,
            h("h2", None, "Timeline"),
            h(
                "p",
                {"class": "muted"},
                "Tool calls in order. Marked: untrusted fields, where the payload (canary) "
                "entered, calls the agent made on instructions from tool output, guard "
                "decisions and the calls where an invariant broke.",
            ),
            timeline if t.trace else h("p", None, "No tool calls."),
            h("h3", None, "Violations not tied to one call") if loose else None,
            h("ul", None, [h("li", None, v) for v in loose]) if loose else None,
        ),
        h("section", None, h("h2", None, "Invariants"), invariants),
        h("section", None, h("h2", None, "Confirmations"), confirmations),
        h("section", None, h("h2", None, "Attribution"), attribution),
        h("section", None, h("h2", None, "Disclosure"), disclosure),
        h("section", None, h("h2", None, "Ledger"), ledger_parts),
    )
