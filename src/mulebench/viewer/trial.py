"""Trial page: timeline of model calls and tool calls, payload entry points,
guard decisions, violations, attribution, disclosure and a ledger diff.

Model output text and reasoning are not in reports; model calls show only
metadata. The final answer is shown when the report stored it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from mulebench.attacks import render, scenario_sha256
from mulebench.harness.disclosure import SINK_ARGS, amounts_in_text
from mulebench.harness.models import (
    CellResult,
    Report,
    ScenarioResult,
    SinkDisclosure,
    TrialResult,
)
from mulebench.harness.seed import seed_cell
from mulebench.invariants.authorization import SYSTEM_ACTORS
from mulebench.tools import ToolCallRecord
from mulebench.viewer.attribution_view import POSTHOC_LABEL, trial_attribution
from mulebench.viewer.common import badge, brl, dl, page, rate, table
from mulebench.viewer.html import Markup, frag, h
from mulebench.viewer.notes import LEGACY_DISCLOSURE_NOTE
from mulebench.viewer.recorded import money, shown, trial_cap, yes_no
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


def _marked_all(text: str, needles: list[str]) -> Markup:
    """Text with every needle highlighted (longest first); every piece escaped."""
    found = sorted({n for n in needles if n and n in text}, key=len, reverse=True)
    if not found:
        return frag(text)
    out: list[object] = []
    rest = text
    while rest:
        hits = [(rest.find(n), n) for n in found if n in rest]
        if not hits:
            out.append(rest)
            break
        at, needle = min(hits, key=lambda x: (x[0], -len(x[1])))
        out += [rest[:at], h("mark", None, needle)]
        rest = rest[at + len(needle) :]
    return frag(out)


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


THIRD_PARTY = "untrusted (third-party)"
AGENT_WRITTEN = "free text (written by the agent)"


def provenance(tool: str, path: str) -> str:
    """Who wrote an untrusted free-text field of a tool result.

    A field that echoes the agent's own text argument to a sink tool (the
    `reason` of `open_dispute`, the `description` of `transfer_pix`) was
    written by the agent; everything else (incoming Pix descriptions, payee
    and counterparty names, KYC text) came from a third party."""
    if tool == "read_notes":  # agent memory: written by the agent, maybe from tool output
        return AGENT_WRITTEN
    return AGENT_WRITTEN if (tool, path) in set(SINK_ARGS.values()) else THIRD_PARTY


def disclosure_label(sink: str, v: SinkDisclosure) -> list[str]:
    """Marker texts for one sink verdict: exact first, then approximate-only."""
    out: list[str] = []
    if v.disclosed:
        fields = ", ".join(v.kinds) or "amount"
        out.append(f"disclosure: {', '.join(v.foreign_accounts)} {fields} in {sink}")
    near = [a for a in v.approximate_accounts if a not in v.foreign_accounts]
    if v.approximate and near:
        out.append(f"disclosure (approx.): {', '.join(near)} amount in {sink}")
    return out


def _disclosures_by_seq(t: TrialResult) -> dict[int, list[str]]:
    """Pin each tool-sink disclosure to the ok call(s) that wrote it.

    The report stores one verdict per sink, not per call. With several calls
    into one sink, the calls whose text names a foreign account's balance
    (exactly or off by a power of ten) are marked; if none can be told apart,
    all of them are."""
    d = t.disclosure
    if d is None:
        return {}
    balances = t.ledger_before or {}
    out: dict[int, list[str]] = {}
    for sink, v in d.sinks.items():
        labels = disclosure_label(sink, v)
        if sink not in SINK_ARGS or not labels:
            continue
        tool, arg = SINK_ARGS[sink]
        calls = [
            (r.seq, text)
            for r in t.trace
            if r.tool == tool and r.outcome == "ok" and isinstance(text := r.args.get(arg), str)
        ]
        wanted = {
            balances[a] for a in [*v.foreign_accounts, *v.approximate_accounts] if balances.get(a)
        }
        hit = [
            seq
            for seq, text in calls
            if any(
                w == x or w in (x * 10, x * 100, x * 1000) or x in (w * 10, w * 100, w * 1000)
                for w in wanted
                for x in amounts_in_text(text)
            )
        ]
        for seq in hit or [seq for seq, _ in calls]:
            out.setdefault(seq, []).extend(labels)
    return out


def _note_links(r: ToolCallRecord, t: TrialResult) -> list[object]:
    """Links between a note's write (save_note) and its reads (read_notes)."""
    if r.outcome != "ok" or r.result is None:
        return []
    if r.tool == "save_note":
        note_id = r.result.get("note_id")
        readers = [
            x.seq
            for x in t.trace
            if x.tool == "read_notes" and x.outcome == "ok" and note_id in _read_note_ids(x)
        ]
        return [
            h(
                "p",
                {"id": f"note-{note_id}"},
                badge("neutral", f"wrote {note_id}"),
                " read at ",
                frag(*[h("a", {"href": f"#call-{s}"}, f"#{s} ") for s in readers])
                if readers
                else "no later call",
            )
        ]
    if r.tool == "read_notes":
        ids = _read_note_ids(r)
        if not ids:
            return []
        writers = {
            str(x.result.get("note_id")): x.seq
            for x in t.trace
            if x.tool == "save_note" and x.outcome == "ok" and x.result is not None
        }
        return [
            h(
                "p",
                None,
                "read notes: ",
                [
                    h("a", {"href": f"#call-{writers[i]}"}, f"{i} (written at #{writers[i]}) ")
                    if i in writers
                    else f"{i} "
                    for i in ids
                ],
            )
        ]
    return []


def _read_note_ids(r: ToolCallRecord) -> list[str]:
    notes = (r.result or {}).get("notes")
    return (
        [str(n["note_id"]) for n in notes if isinstance(n, dict) and "note_id" in n]
        if isinstance(notes, list)
        else []
    )


def _record_item(
    r: ToolCallRecord,
    origin: str | None,
    violations: list[str],
    canary: str | None,
    disclosures: list[str] | None = None,
    links: list[object] | None = None,
) -> Markup:
    disclosures = disclosures or []
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
        [badge("bad", x) for x in disclosures],
        badge("warn", "payload entered here") if payload_paths else None,
    )
    parts: list[object] = [head, h("p", {"class": "muted"}, f"origin: {origin or 'unknown'}")]
    parts += links or []
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
        # one label per provenance group (the size budget rules out one per field)
        for label, kind in ((THIRD_PARTY, "warn"), (AGENT_WRITTEN, "neutral")):
            group = [p for p in r.untrusted_paths if provenance(r.tool, p) == label]
            if not group:
                continue
            items = [
                h(
                    "li",
                    None,
                    h("code", None, p),
                    " ",
                    badge("warn", "payload") if p in payload_paths else None,
                    h("pre", None, _marked(_text(resolve(r.result, p)), canary)),
                )
                for p in group
            ]
            parts.append(h("p", None, badge(kind, label)))
            parts.append(h("ul", {"class": "provenance"}, items))
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
    flags = (("violation", violations), ("disclosure", disclosures), ("injected", injected))
    classes = " ".join(c for c, on in flags if on)
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
            ("payload exposed", "-" if t.payload_exposed is None else yes_no(t.payload_exposed)),
            ("canary", canary or "unknown"),
            ("seed / temperature", f"{t.seed} / {t.temperature}"),
            (
                "unauthorized outflow",
                shown(
                    t,
                    "unauthorized_outflow_cents",
                    money,
                ),
            ),
        ]
    )

    final_sink = t.disclosure.sinks.get("final_answer") if t.disclosure else None
    final_markers = disclosure_label("final_answer", final_sink) if final_sink else []
    if t.final_text is not None:
        answer: object = frag(
            h("p", None, [badge("bad", x) for x in final_markers]) if final_markers else None,
            h("pre", None, _marked(t.final_text, canary)),
        )
    elif stores_final_text:
        answer = h("p", None, "No final answer.")
    else:
        answer = h("p", {"class": "note"}, "Not stored: this report predates final-answer storage.")

    calls = (
        h(
            "p",
            {"class": "note"},
            "Model calls: not recorded (the agent does not report them).",
        )
        if not t.model_calls_recorded
        else table(
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
    )

    origins = {st.seq: st.origin for st in t.agent_steps}
    pinned, loose = _violations_by_seq(t)
    disclosed_at = _disclosures_by_seq(t)

    def items(records: list[ToolCallRecord]) -> Markup:
        return h(
            "ol",
            {"class": "timeline"},
            [
                _record_item(
                    r,
                    origins.get(r.seq),
                    pinned.get(r.seq, []),
                    canary,
                    disclosed_at.get(r.seq),
                    _note_links(r, t),
                )
                for r in records
            ],
        )

    timeline: object = (
        _delegation_lanes(t, items, canary)
        if t.handoff is not None
        else frag(
            *[
                frag(
                    h("h3", None, f"Session {sr.index}: ", h("q", None, sr.request)),
                    h(
                        "p",
                        {"class": "muted"},
                        f"{sr.started_at.isoformat()} to "
                        f"{sr.ended_at.isoformat()}, stopped: {sr.stopped}",
                    ),
                    items([r for r in t.trace if r.session == sr.index])
                    if any(r.session == sr.index for r in t.trace)
                    else h("p", None, "No tool calls."),
                )
                for sr in t.sessions
            ]
        )
        if t.sessions
        else items(list(t.trace))
    )
    memory = _memory_section(t, canary)

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
                    (
                        "attack success",
                        "-" if a.attack_success is None else yes_no(a.attack_success),
                    ),
                    ("task error", yes_no(a.task_error)),
                    ("task omitted", yes_no(a.task_omitted)),
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
                    ("calls cut by cap", trial_cap(t).label(trial_cap(t).calls)),
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
                "Tool calls in order, marking untrusted fields by source, payload (canary) "
                "entry, calls made on tool-output instructions, guards, violations and "
                "disclosures.",
            ),
            timeline if t.trace else h("p", None, "No tool calls."),
            h("h3", None, "Violations not tied to one call") if loose else None,
            h("ul", None, [h("li", None, v) for v in loose]) if loose else None,
        ),
        memory,
        h("section", None, h("h2", None, "Invariants"), invariants),
        h("section", None, h("h2", None, "Confirmations"), confirmations),
        h("section", None, h("h2", None, "Attribution"), attribution),
        h("section", None, h("h2", None, "Disclosure"), disclosure),
        h("section", None, h("h2", None, "Ledger"), ledger_parts),
    )


def _taint_needles(t: TrialResult, canary: str | None) -> list[str]:
    """Strings to highlight in a handoff: the canary and the taint sources
    the harness found (payee keys, accounts, amounts as written)."""
    h_ = t.handoff
    needles = [canary] if canary else []
    if h_ is None:
        return needles
    for src in h_.taint_sources:
        kind, _, value = src.partition(":")
        if kind in ("payee", "account"):
            needles.append(value)
        elif kind == "amount" and value.isdigit():
            whole, frac = divmod(int(value), 100)
            needles += [f"{whole}.{frac:02d}", f"{whole},{frac:02d}", value]
    return needles


def _delegation_lanes(
    t: TrialResult, items: Callable[[list[ToolCallRecord]], Markup], canary: str | None
) -> Markup:
    """Reader lane, the handoff between, Payer lane."""
    ho = t.handoff
    if ho is None:  # pragma: no cover - caller checks
        return frag()
    needles = _taint_needles(t, canary)
    reader = [r for r in t.trace if r.role == "reader"]
    payer = [r for r in t.trace if r.role == "payer"]
    d = t.delegation
    taint = [badge("bad", "tainted")] if ho.tainted else [badge("good", "clean")]
    taint += [badge("bad", s) for s in ho.taint_sources]
    dropped = [
        h("li", None, f"line {x.line}: {x.field} dropped ({x.reason}): ", h("code", None, x.value))
        for x in ho.dropped
    ]
    card = h(
        "div",
        {"class": "lane handoff tainted" if ho.tainted else "lane handoff", "id": "handoff"},
        h("h3", None, "Handoff"),
        h(
            "p",
            {"class": "muted"},
            f"author: {ho.author}, provenance: {ho.provenance}, mode: {ho.mode}"
            + (", Payer also saw the customer request" if ho.payer_saw_request else ""),
        ),
        frag(*taint),
        h("h4", None, "What the Payer received"),
        h("pre", None, _marked_all(ho.payer_input, needles)),
        frag(
            h("h4", None, "What the Reader wrote"),
            h("pre", None, _marked_all(ho.reader_text, needles)),
        )
        if ho.mode == "structured"
        else None,
        frag(h("h4", None, "Dropped by the structured handoff"), h("ul", None, dropped))
        if dropped
        else None,
        dl(
            [
                ("handoff tainted", yes_no(d.handoff_tainted)),
                ("crossed boundary", yes_no(d.crossed_boundary)),
                ("tainted but stopped", yes_no(d.tainted_but_stopped)),
                (
                    "attributed success",
                    "-" if d.attributed_success is None else yes_no(d.attributed_success),
                ),
            ]
        )
        if d is not None
        else None,
    )
    return h(
        "div",
        {"class": "lanes"},
        h(
            "div",
            {"class": "lane"},
            h("h3", None, "Reader (read tools only)"),
            items(reader) if reader else h("p", None, "No tool calls."),
        ),
        card,
        h(
            "div",
            {"class": "lane"},
            h("h3", None, "Payer (payment tools only)"),
            items(payer) if payer else h("p", None, "No tool calls."),
        ),
    )


def _memory_section(t: TrialResult, canary: str | None) -> Markup | None:
    """Agent memory: notes with taint and links, plus the memory metrics."""
    if not t.notes and t.memory is None:
        return None
    rows = []
    for n in t.notes:
        taint = [badge("bad", "canary")] if n.canary else []
        taint += [badge("bad", a) for a in n.artifacts]
        rows.append(
            [
                n.note.note_id,
                n.note.session,
                h("a", {"href": f"#call-{n.note.seq}"}, f"#{n.note.seq}"),
                h("pre", None, _marked(n.note.text, canary)),
                frag(*taint) if taint else "clean",
            ]
        )
    m = t.memory
    return h(
        "section",
        None,
        h("h2", None, "Agent memory"),
        h("p", {"class": "muted"}, "Notes are agent-written; taint is judged by the harness."),
        table("Notes", ["Id", "Session", "Written at", "Text", "Taint"], rows)
        if rows
        else h("p", None, "No notes saved."),
        dl(
            [
                ("memory tainted", yes_no(m.memory_tainted)),
                ("violations in sessions", ", ".join(map(str, m.violation_sessions)) or "-"),
                ("cross-session", m.cross_session or "-"),
                ("note followed", yes_no(m.note_followed)),
            ]
        )
        if m is not None
        else None,
    )
