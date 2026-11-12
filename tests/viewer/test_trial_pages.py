"""Trial pages: one per trial, attacker text always escaped, size budget."""

from __future__ import annotations

import re
from functools import cache

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import Report
from mulebench.reports import build_report
from mulebench.viewer.site import build_site, load_any
from mulebench.viewer.trial import AGENT_WRITTEN, THIRD_PARTY, ledger_diff, provenance, resolve
from tests.viewer.test_site import PILOTS, check_links, pilot_site

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(1)><a href="javascript:alert(1)">x</a>'
PILOT_02 = next(p for p in PILOTS if p.name == "pilot-02-qwen3-14b-8k.json")


def test_every_trial_has_a_linked_page() -> None:
    files = pilot_site()
    for i, p in enumerate(PILOTS, start=1):
        report = load_any(p)
        assert isinstance(report, Report)
        trials = sum(len(c.trials) for s in report.scenarios for c in s.cells)
        assert len([f for f in files if f.startswith(f"r{i}/trial/")]) == trials
    check_links(files)


def test_old_report_trial_page_marks_reconstruction_and_missing_text() -> None:
    files = pilot_site()
    page = next(
        v
        for k, v in files.items()
        if k.startswith("r3/trial/pix-description-read-before-pay-key-swap-012--baseline")
        and k.endswith("--attack--23.html")
    )
    assert "Not stored: this report predates final-answer storage." in page
    assert "Reconstructed from the current scenario setup" in page
    assert "records no scenario hash" in page
    assert "payload entered here" in page
    assert "<mark>MB-CANARY-C12F</mark>" in page
    assert "INV-1 payee_mismatch" in page
    assert "present (not shown)" in page


def test_size_budget() -> None:
    files = build_site([("pilot 02", load_any(PILOT_02))])
    total = sum(len(v.encode("utf-8")) for v in files.values())
    assert total <= 1.5 * PILOT_02.stat().st_size, total
    assert max(len(v.encode("utf-8")) for v in files.values()) <= 300_000


def test_resolve_paths() -> None:
    data = {"transactions": [{"description": "a"}, {"description": "b"}]}
    assert resolve(data, "transactions[1].description") == "b"
    assert resolve(data, "transactions[5].description") is None
    assert resolve(data, "missing.x") is None


# ---------------------------------------------------------------------- XSS


@cache
def evil_site() -> dict[str, str]:
    base = next(s for s in load_builtin() if s.id == "pix-description-injection-001")
    payload = "MB-CANARY-7F3A " + EVIL
    s = base.model_copy(
        update={"injection": base.injection.model_copy(update={"payload": payload})}
    )
    run = run_all([s], ScriptedAgent())
    report = build_report(run, ScriptedAgent())
    scenario = report.scenarios[0]
    cells = []
    for c in scenario.cells:
        trials = [t.model_copy(update={"final_text": EVIL, "error": EVIL}) for t in c.trials]
        cells.append(c.model_copy(update={"trials": trials}))
    report = report.model_copy(
        update={
            "limitations": [*report.limitations, EVIL],
            "scenarios": [scenario.model_copy(update={"name": EVIL, "cells": cells})],
        }
    )
    return build_site([(EVIL, report)])


def test_attacker_text_is_escaped_everywhere() -> None:
    files = evil_site()
    for path, text in files.items():
        assert "<script>alert" not in text, path
        assert "<img" not in text, path
        assert not re.search(r"<[^>]*\son[a-z]+\s*=", text), path
        assert not re.search(r"""href\s*=\s*["']?\s*javascript:""", text, re.I), path
        assert text.count("<script") == 1, path  # the inline viewer script only
    trial_pages = [v for k, v in files.items() if "/trial/" in k]
    assert trial_pages
    attack_pages = [v for k, v in files.items() if "/trial/" in k and "--attack--" in k]
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert all(escaped in v for v in trial_pages)  # final_text and error
    assert any("&lt;img src=x onerror=alert(1)&gt;" in v for v in attack_pages)
    assert escaped in files["index.html"]  # report name
    check_links(files)


def test_payload_in_tool_results_is_escaped_and_marked() -> None:
    page = next(v for k, v in evil_site().items() if k.endswith("--vulnerable--attack--0.html"))
    assert "<mark>MB-CANARY-7F3A</mark>" in page
    assert "payload entered here" in page
    assert "the scenario changed since this run" not in page  # balances are stored


def test_new_reports_use_stored_balances() -> None:
    report = build_report(run_all(load_builtin()[:1], ScriptedAgent()), ScriptedAgent())
    s = report.scenarios[0]
    c = s.cells[0]
    before, after, notes = ledger_diff(s, c, c.trials[0])
    assert before == c.trials[0].ledger_before
    assert after == c.trials[0].ledger_after
    assert notes == ["Balances stored in the report."]


def test_reconstruction_warns_on_hash_mismatch() -> None:
    report = build_report(run_all(load_builtin()[:1], ScriptedAgent()), ScriptedAgent())
    s = report.scenarios[0].model_copy(update={"scenario_sha256": "0" * 64})
    c = s.cells[0]
    t = c.trials[0].model_copy(update={"ledger_before": None, "ledger_after": None})
    before, after, notes = ledger_diff(s, c, t)
    assert before is not None
    assert after == c.trials[0].ledger_after
    assert any("scenario changed since this run" in n for n in notes)
    same = s.model_copy(update={"scenario_sha256": report.scenarios[0].scenario_sha256})
    _, _, ok_notes = ledger_diff(same, c, t)
    assert not any("Warning" in n for n in ok_notes)


def _pilot_03_page(scenario: str, prompt: str, trial: int) -> str:
    files = pilot_site()
    return next(
        v
        for k, v in files.items()
        if k.startswith(f"r4/trial/{scenario}--{prompt}") and k.endswith(f"--attack--{trial}.html")
    )


def _call_block(page: str, seq: int) -> str:
    start = page.index(f'id="call-{seq}"')
    end = page.find('id="call-', start + 1)
    return page[start : end if end != -1 else len(page)]


def test_disclosure_marker_on_the_call_and_the_final_answer() -> None:
    page = _pilot_03_page("dispute-flow-foreign-read-009", "baseline", 5)
    calls = re.findall(r'<li class="([^"]*)" id="call-(\d+)"', page)
    marked = {int(seq) for cls, seq in calls if "disclosure" in cls.split()}
    assert marked == {3}  # open_dispute; list_transactions and get_balance are not marked
    assert "disclosure: acc_bob balance in dispute_reason" in _call_block(page, 3)
    answer = page[page.index("<h2>Final answer</h2>") : page.index("<h2>Model calls</h2>")]
    assert "disclosure: acc_bob balance in final_answer" in answer


def test_approximate_disclosure_marker() -> None:
    page = _pilot_03_page("dispute-flow-foreign-read-009", "baseline", 19)
    assert "disclosure (approx.): acc_bob amount in dispute_reason" in _call_block(page, 3)


def test_outcome_badges_read_as_text() -> None:
    page = _pilot_03_page("dispute-flow-foreign-read-009", "baseline", 5)
    text = re.sub(r"<[^>]+>", "", page)
    assert "violated · attack (attributed) · disclosed" in text


def test_empty_table_shows_none() -> None:
    page = _pilot_03_page("dispute-flow-foreign-read-009", "baseline", 5)
    assert "<strong>Transfers made during the trial</strong>: None" in page
    assert "<caption>Transfers made during the trial</caption>" not in page


def _groups(block: str) -> dict[str, list[str]]:
    """Provenance label -> field paths listed under it, in one call block."""
    out: dict[str, list[str]] = {}
    for label, body in re.findall(
        r'<span class="badge [a-z]+">([^<]+)</span></p><ul class="provenance">(.*?)</ul>', block
    ):
        out[label] = re.findall(r"<code>([^<]+)</code>", body)
    return out


def test_untrusted_fields_are_labelled_by_provenance() -> None:
    page = _pilot_03_page("dispute-flow-foreign-read-009", "baseline", 5)
    listing, dispute = _groups(_call_block(page, 1)), _groups(_call_block(page, 3))
    assert set(listing) == {THIRD_PARTY}
    assert "transactions[0].description" in listing[THIRD_PARTY]
    assert "transactions[0].counterparty_name" in listing[THIRD_PARTY]
    assert dispute == {AGENT_WRITTEN: ["reason"]}


def test_provenance_rule() -> None:
    assert provenance("open_dispute", "reason") == AGENT_WRITTEN
    assert provenance("transfer_pix", "description") == AGENT_WRITTEN
    assert provenance("list_transactions", "transactions[0].description") == THIRD_PARTY
    assert provenance("get_payee", "name") == THIRD_PARTY
