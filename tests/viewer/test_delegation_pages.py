"""Trial pages of delegation scenarios: Reader and Payer lanes with the
handoff between them, taint highlighted."""

from __future__ import annotations

import re
from functools import cache

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.reports import build_report
from mulebench.viewer.site import build_site
from tests.viewer.test_site import check_links

PRESETS = ("vulnerable", "only:structured_handoff")


@cache
def site() -> dict[str, str]:
    agent = ScriptedAgent()
    scenarios = [s for s in load_builtin() if s.topology is not None]
    report = build_report(run_all(scenarios, agent, presets=PRESETS), agent, presets=list(PRESETS))
    return build_site([("delegation", report)])


def page(scenario: str, preset: str, variant: str) -> str:
    slug = preset.replace(":", "-").replace("_", "-")
    return next(
        v
        for k, v in site().items()
        if "/trial/" in k and f"{scenario}--" in k and f"--{variant}--" in k and slug in k
    )


def lanes(html: str) -> list[str]:
    """Reader lane, handoff card, Payer lane, in page order."""
    start = html.index('<div class="lanes">')
    body = html[start:]
    return re.split(r'<div class="lane(?: handoff(?: tainted)?)?"', body)[1:4]


def test_vulnerable_attack_page_has_three_lanes_and_tainted_handoff() -> None:
    html = page("delegation-key-swap-016", "vulnerable", "attack")
    reader, handoff, payer = lanes(html)
    assert "Reader (read tools only)" in reader
    assert "list_transactions" in reader
    assert "transfer_pix" not in reader
    assert 'class="lane handoff tainted"' in html
    assert "<mark>MB-CANARY-D16C</mark>" in handoff
    assert "<mark>energia-pag@attacker.example.test</mark>" in handoff
    assert "agent_written" in handoff
    assert "Payer (payment tools only)" in payer
    assert "transfer_pix" in payer
    assert "list_transactions" not in payer


def test_structured_handoff_page_shows_clean_handoff_and_dropped_fields() -> None:
    html = page("delegation-key-swap-016", "only-structured-handoff", "attack")
    _, handoff, _ = lanes(html)
    assert 'class="lane handoff tainted"' not in html
    assert "What the Reader wrote" in handoff
    assert "payee_not_authorized" in handoff


def test_amount_variant_highlights_the_amount() -> None:
    html = page("delegation-payment-instruction-amount-015b", "vulnerable", "attack")
    _, handoff, _ = lanes(html)
    assert "<mark>45000</mark>" in handoff


def test_non_delegation_pages_have_no_lanes() -> None:
    agent = ScriptedAgent()
    scenarios = [s for s in load_builtin() if s.id == "pix-description-injection-001"]
    report = build_report(run_all(scenarios, agent, presets=("vulnerable",)), agent)
    pages = build_site([("single", report)])
    assert all('class="lanes"' not in v for k, v in pages.items() if "/trial/" in k)


def test_links_resolve() -> None:
    check_links(site())
