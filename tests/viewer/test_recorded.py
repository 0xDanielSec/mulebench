"""Missing metrics render as "not recorded" or as labelled derived values, never as 0."""

from __future__ import annotations

import html
import json
import re
from functools import cache

from mulebench.agents import ScriptedAgent
from mulebench.attacks import load_builtin
from mulebench.harness import run_all
from mulebench.harness.models import Report
from mulebench.reports import build_report
from mulebench.reports.reader import parse_report
from mulebench.viewer.recorded import NOT_RECORDED, cell_cap, report_cap, trial_cap
from mulebench.viewer.site import build_site, load_any
from tests.viewer.test_site import pilot_site
from tests.viewer.test_trial_pages import PILOT_02

DERIVED = "derived from stop reasons"


def dd(page: str, label: str) -> list[str]:
    pattern = rf"<dt>{re.escape(html.escape(label, quote=True))}</dt><dd>(.*?)</dd>"
    return [html.unescape(re.sub(r"<[^>]+>", "", m)) for m in re.findall(pattern, page)]


# ------------------------------------------------------------ output cap


def test_pilot02_cap_cuts_are_derived_from_stop_reasons() -> None:
    report = load_any(PILOT_02)
    assert isinstance(report, Report)
    cap = report_cap(report)
    assert (cap.calls, cap.derived) == (30, True)
    s009 = next(s for s in report.scenarios if s.scenario_id.endswith("009"))
    assert sum(cell_cap(c).calls for c in s009.cells) == 28


def test_pilot02_pages_show_derived_counts_not_zero() -> None:
    files = pilot_site()
    assert dd(files["r3/index.html"], "model calls cut at max_tokens") == [f"30 ({DERIVED})"]
    # Pilot 02 write-up: 009 attack 18, 009 benign 10 (summed over both prompts).
    for variant, expected in (("attack", 18), ("benign", 10)):
        total = 0
        names = [
            k
            for k in files
            if k.startswith("r3/cell/dispute-flow-foreign-read-009--")
            and k.endswith(f"--vulnerable--{variant}.html")
        ]
        assert len(names) == 2  # baseline and data_not_instructions
        for name in names:
            (value,) = dd(files[name], "model calls cut at max_tokens")
            assert value.endswith(f" ({DERIVED})")
            total += int(value.split()[0])
        assert total == expected
    for path, page in files.items():
        if not path.startswith("r3/"):
            continue
        for label in ("model calls cut at max_tokens", "trials cut by cap", "calls cut by cap"):
            for value in dd(page, label):
                assert DERIVED in value, (path, label, value)


def test_new_reports_use_stored_cap_fields() -> None:
    report = build_report(run_all(load_builtin()[:1], ScriptedAgent()), ScriptedAgent())
    t = report.scenarios[0].cells[0].trials[0]
    assert trial_cap(t).derived is False
    assert report_cap(report).derived is False
    files = build_site([("new", report)])
    assert all(DERIVED not in v for v in files.values())


# ------------------------------------------------ general rule: not recorded


@cache
def stripped_site() -> dict[str, str]:
    report = build_report(run_all(load_builtin()[:3], ScriptedAgent()), ScriptedAgent())
    data = json.loads(report.model_dump_json())
    optional_trial = (
        "length_calls",
        "cut_by_cap",
        "context_near_limit",
        "unauthorized_outflow_cents",
        "attribution",
        "disclosure",
        "final_text",
        "ledger_before",
        "ledger_after",
    )
    optional_cell = (
        "length_calls",
        "cut_by_cap_trials",
        "context_near_limit",
        "tool_calls_per_trial",
        "unauthorized_outflow_cents",
        "tool_call_validity",
    )
    optional_agg = (
        "disclosure",
        "disclosure_by_sink",
        "disclosure_approximate",
        "disclosure_approximate_by_sink",
        "attributed_success",
        "task_error",
        "task_omitted",
        "benign_pass",
    )
    for key in ("length_calls", "cut_by_cap_trials", "context_near_limit"):
        data["summary"]["totals"].pop(key, None)
    for s in data["scenarios"]:
        s.pop("scenario_sha256", None)
        for c in s["cells"]:
            for k in optional_cell:
                c.pop(k, None)
            for agg in ("attack", "benign"):
                if c[agg]:
                    for k in optional_agg:
                        c[agg].pop(k, None)
            for t in c["trials"]:
                for k in optional_trial:
                    t.pop(k, None)
                for m in t["model_calls"]:
                    m["stop_reason"] = m.get("stop_reason")
    return build_site([("old", parse_report(data))])


def test_missing_metrics_render_as_not_recorded() -> None:
    files = stripped_site()
    cells = [v for k, v in files.items() if "/cell/" in k]
    assert cells
    for page in cells:
        for label in (
            "unauthorized outflow",
            "context near limit (trials)",
            "tool calls per trial",
            "tool-call validity",
        ):
            assert dd(page, label) == [NOT_RECORDED], label
    attack = [v for k, v in files.items() if "/cell/" in k and k.endswith("--attack.html")]
    for page in attack:
        for label in ("disclosure (approx.)", "refusal"):
            values = dd(page, label)
            assert values, label
        assert dd(page, "disclosure (approx.)") == [NOT_RECORDED]
    trials = [v for k, v in files.items() if "/trial/" in k]
    for page in trials:
        assert dd(page, "unauthorized outflow") == [NOT_RECORDED]


def test_no_missing_metric_renders_as_a_bare_zero() -> None:
    for path, page in stripped_site().items():
        for label in (
            "unauthorized outflow",
            "context near limit (trials)",
            "tool calls per trial",
            "model calls cut at max_tokens",
            "trials cut by cap",
            "calls cut by cap",
        ):
            for value in dd(page, label):
                assert not re.fullmatch(r"(R\$ )?0(\.00)?", value), (path, label, value)


# ---------------------------------------------------------------- booleans


def test_booleans_render_as_yes_no() -> None:
    import pytest

    from mulebench.viewer.html import h

    for files in (pilot_site(), stripped_site()):
        for path, page in files.items():
            text = re.sub(r"<[^>]+>", " ", page)
            assert not re.search(r"\b(True|False)\b", text), path
    with pytest.raises(TypeError, match="yes_no"):
        h("p", None, True)
