"""Build the static site: one directory per input report, all pages escaped.

Output is deterministic (no timestamps, report order preserved, files written
in sorted order) and self-contained: every page inlines its CSS and JS, links
are relative, and nothing is fetched at view time.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from mulebench.harness.models import Report
from mulebench.reports.ablation import AblationReport
from mulebench.reports.reader import parse_report
from mulebench.viewer.ablation_pages import ablation_page
from mulebench.viewer.common import page, table
from mulebench.viewer.html import h
from mulebench.viewer.run_pages import cell_href, cell_page, report_index, trial_href
from mulebench.viewer.trial import trial_page

AnyReport = Report | AblationReport


class ViewerInputError(ValueError):
    pass


def load_any(path: Path) -> AnyReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ViewerInputError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ViewerInputError(f"{path}: not a mulebench report")
    try:
        if data.get("kind") == "ablation":
            return AblationReport.model_validate(data)
        return parse_report(data)
    except ValueError as exc:
        raise ViewerInputError(f"{path}: not a mulebench report ({exc})") from exc


def build_site(inputs: Sequence[tuple[str, AnyReport]]) -> dict[str, str]:
    """Relative path -> page. `inputs` are (display name, report)."""
    files: dict[str, str] = {}
    links: list[tuple[str, str, str]] = []
    runs = ablations = 0
    for name, report in inputs:
        if isinstance(report, AblationReport):
            ablations += 1
            prefix = f"a{ablations}"
            links.append((name, "ablation", f"{prefix}/index.html"))
            files.update(_ablation_files(prefix, name, report))
        else:
            runs += 1
            prefix = f"r{runs}"
            links.append((name, "run", f"{prefix}/index.html"))
            files.update(_run_files(prefix, name, report))
    files["index.html"] = page(
        "mulebench reports",
        [("All reports", None)],
        table(
            "Reports",
            ["Report", "Kind"],
            [[h("a", {"href": href}, name), kind] for name, kind, href in links],
        ),
    )
    return dict(sorted(files.items()))


def _run_files(prefix: str, name: str, report: Report) -> dict[str, str]:
    files = {f"{prefix}/index.html": report_index(report, name)}
    # Reports that store balances also store the final answer (same release).
    stores_final_text = any(
        t.ledger_before is not None for s in report.scenarios for c in s.cells for t in c.trials
    )
    for s in report.scenarios:
        for c in s.cells:
            files[f"{prefix}/{cell_href(s, c)}"] = cell_page(name, s, c)
            for t in c.trials:
                files[f"{prefix}/{trial_href(s, c, t)}"] = trial_page(
                    name,
                    report,
                    s,
                    c,
                    t,
                    stores_final_text=stores_final_text,
                    cell_link=f"../{cell_href(s, c)}",
                )
    return files


def _ablation_files(prefix: str, name: str, report: AblationReport) -> dict[str, str]:
    return {f"{prefix}/index.html": ablation_page(report, name)}


def write_site(files: dict[str, str], out: Path, *, force: bool = False) -> None:
    if out.exists() and any(out.iterdir()) and not force:
        raise ViewerInputError(f"{out} is not empty (use --force to overwrite)")
    for rel, text in sorted(files.items()):
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
