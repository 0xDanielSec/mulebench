"""Site generation from the committed pilot reports: links, CSP, determinism."""

from __future__ import annotations

import html
import posixpath
import re
from functools import cache
from pathlib import Path

import pytest

from mulebench.harness.models import Report
from mulebench.viewer.assets import CSP
from mulebench.viewer.site import ViewerInputError, build_site, load_any, write_site

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "docs" / "experiments" / "data"
# run reports only: the viewer does not read workload reports (`mulebench workloads`)
PILOTS = sorted(p for p in DATA.glob("pilot-*.json") if not p.stem.endswith("-workload"))
HREF = re.compile(r'href="([^"]*)"')
ID = re.compile(r'id="([^"]*)"')
# A URL the browser would fetch or follow: in an attribute value or a CSS url().
# Escaped model text may mention a URL (a model wrote a markdown link to a
# synthetic example.test page in pilot 08); that is text, not a reference.
NETWORK_REF = re.compile(r"""(?:=\s*["']?|url\(\s*["']?)(?:https?:)?//""", re.IGNORECASE)


@cache
def pilot_site() -> dict[str, str]:
    return build_site([(p.stem, load_any(p)) for p in PILOTS])


def check_links(files: dict[str, str]) -> None:
    ids = {path: set(ID.findall(text)) for path, text in files.items()}
    for path, text in files.items():
        for raw in HREF.findall(text):
            href = html.unescape(raw)
            target, _, frag = href.partition("#")
            resolved = (
                posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
                if target
                else path
            )
            assert resolved in files, f"{path}: broken link {href}"
            if frag:
                assert frag in ids[resolved], f"{path}: missing anchor {href}"


def test_pilot_reports_generate_a_linked_site() -> None:
    files = pilot_site()
    assert "index.html" in files
    assert {"r1/index.html", "r2/index.html", "r3/index.html"} <= set(files)
    check_links(files)


def test_every_cell_has_a_page() -> None:
    files = pilot_site()
    for i, p in enumerate(PILOTS, start=1):
        report = load_any(p)
        assert isinstance(report, Report)
        cells = sum(len(s.cells) for s in report.scenarios)
        assert len([f for f in files if f.startswith(f"r{i}/cell/")]) == cells


def test_every_page_has_the_csp_and_no_network_reference() -> None:
    for path, text in pilot_site().items():
        assert text.startswith("<!DOCTYPE html>"), path
        assert f'content="{html.escape(CSP, quote=True)}"' in text, path
        assert not NETWORK_REF.search(text), path
        assert text.count("<script") == 1, path


def test_network_reference_pattern() -> None:
    assert NETWORK_REF.search('<a href="https://x.example.test/">')
    assert NETWORK_REF.search("<img src=//x.example.test/a.png>")
    assert NETWORK_REF.search("background: url('http://x.example.test/a')")
    assert not NETWORK_REF.search("<p>see [link](https://x.example.test/t)</p>")


def test_output_is_deterministic() -> None:
    again = build_site([(p.stem, load_any(p)) for p in PILOTS])
    assert again == pilot_site()


def test_write_site_refuses_non_empty_dir(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ViewerInputError, match="not empty"):
        write_site({"index.html": "a"}, tmp_path)
    write_site({"index.html": "a", "r1/index.html": "b"}, tmp_path, force=True)
    assert (tmp_path / "r1" / "index.html").read_text(encoding="utf-8") == "b"


def test_load_any_rejects_non_reports(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ViewerInputError):
        load_any(bad)
    bad.write_text('{"schema_version": 99}', encoding="utf-8")
    with pytest.raises(ViewerInputError):
        load_any(bad)
