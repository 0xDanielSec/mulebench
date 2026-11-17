"""Site generation from the committed pilot reports: links, CSP, determinism."""

from __future__ import annotations

import html
import posixpath
import re
from functools import cache
from html.parser import HTMLParser
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
# A URL the browser could fetch or follow: absolute or protocol-relative, at the
# start of a value or after a separator (srcset candidates, "0; url=..." in a
# meta refresh, CSS url(...) or @import "..."). Checked in every attribute value
# and in <style> / <script> text. Escaped page text may mention a URL (a model
# wrote a markdown link to a synthetic example.test page in pilot 08): that is
# text, not a reference, and is not checked.
URL_IN_VALUE = re.compile(r"""(?:^|[\s,;=("'])(?:[a-z][a-z0-9+.-]*:)?//""", re.IGNORECASE)
RAW_URL = re.compile(r"""(?:[a-z][a-z0-9+.-]*:|[\s,;=("'])//[a-z0-9\[]""", re.IGNORECASE)


class _Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []
        self._raw: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value and URL_IN_VALUE.search(value.strip()):
                self.found.append(f"<{tag} {name}={value!r}>")
        self._raw = tag if tag in ("style", "script") else None

    def handle_endtag(self, tag: str) -> None:
        self._raw = None

    def handle_data(self, data: str) -> None:
        # a JS comment ("// note") is not a URL: require a host-like character
        if self._raw and RAW_URL.search(data):
            self.found.append(f"<{self._raw}> text")


def network_refs(page: str) -> list[str]:
    parser = _Refs()
    parser.feed(page)
    parser.close()
    return parser.found


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
        assert not network_refs(text), (path, network_refs(text))
        assert text.count("<script") == 1, path


@pytest.mark.parametrize(
    "page",
    [
        '<a href="https://x.example.test/">a</a>',
        "<img src=//x.example.test/a.png>",
        '<img srcset="a.png 1x, https://x.example.test/b.png 2x">',
        '<form action="https://x.example.test/f"></form>',
        '<button formaction="//x.example.test/f">b</button>',
        "<div style=\"background: url('http://x.example.test/a')\"></div>",
        '<meta http-equiv="refresh" content="0; url=https://x.example.test/">',
        '<object data="ftp://x.example.test/o"></object>',
        '<style>@import "https://x.example.test/a.css";</style>',
        "<style>p { background: url(//x.example.test/a) }</style>",
        "<script>fetch('https://x.example.test/')</script>",
    ],
)
def test_network_refs_finds_external_urls_in_any_attribute(page: str) -> None:
    assert network_refs(page), page


def test_network_refs_ignores_urls_in_escaped_text() -> None:
    page = "<p>see [link](https://x.example.test/t) &lt;a href=&quot;https://x&quot;&gt;</p>"
    assert network_refs(page) == []
    assert network_refs('<a href="r1/index.html#top">x</a><script>// note</script>') == []


def test_csp_allows_no_external_origin() -> None:
    directives = dict(d.strip().split(" ", 1) for d in CSP.split(";"))
    assert directives["default-src"] == "'none'"
    for name, sources in directives.items():
        for source in sources.split():
            assert source in ("'none'", "data:") or source.startswith("'sha256-"), (name, source)


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
