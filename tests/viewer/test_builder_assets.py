"""HTML builder escapes everything; assets meet the CSP and contrast rules."""

from __future__ import annotations

import base64
import hashlib
import re

import pytest

from mulebench.viewer.assets import CSP, CSS, JS, PALETTE, TEXT_PAIRS, UI_PAIRS, contrast
from mulebench.viewer.html import Markup, esc, frag, h

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'


def test_text_and_attributes_are_escaped() -> None:
    out = h("p", {"title": EVIL, "class": "x"}, EVIL)
    assert "<script" not in out
    assert "<img" not in out
    assert out.count("&lt;script&gt;") == 2
    assert '"&gt;' not in out.split(">", 1)[0] or "&quot;" in out


def test_nested_children_and_markup() -> None:
    out = h("ul", None, [h("li", None, "a&b"), None, False, [h("li", None, 3)]])
    assert out == "<ul><li>a&amp;b</li><li>3</li></ul>"
    assert frag("<b>", h("i")) == "&lt;b&gt;<i></i>"
    assert isinstance(out, Markup)


@pytest.mark.parametrize("name", ["onclick", "onerror", "style", "srcdoc", "x y", "A"])
def test_dangerous_attribute_names_rejected(name: str) -> None:
    with pytest.raises(ValueError, match=r"not allowed|bad"):
        h("a", {name: "1"})


@pytest.mark.parametrize(
    "href",
    ["javascript:alert(1)", "https://example.test/", "//evil", "/abs", "data:text/html,x", "a b"],
)
def test_only_relative_slug_links(href: str) -> None:
    with pytest.raises(ValueError, match="unsafe link"):
        h("a", {"href": href}, "x")
    assert h("a", {"href": "../r1/cell/a--b.html#t3"}, "ok").startswith('<a href="../r1')


def test_bad_tag_and_void_children_rejected() -> None:
    with pytest.raises(ValueError, match="bad tag"):
        h("scr ipt")
    with pytest.raises(ValueError, match="void"):
        h("br", None, "x")
    with pytest.raises(TypeError):
        h("p", None, object())


def test_esc_quotes() -> None:
    assert esc("'\"<>&") == "&#x27;&quot;&lt;&gt;&amp;"


def _sha(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def test_csp_allows_exactly_the_inline_assets() -> None:
    assert f"style-src 'sha256-{_sha(CSS)}'" in CSP
    assert f"script-src 'sha256-{_sha(JS)}'" in CSP
    assert "default-src 'none'" in CSP
    assert "unsafe" not in CSP
    assert "http" not in CSP


def test_script_has_no_dangerous_sinks() -> None:
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval",
        "Function(",
        "document.write",
        "setTimeout",
        "setInterval",
        "http",
    ):
        assert sink not in JS
    assert "http" not in CSS
    assert not re.search(r"url\(", CSS)


@pytest.mark.parametrize("theme", [0, 1])
def test_palette_contrast(theme: int) -> None:
    for fg, bg in TEXT_PAIRS:
        ratio = contrast(PALETTE[fg][theme], PALETTE[bg][theme])
        assert ratio >= 4.5, (theme, fg, bg, round(ratio, 2))
    for fg, bg in UI_PAIRS:
        assert contrast(PALETTE[fg][theme], PALETTE[bg][theme]) >= 3.0, (theme, fg, bg)
