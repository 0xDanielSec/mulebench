"""A tiny HTML builder that escapes everything.

Report text is attacker-controlled (payloads travel through tool results,
arguments and final answers), so the viewer never concatenates HTML by hand.
`h()` escapes every text child and every attribute value; only `Markup`
values, which the builder itself produces, pass through unescaped. Attribute
names are checked (no `on*` handlers, no `style`), and `href` accepts only
relative links built from the viewer's own slugs.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping

_ATTR_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_FORBIDDEN_ATTRS = frozenset({"style", "srcdoc", "formaction"})
# Relative links only: slugs, dots, slashes and fragments. No scheme, no colon,
# no leading slash (absolute or protocol-relative).
_SAFE_HREF = re.compile(r"^(?!/)[A-Za-z0-9._/#-]*$")  # no "/x" or "//host"
_VOID = frozenset({"meta", "link", "br", "hr", "input", "img"})


class Markup(str):
    """HTML produced by this builder. Never construct it from report data."""

    __slots__ = ()


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _render_children(children: Iterable[object]) -> str:
    out: list[str] = []
    for child in children:
        if child is None or child is False:
            continue
        if isinstance(child, Markup):
            out.append(child)
        elif isinstance(child, str | int | float):
            out.append(esc(child))
        elif isinstance(child, Iterable):
            out.append(_render_children(child))
        else:
            raise TypeError(f"unsupported child type: {type(child).__name__}")
    return "".join(out)


def h(tag: str, attrs: Mapping[str, object] | None = None, *children: object) -> Markup:
    """`<tag attrs>children</tag>` with everything escaped.

    Attribute values of None or False are dropped, True renders a bare
    attribute.
    """
    if not _ATTR_NAME.match(tag):
        raise ValueError(f"bad tag {tag!r}")
    parts = [tag]
    for name, value in (attrs or {}).items():
        if not _ATTR_NAME.match(name) or name.startswith("on") or name in _FORBIDDEN_ATTRS:
            raise ValueError(f"attribute not allowed: {name!r}")
        if value is None or value is False:
            continue
        if value is True:
            parts.append(name)
            continue
        text = str(value)
        if name in ("href", "src", "action") and not _SAFE_HREF.match(text):
            raise ValueError(f"unsafe link: {text!r}")
        parts.append(f'{name}="{esc(text)}"')
    open_tag = "<" + " ".join(parts) + ">"
    if tag in _VOID:
        if children:
            raise ValueError(f"void element {tag!r} takes no children")
        return Markup(open_tag)
    return Markup(f"{open_tag}{_render_children(children)}</{tag}>")


def frag(*children: object) -> Markup:
    """Several children without a wrapping element."""
    return Markup(_render_children(children))
