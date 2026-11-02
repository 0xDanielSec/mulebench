"""Inline CSS and JS for the viewer, and the CSP that allows exactly them.

Every page inlines the same stylesheet and script; the Content-Security-Policy
meta tag allows them by sha256 and nothing else (no network, no eval, no
inline event handlers, no style attributes). The palette lives here as data so
a test can check the contrast of every text/background pair in both themes.
"""

from __future__ import annotations

import base64
import hashlib

# token -> (light, dark)
PALETTE: dict[str, tuple[str, str]] = {
    "bg": ("#ffffff", "#121417"),
    "surface": ("#f4f5f7", "#1c1f24"),
    "fg": ("#1a1a1a", "#e8e8e8"),
    "muted": ("#555555", "#a8adb4"),
    "border": ("#8a8f98", "#5c636c"),
    "link": ("#0b57d0", "#8ab4f8"),
    "focus": ("#b3261e", "#ffb4ab"),
    "bad-bg": ("#fde7e7", "#4a1c1c"),
    "bad-fg": ("#8a1010", "#ffd7d7"),
    "good-bg": ("#e3f4e6", "#173a22"),
    "good-fg": ("#155724", "#c8f0d2"),
    "warn-bg": ("#fff4d6", "#4a3a10"),
    "warn-fg": ("#6b4500", "#ffe7a3"),
    "info-bg": ("#e6eefc", "#1b2d4f"),
    "info-fg": ("#0b3d91", "#cfe0ff"),
    "neutral-bg": ("#eceef1", "#2a2e34"),
    "neutral-fg": ("#333333", "#e0e0e0"),
    "mark-bg": ("#fff0b3", "#5a4a00"),
}

# (foreground, background) pairs that carry text; each must reach 4.5:1.
TEXT_PAIRS: tuple[tuple[str, str], ...] = (
    ("fg", "bg"),
    ("fg", "surface"),
    ("muted", "bg"),
    ("muted", "surface"),
    ("link", "bg"),
    ("link", "surface"),
    ("bad-fg", "bad-bg"),
    ("good-fg", "good-bg"),
    ("warn-fg", "warn-bg"),
    ("info-fg", "info-bg"),
    ("neutral-fg", "neutral-bg"),
    ("fg", "mark-bg"),
)
# Non-text UI parts (focus ring, borders) need 3:1 against the background.
UI_PAIRS: tuple[tuple[str, str], ...] = (("focus", "bg"), ("border", "bg"))


def _vars(theme: int) -> str:
    return "".join(f"--{k}:{v[theme]};" for k, v in PALETTE.items())


CSS = (
    f":root{{{_vars(0)}color-scheme:light}}"
    f"@media (prefers-color-scheme: dark){{:root:not([data-theme=light]){{{_vars(1)}"
    "color-scheme:dark}}"
    f":root[data-theme=dark]{{{_vars(1)}color-scheme:dark}}"
    "*{box-sizing:border-box}"
    "body{margin:0;font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;"
    "background:var(--bg);color:var(--fg)}"
    "header,main,footer{padding:0 1.25rem;max-width:90rem;margin:0 auto}"
    "header{display:flex;flex-wrap:wrap;gap:1rem;align-items:center;"
    "justify-content:space-between;border-bottom:1px solid var(--border);padding-block:.5rem}"
    "a{color:var(--link)}"
    ":focus-visible{outline:3px solid var(--focus);outline-offset:2px}"
    ".skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;"
    "background:var(--bg);padding:.25rem .5rem;z-index:1}"
    "nav ol{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.25rem}"
    "nav li+li::before{content:'/';color:var(--muted);margin-right:.25rem}"
    "table{border-collapse:collapse;margin:.5rem 0 1.5rem;font-size:.9rem}"
    "caption{text-align:left;font-weight:600;padding:.25rem 0}"
    "th,td{border:1px solid var(--border);padding:.3rem .5rem;vertical-align:top;text-align:left}"
    "thead th{background:var(--surface)}"
    ".scroll{overflow-x:auto}"
    ".muted{color:var(--muted)}"
    ".badge{display:inline-block;border-radius:.6rem;padding:0 .5rem;margin:0 .2rem .2rem 0;"
    "font-size:.8rem;font-weight:600;border:1px solid currentColor}"
    ".bad{background:var(--bad-bg);color:var(--bad-fg)}"
    ".good{background:var(--good-bg);color:var(--good-fg)}"
    ".warn{background:var(--warn-bg);color:var(--warn-fg)}"
    ".info{background:var(--info-bg);color:var(--info-fg)}"
    ".neutral{background:var(--neutral-bg);color:var(--neutral-fg)}"
    "pre{background:var(--surface);color:var(--fg);padding:.5rem;overflow-x:auto;"
    "white-space:pre-wrap;word-break:break-word;font-size:.8rem;margin:.25rem 0}"
    "mark{background:var(--mark-bg);color:var(--fg)}"
    "dl{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1rem;margin:.5rem 0}"
    "dt{font-weight:600}dd{margin:0}"
    "ol.timeline{list-style:none;padding:0}"
    "ol.timeline>li{border-left:4px solid var(--border);padding:.25rem 0 .5rem .75rem;"
    "margin-bottom:.75rem}"
    "ol.timeline>li.violation{border-left-color:var(--bad-fg)}"
    "ol.timeline>li.injected{border-left-color:var(--warn-fg)}"
    ".note{border:1px solid var(--border);background:var(--surface);padding:.5rem .75rem;"
    "margin:.5rem 0}"
    "button,input{font:inherit;color:var(--fg);background:var(--surface);"
    "border:1px solid var(--border);padding:.2rem .5rem}"
    "td.num,th.num{text-align:right}"
)

JS = (
    "(function(){var r=document.documentElement;"
    "function g(){try{return localStorage.getItem('mb-theme')}catch(e){return null}}"
    "function s(v){try{localStorage.setItem('mb-theme',v)}catch(e){}}"
    "var t=g();if(t==='light'||t==='dark'){r.setAttribute('data-theme',t)}"
    "var b=document.getElementById('theme-toggle');"
    "if(b){b.hidden=false;b.addEventListener('click',function(){"
    "var c=r.getAttribute('data-theme')||"
    "(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');"
    "var n=c==='dark'?'light':'dark';r.setAttribute('data-theme',n);s(n);"
    "b.setAttribute('aria-pressed',String(n==='dark'))})}"
    "var f=document.getElementById('filter'),tb=document.getElementById('trials'),"
    "w=document.getElementById('filter-box');"
    "if(f&&tb&&w){w.hidden=false;f.addEventListener('input',function(){"
    "var q=f.value.toLowerCase(),rows=tb.tBodies[0].rows,n=0;"
    "for(var i=0;i<rows.length;i++){var k=rows[i].textContent.toLowerCase().indexOf(q)!==-1;"
    "rows[i].hidden=!k;if(k){n++}}"
    "var o=document.getElementById('filter-count');if(o){o.textContent=n+' shown'}})}"
    "})();"
)


def _sha(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


CSP = (
    "default-src 'none'; "
    f"style-src {_sha(CSS)}; "
    f"script-src {_sha(JS)}; "
    "img-src data:; base-uri 'none'; form-action 'none'"
)


def relative_luminance(color: str) -> float:
    def channel(c: int) -> float:
        v = c / 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = (int(color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((relative_luminance(a), relative_luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)
