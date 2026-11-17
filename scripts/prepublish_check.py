"""Pre-publish leak check. Reports only; never modifies files or history.

Scans the working tree (tracked files plus untracked, non-ignored files) and the
full git history (commit metadata, messages and every added line of every diff)
for:

1. domains other than example.test (and a small allowlist of infrastructure
   domains, see DEFAULT_ALLOWED_DOMAINS);
2. email addresses other than the configured git author (`git config
   user.email`), the Claude co-author trailer, and *@example.test;
3. forbidden terms you supply, case-insensitive:
   - env var MB_FORBIDDEN_TERMS="term one,term two", and/or
   - an untracked file `.prepublish-terms` (one term per line, `#` comments).
     This file is in .gitignore so the terms never get committed;
4. API-key-shaped strings (Anthropic, OpenRouter sk-or-, generic sk-, AWS, GitHub, Google, Slack,
   private key blocks). Secrets are printed masked.

Extra allowed domains: env var MB_ALLOWED_DOMAINS="<domain>,<domain>".

Known false positives: the committed file `scripts/prepublish_allow.txt`, one
entry per line, `<exact finding value> -- <one-line justification>` (`#`
comments). A finding whose value equals an entry is reported as
"allowed (<reason>)", never hidden, and does not count as a finding.

Usage:
    uv run python scripts/prepublish_check.py            # tree + history
    uv run python scripts/prepublish_check.py --no-history

Exit code: 0 if nothing was found, 1 if there are findings.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TERMS_FILE = ROOT / ".prepublish-terms"
ALLOW_FILE = ROOT / "scripts" / "prepublish_allow.txt"
ALLOW_SEP = " -- "

# Infrastructure domains that legitimately appear in this repo.
DEFAULT_ALLOWED_DOMAINS = frozenset(
    {
        "example.test",  # all synthetic data
        "apache.org",  # LICENSE text
        "anthropic.com",  # Co-Authored-By trailer (noreply address)
        "claude.com",  # PR attribution link
        "github.com",  # links and CI
        "shields.io",  # README badges
        "pypi.org",  # uv.lock
        "files.pythonhosted.org",  # uv.lock
        "json-schema.org",  # standard JSON Schema dialect identifier ($schema)
        "microsoft.net",  # "Microsoft.NET.Sdk" project SDK name (tools/kql-check)
        "openrouter.ai",  # --provider openrouter base URL
    }
)
DEFAULT_ALLOWED_EMAILS = frozenset({"noreply@anthropic.com"})

_TLDS = (
    "com|net|org|io|br|dev|ai|co|app|gov|edu|info|me|us|uk|de|xyz|sh|tech|bank|"
    "finance|cloud|biz|eu|pt|es|fr|it|nl|ca|au|in|jp|cn|ru"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
URL_HOST = re.compile(r"[a-z][a-z0-9+.-]*://([A-Za-z0-9.-]+)", re.IGNORECASE)
BARE_DOMAIN = re.compile(rf"\b((?:[a-z0-9-]+\.)+(?:{_TLDS}))\b", re.IGNORECASE)
TOML_TABLE = re.compile(r"^\s*\[\[?[A-Za-z0-9_.-]+\]\]?\s*$")
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic", re.compile(r"sk-ant-[a-z]+\d*-[A-Za-z0-9_-]{20,}")),
    ("openrouter", re.compile(r"\bsk-or-v1-[A-Za-z0-9]{32,}")),
    ("generic-sk", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def mask(secret: str) -> str:
    return secret[:6] + "..."


@dataclass(frozen=True, order=True)
class Finding:
    kind: str  # domain | email | term | secret:<type>
    value: str
    where: str  # "<file>:<line>" or "<commit> <file>" or "<commit> metadata"


@dataclass(frozen=True)
class Policy:
    allowed_domains: frozenset[str]
    allowed_emails: frozenset[str]
    terms: tuple[str, ...]

    def domain_allowed(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        return any(d == a or d.endswith("." + a) for a in self.allowed_domains)

    def email_allowed(self, email: str) -> bool:
        e = email.lower()
        return e in self.allowed_emails or self.domain_allowed_for_email(e)

    def domain_allowed_for_email(self, email: str) -> bool:
        domain = email.rsplit("@", 1)[-1]
        return domain == "example.test" or domain.endswith(".example.test")


def scan_text(text: str, where: str, policy: Policy) -> list[Finding]:
    found: set[Finding] = set()
    email_spans: list[tuple[int, int]] = []
    for m in EMAIL.finditer(text):
        email_spans.append(m.span())
        if not policy.email_allowed(m.group(0)):
            found.add(Finding("email", m.group(0), where))
    # TOML table headers (e.g. a dotted [section.name] line in uv.lock) are not domains.
    is_table_header = bool(TOML_TABLE.match(text))
    for pattern in (URL_HOST, BARE_DOMAIN):
        if pattern is BARE_DOMAIN and is_table_header:
            continue
        for m in pattern.finditer(text):
            start, end = m.span(1)
            if any(a <= start and end <= b for a, b in email_spans):
                continue  # part of an email: judged by the email rule
            domain = m.group(1).lower().rstrip(".")
            if "." in domain and not policy.domain_allowed(domain):
                found.add(Finding("domain", domain, where))
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            found.add(Finding(f"secret:{name}", mask(m.group(0)), where))
    lowered = text.lower()
    for term in policy.terms:
        if term.lower() in lowered:
            found.add(Finding("term", term, where))
    return sorted(found)


def _git(*args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed git argv
        ["git", *args],  # noqa: S607 - git from PATH is intended
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout


def load_policy() -> Policy:
    author = _git("config", "user.email").strip().lower()
    extra_domains = {
        d.strip().lower() for d in os.environ.get("MB_ALLOWED_DOMAINS", "").split(",") if d.strip()
    }
    terms = [t.strip() for t in os.environ.get("MB_FORBIDDEN_TERMS", "").split(",") if t.strip()]
    if TERMS_FILE.exists():
        for line in TERMS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return Policy(
        allowed_domains=DEFAULT_ALLOWED_DOMAINS | extra_domains,
        allowed_emails=DEFAULT_ALLOWED_EMAILS | ({author} if author else set()),
        terms=tuple(dict.fromkeys(terms)),
    )


def load_allowlist(path: Path = ALLOW_FILE) -> dict[str, str]:
    """Exact finding value -> justification. Malformed entries are errors."""
    allow: dict[str, str] = {}
    if not path.exists():
        return allow
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value, sep, reason = line.partition(ALLOW_SEP)
        if not sep or not value.strip() or not reason.strip():
            raise SystemExit(f"{path.name}:{n}: expected '<value>{ALLOW_SEP}<justification>'")
        allow[value.strip()] = reason.strip()
    return allow


def split_allowed(
    findings: list[Finding], allow: dict[str, str]
) -> tuple[list[Finding], list[Finding]]:
    """(blocking findings, allowlisted findings)."""
    blocking = [f for f in findings if f.value not in allow]
    allowed = [f for f in findings if f.value in allow]
    return blocking, allowed


def scan_tree(policy: Policy) -> list[Finding]:
    files = _git("ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    findings: list[Finding] = []
    for rel in sorted(set(files)):
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        for n, line in enumerate(text.splitlines(), start=1):
            findings += scan_text(line, f"{rel}:{n}", policy)
    return findings


def scan_history(policy: Policy) -> list[Finding]:
    log = _git(
        "log",
        "--all",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--format=%x00COMMIT %h%nAUTHOR %an <%ae>%nCOMMITTER %cn <%ce>%n%B%x00END",
    )
    findings: list[Finding] = []
    commit, path, in_meta = "?", "?", False
    for line in log.splitlines():
        if line.startswith("\x00COMMIT "):
            commit, path, in_meta = line.split()[1], "?", True
            continue
        if line.startswith("\x00END") or line == "END\x00":
            in_meta = False
            continue
        if in_meta:
            findings += scan_text(line, f"{commit} metadata", policy)
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            findings += scan_text(line[1:], f"{commit} {path}", policy)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report possible leaks before publishing.")
    parser.add_argument("--no-history", action="store_true", help="scan the working tree only")
    args = parser.parse_args(argv)

    policy = load_policy()
    allow = load_allowlist()
    print(f"forbidden terms loaded: {len(policy.terms)}; allowlist entries: {len(allow)}")
    sections = [("working tree", scan_tree(policy))]
    if not args.no_history:
        sections.append(("git history", scan_history(policy)))

    total = 0
    for title, findings in sections:
        unique, allowed = split_allowed(sorted(set(findings)), allow)
        total += len(unique)
        print(f"\n== {title}: {len(unique)} finding(s), {len(allowed)} allowed")
        for f in unique:
            print(f"  [{f.kind}] {f.value}  ({f.where})")
        for f in allowed:
            print(f"  [{f.kind}] {f.value}  ({f.where})  allowed ({allow[f.value]})")
    print(f"\n{'FINDINGS: review before publishing' if total else 'clean'}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
