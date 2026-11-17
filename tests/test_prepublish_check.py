"""Unit tests for scripts/prepublish_check.py.

Flagged values are assembled at runtime (e.g. "corp" + ".com") so this file does
not itself trip the scanner when it runs over the repository.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prepublish_check.py"


@pytest.fixture(scope="module")
def pc() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prepublish_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["prepublish_check"] = module
    spec.loader.exec_module(module)
    return module


AUTHOR = "author" + "@" + "mail" + ".test"
CORP = "corp" + ".com"
HIT = "x" + "@" + "example.tes"  # built so this file is not itself a finding
OTHER = "y" + "@" + "example.tes"


def policy(pc: ModuleType, terms: tuple[str, ...] = ()) -> object:
    return pc.Policy(
        allowed_domains=pc.DEFAULT_ALLOWED_DOMAINS,
        allowed_emails=pc.DEFAULT_ALLOWED_EMAILS | {AUTHOR},
        terms=terms,
    )


def kinds(pc: ModuleType, text: str, terms: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    return [(f.kind, f.value) for f in pc.scan_text(text, "x", policy(pc, terms))]


def test_example_test_domains_allowed(pc: ModuleType) -> None:
    assert kinds(pc, "pay refund-desk@attacker.example.test or alice@example.test") == []


def test_foreign_bare_domain_flagged(pc: ModuleType) -> None:
    assert kinds(pc, f"see {CORP} for details") == [("domain", CORP)]


def test_url_host_flagged(pc: ModuleType) -> None:
    host = "intranet." + CORP
    assert kinds(pc, f"https://{host}/path") == [("domain", host)]


def test_allowlisted_infrastructure_domains(pc: ModuleType) -> None:
    assert kinds(pc, "https://github.com/x and http://www.apache.org/licenses/") == []


def test_foreign_email_flagged_once(pc: ModuleType) -> None:
    email = "someone@" + CORP
    assert kinds(pc, f"contact {email}") == [("email", email)]


def test_author_and_coauthor_emails_allowed(pc: ModuleType) -> None:
    assert kinds(pc, f"Author <{AUTHOR}> Co-Authored-By: <noreply@anthropic.com>") == []


def test_toml_table_header_is_not_a_domain(pc: ModuleType) -> None:
    header = "[package." + "dev-dependencies]"
    assert kinds(pc, header) == []


def test_python_module_paths_are_not_domains(pc: ModuleType) -> None:
    assert kinds(pc, "from mulebench.ledger.models import Account  # ledger.py") == []


def test_forbidden_terms_case_insensitive(pc: ModuleType) -> None:
    assert kinds(pc, "Project ACME rollout", terms=("acme",)) == [("term", "acme")]


# Fake keys assembled at runtime so this file never contains a key-shaped string.
FAKE_SECRETS = {
    "anthropic": "sk-" + "ant-" + "api03-" + "A" * 40,
    "generic-sk": "sk-" + "B" * 40,
    "openrouter": "sk-" + "or-v1-" + "f" * 64,
    "aws-access-key": "AKIA" + "C" * 16,
    "github-token": "ghp" + "_" + "D" * 36,
    "google-api-key": "AIza" + "E" * 35,
    "slack-token": "xoxb" + "-" + "1" * 12,
    "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
}


@pytest.mark.parametrize(("name", "secret"), sorted(FAKE_SECRETS.items()))
def test_api_key_shaped_strings_flagged_and_masked(pc: ModuleType, name: str, secret: str) -> None:
    found = [(f.kind, f.value) for f in pc.scan_text(f"key = '{secret}'", "x", policy(pc))]
    assert (f"secret:{name}", secret[:6] + "...") in found
    assert all(secret not in value for _, value in found)


def test_ordinary_identifiers_are_not_secrets(pc: ModuleType) -> None:
    text = "sk-short task-ant-x AKIA123 sig_0123456789abcdef msg_0123456789abcdef"
    assert [f for f in pc.scan_text(text, "x", policy(pc)) if f.kind.startswith("secret")] == []


def test_allowlist_parses_entries_and_rejects_missing_reason(
    pc: ModuleType, tmp_path: Path
) -> None:
    f = tmp_path / "allow.txt"
    f.write_text("# comment\n\n" + HIT + " -- truncated synthetic key\n", encoding="utf-8")
    assert pc.load_allowlist(f) == {HIT: "truncated synthetic key"}
    f.write_text(HIT + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="justification"):
        pc.load_allowlist(f)
    assert pc.load_allowlist(tmp_path / "missing.txt") == {}


def test_allowlisted_finding_is_reported_not_counted(
    pc: ModuleType, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    hit = pc.Finding("email", HIT, "f:1")
    other = pc.Finding("email", OTHER, "f:2")
    blocking, allowed = pc.split_allowed([hit, other], {HIT: "why"})
    assert (blocking, allowed) == ([other], [hit])
    monkeypatch.setattr(pc, "load_policy", lambda: policy(pc))
    monkeypatch.setattr(pc, "load_allowlist", lambda: {HIT: "why"})
    monkeypatch.setattr(pc, "scan_tree", lambda policy: [hit])
    assert pc.main(["--no-history"]) == 0
    out = capsys.readouterr().out
    assert HIT + "  (f:1)  allowed (why)" in out
    assert "0 finding(s), 1 allowed" in out
    assert out.rstrip().endswith("clean")


def test_missing_git_email_means_no_configured_author(
    pc: ModuleType, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unset(*args: str) -> str:
        raise subprocess.CalledProcessError(1, ["git", *args])

    monkeypatch.setattr(pc, "_git", unset)
    monkeypatch.setattr(pc, "TERMS_FILE", Path("does-not-exist.terms"))
    monkeypatch.delenv("MB_FORBIDDEN_TERMS", raising=False)
    loaded = pc.load_policy()
    assert loaded.author == ""
    assert loaded.allowed_emails == pc.DEFAULT_ALLOWED_EMAILS
    assert not loaded.email_allowed(AUTHOR)

    monkeypatch.setattr(pc, "load_allowlist", dict)
    monkeypatch.setattr(pc, "scan_tree", lambda policy: [])
    assert pc.main(["--no-history"]) == 0
    assert "git user.email is not set" in capsys.readouterr().out


def test_other_git_config_errors_still_raise(
    pc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: str) -> str:
        raise subprocess.CalledProcessError(128, ["git", *args])

    monkeypatch.setattr(pc, "_git", broken)
    with pytest.raises(subprocess.CalledProcessError):
        pc.configured_author()


def test_committed_allowlist_is_valid(pc: ModuleType) -> None:
    allow = pc.load_allowlist()
    assert all(reason for reason in allow.values())
