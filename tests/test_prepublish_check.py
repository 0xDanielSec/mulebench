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
from typing import Any

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


def test_scoped_entry_allows_only_metadata_up_to_its_commit(
    pc: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new = "a" * 40, "b" * 40
    f = tmp_path / "allow.txt"
    f.write_text(
        f"sha256:{pc.value_sha256(HIT)} [metadata-until {old}] -- historical metadata\n",
        encoding="utf-8",
    )
    assert pc.load_allowlist(f) == {}
    scoped = pc.load_scoped_allowlist(f)
    assert scoped == {pc.value_sha256(HIT): (old, "historical metadata")}
    assert HIT not in f.read_text(encoding="utf-8")
    monkeypatch.setattr(pc, "ancestors", lambda sha: frozenset({old, "c" * 40}))
    lineage: dict[str, frozenset[str]] = {}
    ok = pc.Finding("email", HIT, f"{old[:7]} metadata")
    assert pc.scoped_reason(ok, scoped, lineage) == "historical metadata"
    assert pc.scoped_reason(pc.Finding("email", HIT, "ccccccc metadata"), scoped, lineage)
    # a later commit (not an ancestor), a diff line, or a file in the tree: still flagged
    assert (
        pc.scoped_reason(pc.Finding("email", HIT, f"{new[:7]} metadata"), scoped, lineage) is None
    )
    assert (
        pc.scoped_reason(pc.Finding("email", HIT, f"{old[:7]} README.md"), scoped, lineage) is None
    )
    assert pc.scoped_reason(pc.Finding("email", HIT, "README.md:3"), scoped, lineage) is None
    assert (
        pc.scoped_reason(pc.Finding("email", OTHER, f"{old[:7]} metadata"), scoped, lineage) is None
    )
    f.write_text(f"sha256:{'0' * 64} [metadata-after {old}] -- bad scope\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="scope"):
        pc.load_allowlist(f)


def test_committed_scoped_entries_name_known_commits(pc: ModuleType) -> None:
    if pc.is_shallow():
        pytest.fail(pc.SHALLOW_MESSAGE)
    for sha, reason in pc.load_scoped_allowlist().values():
        assert reason
        assert pc.ancestors(sha), sha


def test_history_scan_refuses_a_shallow_clone(
    pc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pc, "is_shallow", lambda: True)
    with pytest.raises(SystemExit, match="fetch-depth: 0"):
        pc.scan_history(policy(pc))


# The one file-scoped secret entry (pilot 11): an sk- match inside an encrypted
# reasoning blob of one gpt-6.1-terra cassette, inside the pilot-11 archive.
P11_ARCHIVE = "docs/experiments/cassettes/pilot-11.tar.xz"
P11_MEMBER = f"{P11_ARCHIVE}!pilot-11-gpt-6.1-terra-vulnerable/a7c3f35e2842fcd9.json"


def _p11_blob_finding(pc: ModuleType) -> Any:
    root = SCRIPT.parents[1]
    found = pc.scan_archive(root / P11_ARCHIVE, P11_ARCHIVE, policy(pc))
    secrets = [f for f in found if f.kind.startswith("secret:")]
    assert len(secrets) == 1
    assert secrets[0].where.startswith(P11_MEMBER + ":")
    assert secrets[0].raw.startswith("sk-")
    assert len(secrets[0].raw) > 32
    return secrets[0]


def test_file_scoped_blob_passes_only_in_its_cassette(pc: ModuleType) -> None:
    files = pc.load_file_scoped_allowlist()
    blob = _p11_blob_finding(pc)
    assert pc.file_scoped_reason(blob, files)
    # the same member in a committed archive version (history scan form)
    hist = pc.Finding(blob.kind, blob.value, f"0b8e0a5e6ea4 {blob.where}", raw=blob.raw)
    assert pc.file_scoped_reason(hist, files)


def test_same_blob_value_in_any_other_file_is_flagged(pc: ModuleType) -> None:
    files = pc.load_file_scoped_allowlist()
    blob = _p11_blob_finding(pc)
    others = [
        "README.md:1",
        f"{P11_ARCHIVE}!pilot-11-gpt-6.1-terra-vulnerable/0000000000000000.json:1",
        "docs/experiments/cassettes/pilot-10.tar.xz!pilot-10-x/a7c3f35e2842fcd9.json:484",
        f"abc1234 {P11_MEMBER}",  # a diff line, not the archive member
        "abc1234 metadata",
    ]
    for where in others:
        (f,) = [x for x in pc.scan_text(blob.raw, where, policy(pc)) if x.kind == blob.kind]
        assert pc.file_scoped_reason(f, files) is None, where
        blocking, _ = pc.split_allowed([f], pc.load_allowlist())
        assert blocking == [f], where


def test_other_value_with_the_same_prefix_is_flagged_everywhere(pc: ModuleType) -> None:
    files = pc.load_file_scoped_allowlist()
    allow = pc.load_allowlist()
    blob = _p11_blob_finding(pc)
    other = blob.raw[:6] + "Z" * (len(blob.raw) - 6)
    assert other != blob.raw
    assert pc.mask(other) == blob.value
    for where in (f"{P11_MEMBER}:484", f"0b8e0a5e6ea4 {P11_MEMBER}:484", "README.md:1"):
        (f,) = [x for x in pc.scan_text(other, where, policy(pc)) if x.kind == blob.kind]
        assert pc.file_scoped_reason(f, files) is None, where
        assert pc.scoped_reason(f, pc.load_scoped_allowlist(), {}) is None, where
        blocking, _ = pc.split_allowed([f], allow)
        assert blocking == [f], where


def test_unscoped_entry_never_allows_a_masked_secret(pc: ModuleType) -> None:
    raw = "sk-" + "Ab" * 20
    (f,) = pc.scan_text(raw, "x.txt:1", policy(pc))
    blocking, allowed = pc.split_allowed([f], {pc.mask(raw): "prefix entry"})
    assert blocking == [f]
    assert allowed == []
    assert not any(v.startswith("sk-") for v in pc.load_allowlist())


def test_file_scoped_entry_parses_and_needs_the_exact_value(pc: ModuleType, tmp_path: Path) -> None:
    raw = "sk-" + "Cd" * 20
    f = tmp_path / "allow.txt"
    f.write_text(
        f"sha256:{pc.exact_sha256(raw)} [file a.tar.xz!m/0123456789abcdef.json] -- why\n",
        encoding="utf-8",
    )
    files = pc.load_file_scoped_allowlist(f)
    assert files == {(pc.exact_sha256(raw), "a.tar.xz!m/0123456789abcdef.json"): "why"}
    (hit,) = pc.scan_text(raw, "a.tar.xz!m/0123456789abcdef.json:9", policy(pc))
    assert pc.file_scoped_reason(hit, files) == "why"
    swapped = "sk-" + raw[3:].swapcase()
    (upper,) = pc.scan_text(swapped, "a.tar.xz!m/0123456789abcdef.json:9", policy(pc))
    assert pc.file_scoped_reason(upper, files) is None  # exact, not lowercased
    bad = tmp_path / "bad.txt"
    bad.write_text("sha256:" + "0" * 64 + " [file ] -- why\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="scope must be"):
        pc.load_file_scoped_allowlist(bad)
