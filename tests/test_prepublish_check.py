"""Unit tests for scripts/prepublish_check.py.

Flagged values are assembled at runtime (e.g. "corp" + ".com") so this file does
not itself trip the scanner when it runs over the repository.
"""

from __future__ import annotations

import importlib.util
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
