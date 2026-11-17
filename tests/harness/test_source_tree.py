"""--expect-harness: the src/ tree hash pins a frozen pilot to its harness commit."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mulebench import cli
from mulebench.harness import source_tree
from mulebench.harness.source_tree import (
    HarnessMismatch,
    check_harness,
    commit_src_tree,
    src_tree,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def git(root: Path, *args: str) -> str:
    done = subprocess.run(  # noqa: S603 - fixed git argv
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.test", *args],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    (root / "src" / "pkg").mkdir(parents=True)
    git(root, "init", "-q")
    git(root, "config", "core.autocrlf", "false")
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    (root / "src" / "pkg" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "docs.md").write_text("docs\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "one")
    return root, git(root, "rev-parse", "HEAD")


def test_clean_tree_equals_commit_tree(repo: tuple[Path, str]) -> None:
    root, sha = repo
    assert src_tree(root) == commit_src_tree(sha, root) == git(root, "rev-parse", "HEAD:src")
    assert check_harness(sha[:8], root) == commit_src_tree(sha, root)


def test_edit_untracked_file_and_later_commit_are_refused(repo: tuple[Path, str]) -> None:
    root, sha = repo
    (root / "src" / "pkg" / "a.py").write_text("A = 2\n", encoding="utf-8")
    with pytest.raises(HarnessMismatch, match="differs from harness commit"):
        check_harness(sha, root)
    git(root, "checkout", "-q", "--", "src")
    (root / "src" / "pkg" / "new.py").write_text("", encoding="utf-8")
    with pytest.raises(HarnessMismatch):
        check_harness(sha, root)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "two")
    with pytest.raises(HarnessMismatch):
        check_harness(sha, root)  # src/ moved on since the frozen commit
    assert check_harness("HEAD", root)


def test_ignored_files_and_changes_outside_src_do_not_count(repo: tuple[Path, str]) -> None:
    root, sha = repo
    (root / "src" / "pkg" / "__pycache__").mkdir()
    (root / "src" / "pkg" / "__pycache__" / "a.pyc").write_bytes(b"x")
    (root / "docs.md").write_text("changed\n", encoding="utf-8")
    assert check_harness(sha, root)


def test_index_and_working_tree_are_untouched(repo: tuple[Path, str]) -> None:
    root, _ = repo
    (root / "src" / "pkg" / "new.py").write_text("", encoding="utf-8")
    before = git(root, "status", "--porcelain")
    src_tree(root)
    assert git(root, "status", "--porcelain") == before == "?? src/pkg/new.py"


def test_unknown_commit_and_no_checkout(repo: tuple[Path, str], tmp_path: Path) -> None:
    root, _ = repo
    with pytest.raises(HarnessMismatch, match="unknown commit"):
        commit_src_tree("0" * 40, root)
    plain = tmp_path / "plain"
    plain.mkdir()
    assert src_tree(plain) is None


def test_cli_refuses_before_running_and_stamps_the_report(
    repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, sha = repo
    monkeypatch.setattr(source_tree, "repo_root", lambda: root)
    out = tmp_path / "r.json"
    scenario = "pix-description-injection-001"
    (root / "src" / "pkg" / "a.py").write_text("A = 3\n", encoding="utf-8")
    code = cli.main(["run", "--scenario", scenario, "--expect-harness", sha, "--out", str(out)])
    assert code == 2
    assert not out.exists()
    git(root, "checkout", "-q", "--", "src")
    code = cli.main(["run", "--scenario", scenario, "--expect-harness", sha, "--out", str(out)])
    assert code in (0, 1)
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["generator"]["src_tree"] == commit_src_tree(sha, root)
    assert report["schema_minor"] == 3


def test_cli_workloads_refuses_on_mismatch(
    repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, sha = repo
    monkeypatch.setattr(source_tree, "repo_root", lambda: root)
    (root / "src" / "pkg" / "a.py").write_text("A = 4\n", encoding="utf-8")
    out = tmp_path / "w.json"
    assert cli.main(["workloads", "--expect-harness", sha, "--out", str(out)]) == 2
    assert not out.exists()
