"""The git tree hash of `src/`, to pin a frozen pilot to its harness commit.

A pre-registration names the harness commit. `mulebench run --expect-harness
<sha>` (and `mulebench workloads`) refuses to start when `src/` on disk is not
the `src/` of that commit, and every report records the tree hash it ran with
(`generator.src_tree`).

The hash is computed the way git would commit the directory: tracked and
untracked files, ignored files left out, line endings normalised by git's own
rules. It uses a throwaway index, so the real index and the working tree are
not touched; `git add` does write the blobs into the object store, where
`git gc` removes them if unused.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

SRC = "src"


class HarnessMismatch(Exception):
    """src/ on disk is not the src/ of the expected commit, or cannot be checked."""


def repo_root() -> Path | None:
    """The checkout holding this package's source, or None for an installed package."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / SRC / "mulebench").is_dir() and (parent / ".git").exists():
            return parent
    return None


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    done = subprocess.run(  # noqa: S603 - fixed git argv
        ["git", *args],  # noqa: S607 - git from PATH is intended
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise HarnessMismatch(f"git {' '.join(args)}: {done.stderr.strip() or done.returncode}")
    return done.stdout.strip()


def src_tree(root: Path | None = None) -> str | None:
    """Tree hash of `src/` as it is on disk; None outside a git checkout or without git."""
    root = root if root is not None else repo_root()
    if root is None:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="mb-tree-") as tmp:
            env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
            _git(root, "add", "-A", "--", SRC, env=env)
            return _git(root, "write-tree", f"--prefix={SRC}/", env=env)
    except (HarnessMismatch, OSError):
        return None


def commit_src_tree(commit: str, root: Path | None = None) -> str:
    """Tree hash of `src/` in `commit` (a full or short sha, or any commit-ish)."""
    root = root if root is not None else repo_root()
    if root is None:
        raise HarnessMismatch("not a git checkout: cannot check --expect-harness")
    try:
        return _git(root, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}:{SRC}")
    except HarnessMismatch as exc:
        raise HarnessMismatch(f"unknown commit {commit!r}, or it has no {SRC}/") from exc
    except OSError as exc:
        raise HarnessMismatch(f"git not available: {exc}") from exc


def check_harness(expected_commit: str, root: Path | None = None) -> str:
    """The on-disk tree hash when it equals the commit's; HarnessMismatch otherwise."""
    want = commit_src_tree(expected_commit, root)
    have = src_tree(root)
    if have is None:
        raise HarnessMismatch("cannot compute the tree hash of src/ (git failed)")
    if have != want:
        raise HarnessMismatch(
            f"src/ differs from harness commit {expected_commit}: tree {have[:12]} on disk, "
            f"{want[:12]} in the commit. Check out that commit (or stash the changes) "
            "before a frozen run."
        )
    return have
