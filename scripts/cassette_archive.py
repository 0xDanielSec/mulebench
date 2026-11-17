"""Deterministic, verified archive of the pilot cassettes (offline replay without a key).

Usage:
    uv run python scripts/cassette_archive.py build    # runs/cassettes/pilot-* -> archive + .sha256
    uv run python scripts/cassette_archive.py verify   # rebuild from runs/cassettes/, compare hash
    uv run python scripts/cassette_archive.py extract  # check hash, then extract to runs/cassettes/

The archive is treated as untrusted input. `extract` checks its sha256 against the
committed `.sha256` file BEFORE opening it, then accepts only regular `.json` files
with names of the form `pilot-<name>/<16 hex>.json` or `pilot-<name>/_server_meta.json`,
within file-count and size caps, and extracts them with tarfile's "data" filter into
runs/cassettes/. Anything else (absolute paths, "..", links, devices, directories,
other names, too many or too large members) rejects the whole archive before any file
is written.

The build is deterministic: entries sorted by name, USTAR format, mtime 0, mode 0644,
uid/gid 0, empty user and group names, xz preset 9 (single-threaded), so the same
cassettes always give the same sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import lzma
import re
import sys
import tarfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASSETTES = ROOT / "runs" / "cassettes"
ARCHIVE = ROOT / "docs" / "experiments" / "cassettes" / "pilots-01-08.tar.xz"
SHA_FILE = ARCHIVE.with_name(ARCHIVE.name + ".sha256")
MEMBER = re.compile(r"^pilot-[a-z0-9.-]+/(?:[0-9a-f]{16}|_server_meta)\.json$")
XZ_PRESET = 9


@dataclass(frozen=True)
class Caps:
    archive_bytes: int = 32 * 1024 * 1024
    files: int = 20_000
    file_bytes: int = 4 * 1024 * 1024
    total_bytes: int = 512 * 1024 * 1024


DEFAULT_CAPS = Caps()


class ArchiveError(Exception):
    """The archive failed a check; nothing was extracted."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_files(src: Path = CASSETTES) -> list[tuple[str, Path]]:
    """(member name, path) of every pilot cassette, sorted by member name."""
    out: list[tuple[str, Path]] = []
    for path in src.glob("pilot-*/*"):
        name = path.relative_to(src).as_posix()
        if not path.is_file() or path.is_symlink() or not MEMBER.match(name):
            raise ArchiveError(f"unexpected source entry: {name}")
        out.append((name, path))
    if not out:
        raise ArchiveError(f"no pilot cassettes under {src}")
    return sorted(out)


def build_bytes(files: Iterable[tuple[str, bytes]]) -> bytes:
    """Deterministic .tar.xz of (name, content) pairs, in the given order."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    return lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ, preset=XZ_PRESET)


def build_from(src: Path = CASSETTES) -> bytes:
    return build_bytes((name, path.read_bytes()) for name, path in source_files(src))


def expected_sha(sha_file: Path = SHA_FILE) -> str:
    value = sha_file.read_text(encoding="utf-8").split()[0].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ArchiveError(f"malformed hash file {sha_file}")
    return value


def checked_members(tar: tarfile.TarFile, caps: Caps) -> list[tarfile.TarInfo]:
    """All members, if every one passes; otherwise ArchiveError."""
    members: list[tarfile.TarInfo] = []
    total = 0
    seen: set[str] = set()
    for m in tar:
        name = m.name
        if not m.isreg():
            raise ArchiveError(f"not a regular file: {name!r} (type {m.type!r})")
        if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
            raise ArchiveError(f"absolute path: {name!r}")
        if ".." in name.replace("\\", "/").split("/") or "\\" in name:
            raise ArchiveError(f"path traversal: {name!r}")
        if not MEMBER.match(name):
            raise ArchiveError(f"unexpected member name: {name!r}")
        if name in seen:
            raise ArchiveError(f"duplicate member: {name!r}")
        if m.size > caps.file_bytes:
            raise ArchiveError(f"member too large: {name!r} ({m.size} bytes)")
        total += m.size
        if total > caps.total_bytes:
            raise ArchiveError(f"archive too large uncompressed (> {caps.total_bytes} bytes)")
        if len(members) >= caps.files:
            raise ArchiveError(f"too many members (> {caps.files})")
        seen.add(name)
        members.append(m)
    return members


def extract(
    archive: Path = ARCHIVE,
    dest: Path = CASSETTES,
    sha: str | None = None,
    caps: Caps = DEFAULT_CAPS,
    force: bool = False,
    prefix: str = "",
) -> int:
    """Check the hash, check every member, then extract the members whose name starts
    with `prefix` (all by default). Returns the number of files extracted."""
    if archive.stat().st_size > caps.archive_bytes:
        raise ArchiveError(f"archive file too large (> {caps.archive_bytes} bytes)")
    data = archive.read_bytes()
    want = sha if sha is not None else expected_sha()
    got = sha256_bytes(data)
    if got != want:
        raise ArchiveError(f"sha256 mismatch: got {got}, expected {want}")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as tar:
        members = [m for m in checked_members(tar, caps) if m.name.startswith(prefix)]
        for m in members:
            target = (root / m.name).resolve()
            if not target.is_relative_to(root):
                raise ArchiveError(f"outside destination: {m.name!r}")
            if target.exists() and not force:
                f = tar.extractfile(m)
                if f is None:
                    raise ArchiveError(f"unreadable member: {m.name!r}")
                if target.read_bytes() != f.read():
                    raise ArchiveError(f"{target} exists and differs (use --force)")
        tar.extractall(root, members=members, filter="data")
    return len(members)


def iter_texts(archive: Path, caps: Caps = DEFAULT_CAPS) -> Iterable[tuple[str, str]]:
    """(member name, text) of every member, after the member checks; never writes."""
    with tarfile.open(archive, mode="r:xz") as tar:
        for m in checked_members(tar, caps):
            f = tar.extractfile(m)
            if f is None:
                raise ArchiveError(f"unreadable member: {m.name!r}")
            yield m.name, f.read().decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/cassette_archive.py")
    parser.add_argument("mode", choices=("build", "verify", "extract"))
    parser.add_argument("--force", action="store_true", help="extract: overwrite differing files")
    parser.add_argument("--only", default="", help="extract: member name prefix, e.g. pilot-08-")
    args = parser.parse_args(argv)
    try:
        if args.mode == "build":
            data = build_from()
            ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
            ARCHIVE.write_bytes(data)
            SHA_FILE.write_text(
                f"{sha256_bytes(data)}  {ARCHIVE.name}\n", encoding="utf-8", newline="\n"
            )
            print(f"wrote {ARCHIVE.relative_to(ROOT)} ({len(data)} bytes) {sha256_bytes(data)}")
        elif args.mode == "verify":
            got, want = sha256_bytes(build_from()), expected_sha()
            print(f"rebuilt {got}\ncommitted {want}")
            if got != want:
                print("MISMATCH: runs/cassettes/ differs from the committed archive")
                return 1
            print("ok: rebuild matches the committed hash")
        else:
            n = extract(force=args.force, prefix=args.only)
            print(f"ok: sha256 verified, {n} files extracted to {CASSETTES.relative_to(ROOT)}")
    except ArchiveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
