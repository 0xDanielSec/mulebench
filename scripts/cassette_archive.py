"""Deterministic, verified archive of the pilot cassettes (offline replay without a key).

Usage:
    uv run python scripts/cassette_archive.py build    # runs/cassettes/pilot-* -> archive + .sha256
    uv run python scripts/cassette_archive.py verify   # rebuild from runs/cassettes/, compare hash
    uv run python scripts/cassette_archive.py extract  # check hash, then extract to runs/cassettes/

Two archives, chosen with `--archive` (default `pilots-01-08`):
`pilots-01-08.tar.xz` (pilots 01 to 08; frozen, its sha256 is cited by the pilot 08
document) and `pilot-09.tar.xz` (pilot 09 only). Each archive holds only the
cassette directories of its own pilots, so adding a pilot never changes the hash
of an earlier archive.

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
ARCHIVE_DIR = ROOT / "docs" / "experiments" / "cassettes"
# archive name -> glob of its cassette directories under runs/cassettes/
ARCHIVES: dict[str, str] = {
    "pilots-01-08": "pilot-0[1-8]-*",
    "pilot-09": "pilot-09-*",
}
DEFAULT_ARCHIVE = "pilots-01-08"
ARCHIVE = ARCHIVE_DIR / f"{DEFAULT_ARCHIVE}.tar.xz"
SHA_FILE = ARCHIVE.with_name(ARCHIVE.name + ".sha256")
MEMBER = re.compile(r"^pilot-[a-z0-9._-]+/(?:[0-9a-f]{16}|_server_meta)\.json$")


def archive_paths(name: str) -> tuple[Path, Path]:
    """(archive, sha256 file) of a named archive."""
    archive = ARCHIVE_DIR / f"{name}.tar.xz"
    return archive, archive.with_name(archive.name + ".sha256")


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


def source_files(src: Path = CASSETTES, dirs: str = "pilot-*") -> list[tuple[str, Path]]:
    """(member name, path) of every cassette in the `dirs` directories, sorted by name."""
    out: list[tuple[str, Path]] = []
    for path in src.glob(f"{dirs}/*"):
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


def build_from(src: Path = CASSETTES, dirs: str = ARCHIVES[DEFAULT_ARCHIVE]) -> bytes:
    return build_bytes((name, path.read_bytes()) for name, path in source_files(src, dirs))


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
    sha_file: Path = SHA_FILE,
) -> int:
    """Check the hash, check every member, then extract the members whose name starts
    with `prefix` (all by default). Returns the number of files extracted."""
    if archive.stat().st_size > caps.archive_bytes:
        raise ArchiveError(f"archive file too large (> {caps.archive_bytes} bytes)")
    data = archive.read_bytes()
    want = sha if sha is not None else expected_sha(sha_file)
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
    parser.add_argument(
        "--archive", choices=sorted(ARCHIVES), default=DEFAULT_ARCHIVE, help="which archive"
    )
    args = parser.parse_args(argv)
    archive, sha_file = archive_paths(args.archive)
    dirs = ARCHIVES[args.archive]
    try:
        if args.mode == "build":
            data = build_from(dirs=dirs)
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(data)
            sha_file.write_text(
                f"{sha256_bytes(data)}  {archive.name}\n", encoding="utf-8", newline="\n"
            )
            print(f"wrote {archive.relative_to(ROOT)} ({len(data)} bytes) {sha256_bytes(data)}")
        elif args.mode == "verify":
            got, want = sha256_bytes(build_from(dirs=dirs)), expected_sha(sha_file)
            print(f"rebuilt {got}\ncommitted {want}")
            if got != want:
                print("MISMATCH: runs/cassettes/ differs from the committed archive")
                return 1
            print("ok: rebuild matches the committed hash")
        else:
            n = extract(archive, force=args.force, prefix=args.only, sha_file=sha_file)
            print(f"ok: sha256 verified, {n} files extracted to {CASSETTES.relative_to(ROOT)}")
    except ArchiveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
