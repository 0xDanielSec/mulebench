"""The committed cassette archive: deterministic build, hash, and safe extraction."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import lzma
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
GOOD = "pilot-08-x/0123456789abcdef.json"


def _load(name: str, file: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ca() -> ModuleType:
    return _load("cassette_archive_under_test", "cassette_archive.py")


def raw_archive(add: Callable[[tarfile.TarFile], None]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        add(tar)
    return lzma.compress(buf.getvalue(), format=lzma.FORMAT_XZ)


def reg(tar: tarfile.TarFile, name: str, data: bytes = b"{}") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def reg_twice(tar: tarfile.TarFile, name: str) -> None:
    reg(tar, name)
    reg(tar, name)


def special(tar: tarfile.TarFile, name: str, kind: bytes, link: str = "") -> None:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    tar.addfile(info)


def write(tmp_path: Path, data: bytes) -> tuple[Path, str]:
    path = tmp_path / "a.tar.xz"
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def test_build_is_deterministic_and_normalised(ca: ModuleType) -> None:
    files = [("pilot-08-a/0000000000000001.json", b"{}"), (GOOD, b'{"a": 1}')]
    first, second = ca.build_bytes(files), ca.build_bytes(files)
    assert first == second
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:xz") as tar:
        members = tar.getmembers()
    assert [m.name for m in members] == [n for n, _ in files]
    for m in members:
        assert (m.mtime, m.uid, m.gid, m.uname, m.gname, m.mode) == (0, 0, 0, "", "", 0o644)
        assert m.isreg()


def test_source_files_are_sorted_and_named(ca: ModuleType, tmp_path: Path) -> None:
    for name in ("pilot-09-b/00000000000000ff.json", "pilot-09-a/_server_meta.json"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("{}", encoding="utf-8")
    assert [n for n, _ in ca.source_files(tmp_path)] == [
        "pilot-09-a/_server_meta.json",
        "pilot-09-b/00000000000000ff.json",
    ]
    (tmp_path / "pilot-09-a" / "notes.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ca.ArchiveError, match="unexpected source entry"):
        ca.source_files(tmp_path)


def test_committed_archive_matches_its_hash(ca: ModuleType) -> None:
    data = ca.ARCHIVE.read_bytes()
    assert ca.sha256_bytes(data) == ca.expected_sha()
    assert ca.SHA_FILE.read_bytes().endswith(b"  pilots-01-08.tar.xz\n")


def test_committed_archive_rebuilds_byte_for_byte(ca: ModuleType) -> None:
    with tarfile.open(ca.ARCHIVE, mode="r:xz") as tar:
        members = ca.checked_members(tar, ca.DEFAULT_CAPS)
        files = []
        for m in members:
            f = tar.extractfile(m)
            assert f is not None
            files.append((m.name, f.read()))
    assert [n for n, _ in files] == sorted(n for n, _ in files)
    assert ca.sha256_bytes(ca.build_bytes(files)) == ca.expected_sha()


def test_extract_good_archive(ca: ModuleType, tmp_path: Path) -> None:
    path, sha = write(tmp_path, ca.build_bytes([(GOOD, b'{"ok": true}')]))
    dest = tmp_path / "out"
    assert ca.extract(path, dest, sha) == 1
    assert (dest / GOOD).read_bytes() == b'{"ok": true}'
    assert ca.extract(path, dest, sha) == 1  # identical file: fine
    (dest / GOOD).write_bytes(b"changed")
    with pytest.raises(ca.ArchiveError, match="exists and differs"):
        ca.extract(path, dest, sha)
    assert ca.extract(path, dest, sha, force=True) == 1


def test_hash_is_checked_before_the_archive_is_opened(ca: ModuleType, tmp_path: Path) -> None:
    path, _ = write(tmp_path, b"not even an archive")
    with pytest.raises(ca.ArchiveError, match="sha256 mismatch"):
        ca.extract(path, tmp_path / "out", "0" * 64)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    ("add", "message"),
    [
        (lambda t: reg(t, "../pilot-08-x/0123456789abcdef.json"), "path traversal"),
        (lambda t: reg(t, "pilot-08-x/../../0123456789abcdef.json"), "path traversal"),
        (lambda t: reg(t, "/pilot-08-x/0123456789abcdef.json"), "absolute path"),
        (lambda t: reg(t, "C:/pilot-08-x/0123456789abcdef.json"), "absolute path"),
        (lambda t: reg(t, "pilot-08-x\\..\\0123456789abcdef.json"), "path traversal"),
        (lambda t: special(t, GOOD, tarfile.SYMTYPE, "/etc/passwd"), "not a regular file"),
        (lambda t: special(t, GOOD, tarfile.LNKTYPE, "pilot-08-x/x.json"), "not a regular"),
        (lambda t: special(t, GOOD, tarfile.CHRTYPE), "not a regular file"),
        (lambda t: special(t, GOOD, tarfile.BLKTYPE), "not a regular file"),
        (lambda t: special(t, GOOD, tarfile.FIFOTYPE), "not a regular file"),
        (lambda t: special(t, "pilot-08-x", tarfile.DIRTYPE), "not a regular file"),
        (lambda t: reg(t, "pilot-08-x/0123456789abcdef.py"), "unexpected member name"),
        (lambda t: reg(t, "other/0123456789abcdef.json"), "unexpected member name"),
        (lambda t: reg(t, "pilot-08-x/sub/0123456789abcdef.json"), "unexpected member name"),
        (lambda t: reg_twice(t, GOOD), "duplicate member"),
    ],
)
def test_malicious_archives_are_rejected_before_any_write(
    ca: ModuleType,
    tmp_path: Path,
    add: Callable[[tarfile.TarFile], None],
    message: str,
) -> None:
    def good_then_bad(tar: tarfile.TarFile) -> None:
        reg(tar, "pilot-08-x/fedcba9876543210.json")
        add(tar)

    good_first = raw_archive(good_then_bad)
    path, sha = write(tmp_path, good_first)
    dest = tmp_path / "out"
    with pytest.raises(ca.ArchiveError, match=message):
        ca.extract(path, dest, sha)
    assert not any(dest.rglob("*")), "nothing may be written when any member is rejected"
    assert not (tmp_path.parent / "0123456789abcdef.json").exists()


def test_oversized_member_is_rejected(ca: ModuleType, tmp_path: Path) -> None:
    path, sha = write(tmp_path, ca.build_bytes([(GOOD, b"x" * 2048)]))
    with pytest.raises(ca.ArchiveError, match="member too large"):
        ca.extract(path, tmp_path / "out", sha, ca.Caps(file_bytes=1024))


def test_total_size_cap_and_file_cap(ca: ModuleType, tmp_path: Path) -> None:
    files = [(f"pilot-08-x/{i:016x}.json", b"y" * 600) for i in range(3)]
    path, sha = write(tmp_path, ca.build_bytes(files))
    with pytest.raises(ca.ArchiveError, match="too large uncompressed"):
        ca.extract(path, tmp_path / "out", sha, ca.Caps(total_bytes=1000))
    with pytest.raises(ca.ArchiveError, match="too many members"):
        ca.extract(path, tmp_path / "out", sha, ca.Caps(files=2))
    with pytest.raises(ca.ArchiveError, match="archive file too large"):
        ca.extract(path, tmp_path / "out", sha, ca.Caps(archive_bytes=10))


def test_decompression_bomb_is_capped_by_declared_size(ca: ModuleType, tmp_path: Path) -> None:
    # 8 MiB of zeros compresses to a few KiB; the total cap rejects it unread.
    path, sha = write(tmp_path, ca.build_bytes([(GOOD, bytes(8 * 1024 * 1024))]))
    assert path.stat().st_size < 64 * 1024
    with pytest.raises(ca.ArchiveError, match="member too large"):
        ca.extract(path, tmp_path / "out", sha)


def test_prepublish_scans_archive_members(ca: ModuleType, tmp_path: Path) -> None:
    pc = _load("prepublish_check_for_archive", "prepublish_check.py")
    leak = b'{"note": "mail someone' + b"@leak-domain.invalid, key sk-or-v1-" + b"a" * 40 + b'"}'
    path, _ = write(tmp_path, ca.build_bytes([(GOOD, leak)]))
    findings = pc.scan_archive(
        path, "x.tar.xz", pc.Policy(frozenset({"example.test"}), frozenset(), ())
    )
    kinds = {f.kind for f in findings}
    assert "email" in kinds
    assert any(k.startswith("secret") for k in kinds)
    assert all(f.where.startswith(f"x.tar.xz!{GOOD}:") for f in findings)
    bad, _ = write(tmp_path, raw_archive(lambda t: special(t, GOOD, tarfile.SYMTYPE, "/x")))
    (rejected,) = pc.scan_archive(
        bad, "bad.tar.xz", pc.Policy(frozenset({"example.test"}), frozenset(), ())
    )
    assert rejected.kind == "archive"
