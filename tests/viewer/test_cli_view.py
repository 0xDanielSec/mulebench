"""`mulebench view` writes the site and reports bad input."""

from __future__ import annotations

from pathlib import Path

import pytest

from mulebench.cli import main
from tests.viewer.test_site import PILOTS


def test_view_writes_site(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pilot01 = next(p for p in PILOTS if "llama" in p.name)
    out = tmp_path / "site"
    assert main(["view", str(pilot01), "--out", str(out)]) == 0
    assert (out / "index.html").is_file()
    assert (out / "r1" / "index.html").is_file()
    assert any((out / "r1" / "trial").iterdir())
    assert "wrote" in capsys.readouterr().out
    # Not empty now: refused without --force, accepted with it.
    assert main(["view", str(pilot01), "--out", str(out)]) == 2
    assert main(["view", str(pilot01), "--out", str(out), "--force"]) == 0


def test_view_rejects_non_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "x.json"
    bad.write_text("{}", encoding="utf-8")
    assert main(["view", str(bad), "--out", str(tmp_path / "o")]) == 2
    assert "not a mulebench report" in capsys.readouterr().err
    assert main(["view", str(tmp_path / "missing.json"), "--out", str(tmp_path / "o")]) == 2
