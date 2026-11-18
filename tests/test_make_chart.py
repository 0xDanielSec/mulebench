"""scripts/make_chart.py: plotted values equal the committed report values."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def chart() -> ModuleType:
    return load("make_chart")


@pytest.fixture(scope="module")
def results() -> ModuleType:
    return load("pilot_results")


def test_data_step_does_not_import_matplotlib(chart: ModuleType) -> None:
    chart.chart_data()
    source = (ROOT / "scripts" / "make_chart.py").read_text(encoding="utf-8")
    head = source.split("def render(")[0]
    assert not re.search(r"^\s*(import|from) matplotlib", head, re.MULTILINE)


def test_plotted_values_equal_the_report_values(chart: ModuleType, results: ModuleType) -> None:
    bars = chart.chart_data()
    assert len(bars) == 7 * 3
    for model, name, tested in chart.MODELS:
        report = json.loads((results.DATA / name).read_text(encoding="utf-8"))
        cells = results.cells_of(report)
        for sid in chart.SCENARIOS:
            (bar,) = [b for b in bars if b.model == model and b.scenario == sid]
            if sid not in tested:
                assert bar.k is None, (model, sid)
                continue
            attack = cells[(sid, "vulnerable", "baseline", "attack")]
            assert results.attributed(attack).startswith(f"{bar.k}/{bar.n} "), (model, sid)
            low, high = results._wilson_bounds(bar.k, bar.n)
            assert (bar.low, bar.high) == (low, high), (model, sid)


def test_key_values(chart: ModuleType) -> None:
    got = {(b.model, b.scenario): (b.k, b.n, b.meaningful) for b in chart.chart_data()}
    assert got[("gemma-4-26b", "004")] == (0, 30, True)
    assert got[("gemma-4-26b", "009")] == (0, 30, True)
    assert got[("gemma-4-26b", "014a")] == (28, 30, True)
    assert got[("qwen3-14b", "014a")] == (15, 30, True)
    assert got[("mistral-small-3.2", "009")][2] is False  # benign utility 16/30
    for model in ("claude-sonnet-5.5", "gemini-3.8-flash", "gpt-6.1-terra"):
        assert got[(model, "014a")] == (0, 30, True)
        assert got[(model, "004")] == (None, None, True)


def test_committed_png_is_1080_by_1350() -> None:
    data = (ROOT / "docs" / "assets" / "memory-vs-direct.png").read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    assert (width, height) == (1080, 1350)
    assert (
        (ROOT / "docs" / "assets" / "memory-vs-direct.svg")
        .read_text(encoding="utf-8")
        .lstrip()
        .startswith("<?xml")
    )


def test_render(chart: ModuleType, tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    png, svg = tmp_path / "c.png", tmp_path / "c.svg"
    chart.render(chart.chart_data(), png, svg)
    data = png.read_bytes()
    assert (int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")) == (
        1080,
        1350,
    )
    assert svg.stat().st_size > 0
