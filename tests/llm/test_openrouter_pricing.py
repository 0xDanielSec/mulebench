"""Local OpenRouter price table and the openrouter CLI guards. Offline only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulebench.agents.base import TokenUsage
from mulebench.agents.llm.pricing_file import (
    DEFAULT_PRICING_FILE,
    PriceFileError,
    fixed_pricer,
    load_price_table,
)
from mulebench.agents.llm.transport import CassetteTransport, FakeTransport
from mulebench.cli import main

ROOT = Path(__file__).resolve().parents[2]
MODEL = "vendor/tiny-model"
HOST = "SyntheticHost"
TABLE = f"""
as_of = "2026-11-16"
source = "synthetic test table"

[[price]]
model = "{MODEL}"
host = "{HOST}"
input_per_mtok = 1.0
output_per_mtok = 4.0

[[price]]
model = "{MODEL}"
host = "TBD"
input_per_mtok = 9.0
output_per_mtok = 9.0
"""


def write(tmp_path: Path, text: str = TABLE) -> Path:
    path = tmp_path / "prices.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_price_is_per_model_and_host_and_tbd_never_matches(tmp_path: Path) -> None:
    table = load_price_table(write(tmp_path))
    assert table.as_of == "2026-11-16"
    assert len(table.sha256) == 64
    price = table.price(MODEL, HOST.lower())
    assert price is not None
    assert (price.input_per_mtok, price.output_per_mtok) == (1.0, 4.0)
    assert table.price(MODEL, "TBD") is None
    assert table.price(MODEL, "OtherHost") is None
    assert table.price("vendor/other", HOST) is None
    top = table.any_price(MODEL)
    assert top is not None
    assert top.output_per_mtok == 9.0


def test_fixed_pricer_uses_the_table_price() -> None:
    table_price = load_price_table(DEFAULT_PRICING_FILE.resolve()).any_price("qwen/qwen3-14b")
    assert table_price is not None
    cost = fixed_pricer(table_price)(TokenUsage(input_tokens=1_000_000, output_tokens=0), "x")
    assert cost == table_price.input_per_mtok


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("as_of = 'yesterday'\nsource = 'x'\n", "as_of"),
        ("as_of = '2026-11-16'\n", "source"),
        ("not toml = = 1", "not valid TOML"),
        (
            TABLE + f'\n[[price]]\nmodel = "{MODEL}"\nhost = "{HOST}"\n'
            "input_per_mtok = 1.0\noutput_per_mtok = 1.0\n",
            "duplicate",
        ),
        (
            "as_of = '2026-11-16'\nsource = 'x'\n[[price]]\nmodel = 'm'\nhost = 'h'\n"
            "input_per_mtok = -1.0\noutput_per_mtok = 1.0\n",
            "greater than or equal",
        ),
    ],
)
def test_malformed_tables_are_rejected(tmp_path: Path, text: str, error: str) -> None:
    with pytest.raises(PriceFileError, match=error):
        load_price_table(write(tmp_path, text))


def test_committed_table_is_valid_and_unpinned() -> None:
    table = load_price_table(ROOT / "pricing" / "openrouter.toml")
    assert table.models() == [
        "anthropic/claude-sonnet-5.5",
        "google/gemini-3.8-flash",
        "google/gemma-4-26b-a4b-it",
        "mistralai/mistral-small-3.2-24b-instruct",
        "openai/gpt-6.1-terra",
        "openai/gpt-oss-20b",
        "qwen/qwen3-14b",
    ]


def run(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--builtin",
        "--scenario",
        "pix-description-injection-001",
        "--agent",
        "llm",
        "--provider",
        "openrouter",
        "--model",
        MODEL,
        "--prompt-variants",
        "baseline",
        "--trials",
        "1",
        "--cassettes",
        str(tmp_path / "cas"),
        *extra,
    ]


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        (("--max-cost-usd", "1"), "--openrouter-host"),
        (("--openrouter-host", HOST), "--max-cost-usd"),
        (("--openrouter-host", HOST, "--max-cost-usd", "1", "--base-url", "http://x"), "base-url"),
        (("--openrouter-host", "TBD", "--max-cost-usd", "1"), "no price"),
        (("--openrouter-host", "OtherHost", "--max-cost-usd", "1"), "no price"),
        (
            ("--openrouter-host", HOST, "--max-cost-usd", "1", "--record", "--allow-remote"),
            "MB_LIVE",
        ),
    ],
)
def test_cli_refuses_without_host_cap_or_price(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    extra: tuple[str, ...],
    error: str,
) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    code = main(run(tmp_path, "--pricing", str(write(tmp_path)), *extra))
    assert code == 2
    assert error in capsys.readouterr().err


def test_cli_record_needs_allow_remote(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setenv("MB_OPENROUTER_API_KEY", "placeholder")
    args = run(tmp_path, "--pricing", str(write(tmp_path)), "--openrouter-host", HOST)
    assert main([*args, "--max-cost-usd", "1", "--record"]) == 2
    assert "--allow-remote" in capsys.readouterr().err


def test_routed_flags_refused_for_other_providers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = run(tmp_path, "--openrouter-host", HOST)
    args[args.index("openrouter")] = "openai-compatible"
    assert main(args) == 2
    assert "only apply to --provider openrouter" in capsys.readouterr().err


def respond(params: dict[str, Any], trial_key: str) -> dict[str, Any]:
    return {
        "id": "gen",
        "model": MODEL,
        "provider": HOST,
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "cost": 0.5},
    }


def test_replayed_run_reports_host_price_file_and_costs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mulebench.agents.llm.transport as transport_module

    prices = write(tmp_path)
    out = tmp_path / "r.json"
    args = [
        *run(tmp_path, "--pricing", str(prices), "--openrouter-host", HOST),
        "--openrouter-quantization",
        "fp8",
        "--max-cost-usd",
        "1",
        "--out",
        str(out),
    ]
    # First pass: the CLI's replay transport records synthetic responses.
    recorder = CassetteTransport(tmp_path / "cas", "record", FakeTransport(respond))
    with monkeypatch.context() as m:
        m.setattr(transport_module, "CassetteTransport", lambda *a, **k: recorder)
        assert main(args) in (0, 1)
    # Second pass: a plain replay of those cassettes.
    out.unlink()
    assert main(args) in (0, 1)
    report = json.loads(out.read_text(encoding="utf-8"))
    llm = report["llm"]
    assert llm["provider"] == "openrouter"
    assert llm["openrouter_host"] == HOST
    assert llm["openrouter_quantization"] == "fp8"
    stored = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "cas").iterdir()]
    sent = stored[0]["interactions"][0]["request"]["provider"]
    assert sent["quantizations"] == ["fp8"]
    routing = report["routing"]
    assert routing["calls"] >= 1
    assert routing["served_provider"] == {HOST: routing["calls"]}
    assert routing["served_quantization"] == {"null": routing["calls"]}
    assert routing["provider_cost_usd"] == pytest.approx(0.5 * routing["calls"])
    assert llm["pricing_file_sha256"] == load_price_table(prices).sha256
    assert report["pricing"]["as_of"] == "2026-11-16"
    trial = report["scenarios"][0]["cells"][0]["trials"][0]
    (call,) = trial["model_calls"]
    assert call["requested_model"] == MODEL
    assert call["served_provider"] == HOST
    assert call["provider_cost_usd"] == 0.5
    assert call["cost_usd"] == pytest.approx((1000 * 1.0 + 500 * 4.0) / 1_000_000)
