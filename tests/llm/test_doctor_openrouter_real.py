"""doctor host/price rule against the real DeepInfra endpoint listings of the
pilot 08 models (tests/fixtures/openrouter, 2026-11-16) and the committed
price table. Offline: the listings are served by httpx.MockTransport."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.doctor_openrouter import run_openrouter_doctor

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "openrouter"
PRICING = ROOT / "pricing" / "openrouter.toml"
HOST = "DeepInfra"


def listing(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return data


def client_for(data: dict[str, Any]) -> httpx.Client:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path.endswith("/endpoints")
        return httpx.Response(200, json=data)

    return httpx.Client(transport=httpx.MockTransport(handler))


def doctor(data: dict[str, Any], quantization: str, pricing: Path = PRICING) -> list[Any]:
    return run_openrouter_doctor(
        data["data"]["id"],
        host=HOST,
        quantization=quantization,
        pricing=pricing,
        allow_remote=True,
        client=client_for(data),
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    monkeypatch.setenv("MB_OPENROUTER_API_KEY", "placeholder")


@pytest.mark.parametrize(
    ("name", "quantization", "eligible"),
    [
        ("gpt-oss-20b.json", "bf16", 2),
        ("mistral-small-3.2-24b-instruct.json", "fp8", 3),
        ("qwen3-14b.json", "fp8", 1),
        ("gemma-4-26b-a4b-it.json", "fp8", 1),
    ],
)
def test_real_listings_pass_with_eligible_endpoints(
    name: str, quantization: str, eligible: int
) -> None:
    checks = doctor(listing(name), quantization)
    by_name = {c.name: c for c in checks}
    assert by_name["host"].level == "ok", by_name["host"].detail
    assert f"{eligible} eligible DeepInfra {quantization} endpoint(s)" in by_name["host"].detail
    assert "any of them may serve" in by_name["host"].detail
    assert by_name["price"].level == "ok", by_name["price"].detail
    assert checks[-1].level == "skip"  # no live probe without MB_LIVE


def test_qwen3_tool_less_endpoints_are_not_eligible() -> None:
    data = listing("qwen3-14b.json")
    tags = [e["tag"] for e in data["data"]["endpoints"]]
    assert len(tags) == 3
    host = next(c for c in doctor(data, "fp8") if c.name == "host")
    assert "(deepinfra/fp8)" in host.detail  # flex and priority lack tools


def write_table(tmp_path: Path, model: str, pin: float, pout: float) -> Path:
    path = tmp_path / "p.toml"
    path.write_text(
        f'as_of = "2026-11-16"\nsource = "t"\n[[price]]\nmodel = "{model}"\nhost = "{HOST}"\n'
        f"input_per_mtok = {pin}\noutput_per_mtok = {pout}\n",
        encoding="utf-8",
    )
    return path


def test_price_below_any_eligible_endpoint_fails(tmp_path: Path) -> None:
    data = listing("mistral-small-3.2-24b-instruct.json")
    # 0.112 is below the priority endpoint's 0.1125 input price
    low = write_table(tmp_path, data["data"]["id"], 0.112, 0.300)
    price = next(c for c in doctor(data, "fp8", low) if c.name == "price")
    assert price.level == "fail"
    assert "underestimate" in price.detail
    # qwen3: the tool-less priority endpoint (0.18/0.36) does not raise the bar
    qwen = listing("qwen3-14b.json")
    ok = write_table(tmp_path, qwen["data"]["id"], 0.12, 0.24)
    assert next(c for c in doctor(qwen, "fp8", ok) if c.name == "price").level == "ok"


def test_short_context_endpoint_fails() -> None:
    data = listing("gpt-oss-20b.json")
    data["data"]["endpoints"][0]["context_length"] = 4096
    host = next(c for c in doctor(data, "bf16") if c.name == "host")
    assert host.level == "fail"
    assert "context below 8192" in host.detail
