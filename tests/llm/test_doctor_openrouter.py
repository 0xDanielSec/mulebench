"""`mulebench doctor --provider openrouter`. Offline: httpx.MockTransport only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.cli import main
from mulebench.doctor_openrouter import run_openrouter_doctor

MODEL = "vendor/tiny-model"
HOST = "SyntheticHost"
FAKE_KEY = "sk-or-v1-" + "cd" * 32  # built: not itself a prepublish finding
ENDPOINTS = {
    "data": {
        "id": MODEL,
        "endpoints": [
            {
                "provider_name": HOST,
                "quantization": "fp8",
                "context_length": 131072,
                "pricing": {"prompt": "0.0000001", "completion": "0.0000003"},
                "supported_parameters": ["tools", "seed", "temperature", "max_tokens"],
            },
            {
                "provider_name": "NoToolsHost",
                "quantization": "bf16",
                "context_length": 32768,
                "pricing": {"prompt": "0.00000005", "completion": "0.0000001"},
                "supported_parameters": ["temperature"],
            },
        ],
    }
}


def prices(tmp_path: Path, pin: float = 0.1, pout: float = 0.3) -> Path:
    path = tmp_path / "p.toml"
    path.write_text(
        f'as_of = "2026-11-16"\nsource = "t"\n[[price]]\nmodel = "{MODEL}"\nhost = "{HOST}"\n'
        f"input_per_mtok = {pin}\noutput_per_mtok = {pout}\n",
        encoding="utf-8",
    )
    return path


def ping(token: str, call_id: str, provider: str = HOST) -> dict[str, Any]:
    call = {
        "id": call_id,
        "type": "function",
        "function": {"name": "ping", "arguments": json.dumps({"token": token})},
    }
    return {
        "id": "gen",
        "model": MODEL,
        "provider": provider,
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": "", "tool_calls": [call]},
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 5},
    }


def mock(chat: list[dict[str, Any]] | None = None) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    replies = list(chat or [])

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path == f"/api/v1/models/{MODEL}/endpoints":
            return httpx.Response(200, json=ENDPOINTS)
        if req.url.path == "/api/v1/chat/completions" and replies:
            return httpx.Response(200, json=replies.pop(0))
        return httpx.Response(404, json={"error": {"code": 404}})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def levels(checks: list[Any]) -> list[tuple[str, str]]:
    return [(c.name, c.level) for c in checks]


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    monkeypatch.setenv("MB_OPENROUTER_API_KEY", FAKE_KEY)


def test_needs_allow_remote(tmp_path: Path) -> None:
    client, seen = mock()
    checks = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path), allow_remote=False, client=client
    )
    assert levels(checks) == [("remote", "fail")]
    assert seen == []


def test_lists_hosts_without_key_or_live_calls(tmp_path: Path) -> None:
    client, seen = mock()
    checks = run_openrouter_doctor(
        MODEL, host=None, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert levels(checks) == [
        ("key", "ok"),
        ("endpoint", "ok"),
        ("endpoint", "warn"),
        ("host", "warn"),
    ]
    assert "quantization=fp8" in checks[1].detail
    assert "$0.100/$0.300" in checks[1].detail
    assert "missing tools, seed" in checks[2].detail
    assert f"one of: {HOST}" in checks[3].detail
    assert [r.url.path for r in seen] == [f"/api/v1/models/{MODEL}/endpoints"]
    assert "authorization" not in seen[0].headers
    assert all(FAKE_KEY not in c.detail for c in checks)


def test_key_presence_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_OPENROUTER_API_KEY")
    client, _ = mock()
    checks = run_openrouter_doctor(
        MODEL, host=None, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert checks[0].level == "fail"
    assert "is not set" in checks[0].detail


@pytest.mark.parametrize(
    ("host", "detail"),
    [("OtherHost", "does not serve"), ("NoToolsHost", "missing tools")],
)
def test_host_must_serve_the_model_with_tools(tmp_path: Path, host: str, detail: str) -> None:
    client, _ = mock()
    checks = run_openrouter_doctor(
        MODEL, host=host, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert checks[-1].level == "fail"
    assert detail in checks[-1].detail


def test_unknown_model(tmp_path: Path) -> None:
    client, _ = mock()
    checks = run_openrouter_doctor(
        "vendor/none", host=HOST, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert checks[-1].level == "fail"
    assert "not available" in checks[-1].detail


def test_price_table_must_have_the_host_and_matching_price(tmp_path: Path) -> None:
    client, _ = mock()
    ok = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert ("price", "ok") in levels(ok)
    assert levels(ok)[-1] == ("tool calling", "skip")
    differs = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path, pout=0.2), allow_remote=True, client=client
    )
    assert ("price", "fail") in levels(differs)
    missing = tmp_path / "none.toml"
    missing.write_text('as_of = "2026-11-16"\nsource = "t"\n', encoding="utf-8")
    absent = run_openrouter_doctor(
        MODEL, host=HOST, pricing=missing, allow_remote=True, client=client
    )
    assert ("price", "fail") in levels(absent)


def test_live_probes_are_pinned_and_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, seen = mock([ping("mb-probe", "c1"), ping("mb-probe-2", "c2")])
    checks = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert levels(checks)[-3:] == [
        ("tool calling", "ok"),
        ("tool calling after a tool result", "ok"),
        ("served quantization", "warn"),
    ]
    chats = [r for r in seen if r.url.path.endswith("/chat/completions")]
    assert len(chats) == 2
    for r in chats:
        body = json.loads(r.content)
        assert body["provider"]["order"] == [HOST]
        assert body["provider"]["allow_fallbacks"] is False
        assert r.headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert all(FAKE_KEY not in c.detail for c in checks)


def test_live_probe_from_another_host_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, _ = mock([ping("mb-probe", "c1", provider="OtherHost")])
    checks = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert checks[-1].level == "fail"
    assert "provider_mismatch" in checks[-1].detail


def test_cli_flags(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--model", MODEL, "--provider", "openrouter"]) == 1
    assert "--allow-remote" in capsys.readouterr().out
    assert main(["doctor", "--model", "m", "--openrouter-host", HOST]) == 2
    assert "only apply to --provider openrouter" in capsys.readouterr().err


SAME_HOST = {
    "data": {
        "id": MODEL,
        "endpoints": [
            {
                "provider_name": HOST,
                "quantization": "fp8",
                "pricing": {"prompt": "0.0000001", "completion": "0.0000003"},
                "supported_parameters": ["tools", "seed", "temperature"],
            },
            {
                "provider_name": HOST,
                "quantization": "bf16",
                "pricing": {"prompt": "0.0000002", "completion": "0.0000004"},
                "supported_parameters": ["temperature"],
            },
        ],
    }
}


def same_host_client(chat: list[dict[str, Any]] | None = None) -> httpx.Client:
    replies = list(chat or [])

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/endpoints"):
            return httpx.Response(200, json=SAME_HOST)
        return httpx.Response(200, json=replies.pop(0))

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_several_endpoints_at_one_host_need_a_quantization_pin(tmp_path: Path) -> None:
    p = prices(tmp_path, pin=0.2, pout=0.4)  # the highest of the host's endpoints
    unpinned = run_openrouter_doctor(
        MODEL, host=HOST, pricing=p, allow_remote=True, client=same_host_client()
    )
    assert unpinned[-1].level == "fail"
    assert "--openrouter-quantization" in unpinned[-1].detail
    no_tools = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="bf16",
        pricing=p,
        allow_remote=True,
        client=same_host_client(),
    )
    assert no_tools[-1].level == "fail"
    assert "missing tools" in no_tools[-1].detail
    absent = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="int4",
        pricing=p,
        allow_remote=True,
        client=same_host_client(),
    )
    assert "no int4 endpoint" in absent[-1].detail
    pinned = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="fp8",
        pricing=p,
        allow_remote=True,
        client=same_host_client(),
    )
    assert ("host", "ok") in levels(pinned)
    price = next(c for c in pinned if c.name == "price")
    assert price.level == "ok"
    assert "highest of the host's endpoints" in price.detail


def test_live_probe_reports_and_checks_served_quantization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    p = prices(tmp_path, pin=0.2, pout=0.4)
    good = [
        {**ping("mb-probe", "c1"), "quantization": "fp8"},
        {**ping("mb-probe-2", "c2"), "quantization": "fp8"},
    ]
    ok = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="fp8",
        pricing=p,
        allow_remote=True,
        client=same_host_client(good),
    )
    assert levels(ok)[-1] == ("served quantization", "ok")
    assert ok[-1].detail == "fp8"
    bad = [{**ping("mb-probe", "c1"), "quantization": "bf16"}]
    wrong = run_openrouter_doctor(
        MODEL,
        host=HOST,
        quantization="fp8",
        pricing=p,
        allow_remote=True,
        client=same_host_client(bad),
    )
    assert wrong[-1].level == "fail"
    assert "quantization_mismatch" in wrong[-1].detail
