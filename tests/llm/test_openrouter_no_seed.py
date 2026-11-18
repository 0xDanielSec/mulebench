"""--allow-no-seed / --allow-no-temperature, and reasoning tokens in cost (offline).

Defaults send seed and temperature as before. With the flags the field is left out
of every request (runs and doctor probes), and the report records
seed_supported / temperature_supported = false. The doctor still fails on a host
without tool calling. Reasoning tokens are inside completion_tokens, so they are in
the cost; the report counts them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.openai_compat import parse_completion
from mulebench.agents.llm.openrouter import OpenRouterChatModel
from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import fixed_pricer
from mulebench.agents.llm.transport import TransportResponse
from mulebench.attacks import load_builtin
from mulebench.doctor_openrouter import run_openrouter_doctor
from mulebench.harness import run_all
from mulebench.reports import build_report

MODEL = "vendor/frontier-model"
HOST = "SyntheticHost"
SCENARIO = "memory-auto-persistent-exfiltration-014a"
FAKE_KEY = "sk-or-v1-" + "ef" * 32
PRICE = Price(input_per_mtok=2.0, output_per_mtok=10.0, cache_read_per_mtok=0.0)


class Recording:
    def __init__(self, reasoning: int = 0) -> None:
        self.requests: list[dict[str, Any]] = []
        self.reasoning = reasoning

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        self.requests.append(params)
        usage: dict[str, Any] = {"prompt_tokens": 100, "completion_tokens": 50}
        if self.reasoning:
            usage["completion_tokens_details"] = {"reasoning_tokens": self.reasoning}
        body = {
            "id": "gen",
            "model": MODEL,
            "provider": HOST,
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
            ],
            "usage": usage,
        }
        return TransportResponse(body=body)


def run(transport: Recording, *, seed: bool, temperature: bool) -> tuple[Any, LLMAgent]:
    scenario = next(s for s in load_builtin() if s.id == SCENARIO)
    agent = LLMAgent(
        OpenRouterChatModel(transport, HOST, None, send_seed=seed, send_temperature=temperature),
        model=MODEL,
        effort="none",
        meter=CostMeter(10.0),
        temperature=0.7 if temperature else None,
        seed=10000 if seed else None,
        pricer=fixed_pricer(PRICE),
    )
    outcome = run_all(
        [scenario], agent, prompt_variants=("baseline",), trials=1, presets=("vulnerable",)
    )
    return outcome, agent


def test_default_sends_seed_and_temperature() -> None:
    transport = Recording()
    run(transport, seed=True, temperature=True)
    assert transport.requests
    assert all("seed" in p and p["temperature"] == 0.7 for p in transport.requests)


def test_flags_leave_seed_and_temperature_out_of_every_request() -> None:
    transport = Recording()
    outcome, _ = run(transport, seed=False, temperature=False)
    assert transport.requests  # session, extraction and later session calls
    for p in transport.requests:
        assert "seed" not in p
        assert "temperature" not in p
        assert p["provider"]["require_parameters"] is True
    trial = outcome.results[0].cells[0].trials[0]
    assert trial.seed is None
    assert trial.temperature is None


def cli_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run", "--builtin", "--scenario", SCENARIO,
        "--agent", "llm", "--provider", "openrouter", "--allow-remote",
        "--model", "anthropic/claude-sonnet-5.5", "--openrouter-host", "Anthropic",
        "--preset", "vulnerable", "--prompt-variants", "baseline", "--trials", "1",
        "--temperature", "0.7", "--seed", "10000", "--max-cost-usd", "1.00",
        "--cassettes", str(tmp_path / "c"), *extra,
    ]  # fmt: skip


def test_cli_records_support_flags(tmp_path: Path) -> None:
    from mulebench.cli import _build_llm, _parser

    built = _build_llm(_parser().parse_args(cli_args(tmp_path)))
    assert not isinstance(built, int)
    agent, config, _, _ = built
    assert (config.seed_supported, config.temperature_supported) == (True, True)
    assert (config.seed, config.temperature) == (10000, 0.7)

    built = _build_llm(
        _parser().parse_args(cli_args(tmp_path, "--allow-no-seed", "--allow-no-temperature"))
    )
    assert not isinstance(built, int)
    agent, config, _, _ = built
    llm = config.model_dump(mode="json")
    assert llm["seed_supported"] is False
    assert llm["temperature_supported"] is False
    assert llm["seed"] is None
    assert llm["temperature"] is None
    assert llm["seed_derivation"] is None
    assert getattr(agent, "seed", "x") is None
    chat = getattr(agent, "chat", None)
    assert isinstance(chat, OpenRouterChatModel)
    assert (chat.send_seed, chat.send_temperature) == (False, False)


def test_flags_only_apply_to_openrouter(tmp_path: Path, capsys: Any) -> None:
    from mulebench.cli import main

    argv = [
        "run", "--builtin", "--scenario", SCENARIO, "--agent", "llm",
        "--provider", "openai-compatible", "--model", "m", "--cassettes", str(tmp_path),
        "--allow-no-seed",
    ]  # fmt: skip
    assert main(argv) == 2
    assert "only apply to --provider openrouter" in capsys.readouterr().err


# ---------------------------------------------------------------- doctor

ENDPOINTS = {
    "data": {
        "id": MODEL,
        "endpoints": [
            {
                "provider_name": HOST,
                "tag": "synthetic",
                "quantization": "unknown",
                "context_length": 1000000,
                "pricing": {"prompt": "0.000002", "completion": "0.00001"},
                "supported_parameters": ["tools", "max_tokens"],
            },
            {
                "provider_name": "NoToolsHost",
                "quantization": "unknown",
                "context_length": 1000000,
                "pricing": {"prompt": "0.000001", "completion": "0.000005"},
                "supported_parameters": ["max_tokens", "seed", "temperature"],
            },
        ],
    }
}


def ping(call_id: str, token: str) -> dict[str, Any]:
    call = {
        "id": call_id,
        "type": "function",
        "function": {"name": "ping", "arguments": json.dumps({"token": token})},
    }
    return {
        "id": "gen",
        "model": MODEL,
        "provider": HOST,
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


def prices(tmp_path: Path) -> Path:
    path = tmp_path / "p.toml"
    path.write_text(
        f'as_of = "2026-11-18"\nsource = "t"\n[[price]]\nmodel = "{MODEL}"\nhost = "{HOST}"\n'
        "input_per_mtok = 2.0\noutput_per_mtok = 10.0\n"
        f'[[price]]\nmodel = "{MODEL}"\nhost = "NoToolsHost"\n'
        "input_per_mtok = 1.0\noutput_per_mtok = 5.0\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    monkeypatch.setenv("MB_OPENROUTER_API_KEY", FAKE_KEY)


def test_doctor_fails_without_seed_unless_allowed(tmp_path: Path) -> None:
    client, _ = mock()
    checks = run_openrouter_doctor(
        MODEL, host=HOST, pricing=prices(tmp_path), allow_remote=True, client=client
    )
    assert checks[-1].level == "fail"
    assert "no host supports tools, seed, temperature" in checks[-1].detail
    client, _ = mock()
    checks = run_openrouter_doctor(
        MODEL,
        host=HOST,
        pricing=prices(tmp_path),
        allow_remote=True,
        client=client,
        require_seed=False,
        require_temperature=False,
    )
    by_name = {c.name: c for c in checks}
    assert by_name["host"].level == "ok"
    assert by_name["price"].level == "ok"
    assert by_name["seed"].level == "warn"
    assert by_name["temperature"].level == "warn"


def test_doctor_still_fails_on_missing_tools(tmp_path: Path) -> None:
    client, _ = mock()
    checks = run_openrouter_doctor(
        MODEL,
        host="NoToolsHost",
        pricing=prices(tmp_path),
        allow_remote=True,
        client=client,
        require_seed=False,
        require_temperature=False,
    )
    assert checks[-1].level == "fail"
    assert "no endpoint with tools" in checks[-1].detail


def test_doctor_probes_omit_seed_and_temperature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, seen = mock([ping("c1", "mb-probe"), ping("c2", "mb-probe-2")])
    checks = run_openrouter_doctor(
        MODEL,
        host=HOST,
        pricing=prices(tmp_path),
        allow_remote=True,
        client=client,
        require_seed=False,
        require_temperature=False,
    )
    chats = [json.loads(r.content) for r in seen if r.url.path.endswith("/chat/completions")]
    assert len(chats) == 2
    assert all("seed" not in c and "temperature" not in c for c in chats)
    assert {c.name: c.level for c in checks}["tool calling"] == "ok"


# -------------------------------------------------------------- reasoning


def test_reasoning_tokens_are_in_output_tokens_and_cost() -> None:
    body = Recording(reasoning=40).send({}, "k").body
    response = parse_completion(body)
    assert response.usage.output_tokens == 50  # completion_tokens, reasoning included
    assert response.reasoning_tokens == 40
    # A count above completion_tokens is recorded, never added (OpenRouter bills
    # completion_tokens; seen in pilot 08 qwen3-14b).
    body["usage"]["completion_tokens_details"] = {"reasoning_tokens": 80}
    assert parse_completion(body).usage.output_tokens == 50


def test_report_counts_reasoning_tokens() -> None:
    transport = Recording(reasoning=40)
    outcome, agent = run(transport, seed=True, temperature=True)
    report = build_report(outcome, agent, prompt_variants=["baseline"], trials=1)
    assert report.routing is not None
    assert report.routing.calls == len(transport.requests)
    assert report.routing.reasoning_tokens == 40 * len(transport.requests)
    assert report.routing.calls_with_reasoning == len(transport.requests)
    per_call = (100 * 2.0 + 50 * 10.0) / 1_000_000
    assert agent.meter.spent_usd == round(per_call * len(transport.requests), 6)
