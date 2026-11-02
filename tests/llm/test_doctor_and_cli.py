"""`mulebench doctor` and the openai-compatible CLI flags. Offline: httpx.MockTransport only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.cli import main
from mulebench.doctor import (
    MAX_TOKENS_HELP,
    MIN_NUM_CTX,
    PROBE_MAX_TOKENS,
    REASONING_MAX_TOKENS,
    TWO_TURN_CHECK,
    Check,
    print_checks,
    run_doctor,
)

URL = "http://localhost:11434/v1"
TAGS = {"models": [{"name": "tiny:1b", "digest": "sha256:abc"}]}


def show(num_ctx: int | None) -> dict[str, Any]:
    params = "stop x" if num_ctx is None else f"num_ctx {num_ctx}"
    return {"details": {"quantization_level": "Q4_K_M"}, "parameters": params, "model_info": {}}


def server(
    num_ctx: int | None = MIN_NUM_CTX, chat: dict[str, Any] | None = None, tags: Any = TAGS
) -> tuple[httpx.Client, list[str]]:
    hits: list[str] = []
    routes: dict[str, Any] = {
        "GET /api/version": {"version": "0.12.0"},
        "GET /api/tags": tags,
        "POST /api/show": show(num_ctx),
        "POST /v1/chat/completions": chat,
    }

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        hits.append(key)
        body = routes.get(key)
        return httpx.Response(404) if body is None else httpx.Response(200, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler)), hits


def levels(checks: list[Any]) -> dict[str, str]:
    return {c.name: c.level for c in checks}


def ping(arguments: str = '{"token": "mb-probe"}', name: str = "ping") -> dict[str, Any]:
    call = {"id": "c", "type": "function", "function": {"name": name, "arguments": arguments}}
    return {
        "choices": [
            {"message": {"role": "assistant", "tool_calls": [call]}, "finish_reason": "tool_calls"}
        ]
    }


# --------------------------------------------------------------- doctor


def test_all_ok_without_mb_live_skips_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    client, hits = server()
    checks = run_doctor("tiny:1b", URL, client=client)
    assert levels(checks) == {
        "server": "ok",
        "model": "ok",
        "num_ctx": "ok",
        "tool calling": "skip",
    }
    assert "POST /v1/chat/completions" not in hits  # no inference without MB_LIVE
    assert print_checks(checks, out=lambda line: None) == 0


@pytest.mark.parametrize("num_ctx", [4096, None])
def test_small_or_unknown_num_ctx_warns_and_explains(
    monkeypatch: pytest.MonkeyPatch, num_ctx: int | None
) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    checks = run_doctor("tiny:1b", URL, client=server(num_ctx)[0])
    (ctx,) = [c for c in checks if c.name == "num_ctx"]
    assert ctx.level == "warn"
    assert "OLLAMA_CONTEXT_LENGTH" in ctx.detail
    assert print_checks(checks, out=lambda line: None) == 0  # a warning is not a failure


def test_missing_model_fails_with_pull_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    checks = run_doctor("big:70b", URL, client=server()[0])
    assert checks[-1].level == "fail"
    assert "ollama pull big:70b" in checks[-1].detail
    assert print_checks(checks, out=lambda line: None) == 1


def test_latest_tag_matches_bare_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    client, _ = server(tags={"models": [{"name": "tiny:latest"}]})
    assert levels(run_doctor("tiny", URL, client=client))["model"] == "ok"


def test_server_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    (check,) = run_doctor("tiny:1b", URL, client=client)
    assert (check.level, check.name) == ("fail", "server")


@pytest.mark.parametrize(
    ("chat", "level", "detail"),
    [
        (ping(), "ok", "valid tool call"),
        (ping('{"token": '), "fail", "malformed tool call (json)"),
        (
            {"choices": [{"message": {"role": "assistant", "content": "pong"}}]},
            "fail",
            "without calling",
        ),
    ],
)
def test_probe_with_mb_live(
    monkeypatch: pytest.MonkeyPatch, chat: dict[str, Any], level: str, detail: str
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, hits = server(chat=chat)
    probe = next(c for c in run_doctor("tiny:1b", URL, client=client) if c.name == "tool calling")
    assert (probe.name, probe.level) == ("tool calling", level)
    assert detail in probe.detail
    # One call; a second only after a valid first tool call (two-turn probe).
    assert hits.count("POST /v1/chat/completions") == (2 if level == "ok" else 1)


# ------------------------------------------------------------------ CLI


def test_cli_doctor_refuses_remote_hosts() -> None:
    assert main(["doctor", "--model", "m", "--base-url", "https://llm.example.test/v1"]) == 2


def test_cli_local_only_flags_rejected_for_anthropic(tmp_path: Path) -> None:
    argv = ["run", "--agent", "llm", "--model", "m", "--cassettes", str(tmp_path), "--seed", "1"]
    assert main(argv) == 2


def local(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--agent",
        "llm",
        "--provider",
        "openai-compatible",
        "--model",
        "tiny:1b",
        "--cassettes",
        str(tmp_path / "cassettes"),
        *extra,
    ]


def test_cli_local_refuses_remote_base_url(tmp_path: Path) -> None:
    assert main(local(tmp_path, "--base-url", "https://llm.example.test/v1")) == 2


def test_cli_local_record_needs_mb_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    assert main(local(tmp_path, "--record")) == 2
    assert "MB_LIVE=1" in capsys.readouterr().err


def test_cli_local_replay_without_cassettes_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(local(tmp_path)) == 2
    assert "no recorded response" in capsys.readouterr().err


def test_cli_local_needs_cassettes_dir() -> None:
    argv = ["run", "--agent", "llm", "--provider", "openai-compatible", "--model", "m"]
    assert main(argv) == 2


# ------------------------------------------- reasoning models (qwen3-like)

THINK = "The user wants ping. " * 20  # ~100+ tokens of reasoning before any call


def reasoning_server(shape: str, think_tokens: int = 300) -> tuple[httpx.Client, list[Any]]:
    """Fake qwen3: reasons first; only calls the tool if max_tokens leaves room."""
    sent: list[Any] = []

    def chat(req: httpx.Request) -> dict[str, Any]:
        params = json.loads(req.content)
        sent.append(params)
        reasoning = {"reasoning": THINK} if shape == "field" else {}
        if params["max_tokens"] <= think_tokens:
            content = "" if shape == "field" else f"<think>{THINK}"  # cut off mid-thought
            message: dict[str, Any] = {"role": "assistant", "content": content, **reasoning}
            return {"choices": [{"message": message, "finish_reason": "length"}]}
        content = "" if shape == "field" else f"<think>{THINK}</think>"
        call = {
            "id": "c",
            "type": "function",
            "function": {"name": "ping", "arguments": '{"token": "mb-probe"}'},
        }
        message = {"role": "assistant", "content": content, "tool_calls": [call], **reasoning}
        return {"choices": [{"message": message, "finish_reason": "tool_calls"}]}

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        if key == "POST /v1/chat/completions":
            return httpx.Response(200, json=chat(req))
        routes: dict[str, Any] = {
            "GET /api/version": {"version": "0.40.13"},
            "GET /api/tags": {"models": [{"name": "qwen3-14b-8k:latest", "digest": "d"}]},
            "POST /api/show": show(8192),
        }
        body = routes.get(key)
        return httpx.Response(404) if body is None else httpx.Response(200, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler)), sent


@pytest.mark.parametrize("shape", ["think_tags", "field"])
def test_reasoning_model_passes_with_the_probe_budget(
    monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, sent = reasoning_server(shape)
    checks = run_doctor("qwen3-14b-8k", URL, client=client)
    probe = next(c for c in checks if c.name == "tool calling")
    assert (probe.level, probe.detail) == ("ok", "the model returned a valid tool call")
    assert sent[0]["max_tokens"] == PROBE_MAX_TOKENS
    # A passing probe still recommends a larger budget for runs.
    assert checks[-1] == Check("warn", "max_tokens", MAX_TOKENS_HELP)
    assert f"--max-tokens {REASONING_MAX_TOKENS}" in MAX_TOKENS_HELP


def test_plain_model_gets_no_max_tokens_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    call = {"id": "c", "type": "function", "function": {"name": "ping", "arguments": "{}"}}
    chat = {
        "choices": [
            {
                "message": {"role": "assistant", "content": "", "tool_calls": [call]},
                "finish_reason": "tool_calls",
            }
        ]
    }
    checks = run_doctor("tiny:1b", URL, client=server(chat=chat)[0])
    assert checks[-1].name == "tool calling after a tool result"
    assert all(c.name != "max_tokens" for c in checks)


@pytest.mark.parametrize("shape", ["think_tags", "field"])
def test_old_budget_reproduces_the_failure_with_a_diagnostic(
    monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """The live failure: a budget of 64 tokens ends inside the reasoning."""
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setattr("mulebench.doctor.PROBE_MAX_TOKENS", 64)
    client, _ = reasoning_server(shape)
    checks = run_doctor("qwen3-14b-8k", URL, client=client)
    assert checks[-1].name == "max_tokens"
    probe = checks[-2]
    assert probe.level == "fail"
    assert probe.detail == (
        "the model answered without calling the tool; finish_reason=length "
        "reasoning_present=yes content_empty=yes "
        "(the output hit max_tokens=64 before a tool call; reasoning used the budget)"
    )
    assert "ping" not in probe.detail.split(";")[1]  # no model text in the diagnostic


def test_plain_text_answer_diagnostic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    chat = {
        "choices": [{"message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}]
    }
    probe = run_doctor("tiny:1b", URL, client=server(chat=chat)[0])[-1]
    assert probe.detail.endswith("finish_reason=stop reasoning_present=no content_empty=no")
    assert "pong" not in probe.detail


def test_doctor_shows_digest_of_a_derived_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    client, _ = server(tags={"models": [{"name": "llama31-8b-8k:latest", "digest": "sha256:d"}]})
    model = [c for c in run_doctor("llama31-8b-8k", URL, client=client) if c.name == "model"]
    assert model[0].detail == "llama31-8b-8k digest=sha256:d quantization=Q4_K_M"


# ------------------------------------------------------- two-turn probe


def two_turn_server(
    second: dict[str, Any], prompt_tokens: tuple[int, int] = (100, 140)
) -> tuple[httpx.Client, list[Any]]:
    """First chat call returns a ping; the second returns `second`."""
    sent: list[Any] = []

    def handler(req: httpx.Request) -> httpx.Response:
        key = f"{req.method} {req.url.path}"
        if key == "POST /v1/chat/completions":
            params = json.loads(req.content)
            sent.append(params)
            body = ping() if len(sent) == 1 else second
            body = {
                **body,
                "usage": {"prompt_tokens": prompt_tokens[len(sent) - 1], "completion_tokens": 5},
            }
            return httpx.Response(200, json=body)
        routes: dict[str, Any] = {
            "GET /api/version": {"version": "0.12.0"},
            "GET /api/tags": TAGS,
            "POST /api/show": show(MIN_NUM_CTX),
        }
        route = routes.get(key)
        return httpx.Response(404) if route is None else httpx.Response(200, json=route)

    return httpx.Client(transport=httpx.MockTransport(handler)), sent


def second_turn(checks: list[Any]) -> Any:
    return next(c for c in checks if c.name == TWO_TURN_CHECK)


def test_two_turn_probe_passes_and_sends_the_tool_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    client, sent = two_turn_server(ping('{"token": "mb-probe-2"}'))
    check = second_turn(run_doctor("tiny:1b", URL, client=client))
    assert (check.level, check.detail) == (
        "ok",
        "the model called a tool again after a tool result",
    )
    assert len(sent) == 2
    roles = [m["role"] for m in sent[1]["messages"]]
    assert roles == ["system", "user", "assistant", "tool"]
    assert sent[1]["messages"][3]["tool_call_id"] == "c"
    assert sent[1]["tools"] == sent[0]["tools"]


def test_two_turn_probe_fails_when_no_second_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    empty = {
        "choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]
    }
    client, _ = two_turn_server(empty)
    checks = run_doctor("tiny:1b", URL, client=client)
    assert levels(checks)["tool calling"] == "ok"
    check = second_turn(checks)
    assert check.level == "fail"
    assert "without calling the tool" in check.detail
    assert print_checks(checks, out=lambda _: None) == 1


def test_two_turn_probe_detects_a_template_that_drops_the_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mistral-nemo pattern: prompt_tokens fall after a tool result."""
    monkeypatch.setenv("MB_LIVE", "1")
    client, _ = two_turn_server(ping('{"token": "mb-probe-2"}'), prompt_tokens=(790, 230))
    check = second_turn(run_doctor("tiny:1b", URL, client=client))
    assert check.level == "fail"
    assert "shrank from 790 to 230 tokens" in check.detail


def test_no_second_turn_after_a_failed_first_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    chat = {"choices": [{"message": {"role": "assistant", "content": "pong"}}]}
    checks = run_doctor("tiny:1b", URL, client=server(chat=chat)[0])
    assert all(c.name != TWO_TURN_CHECK for c in checks)
