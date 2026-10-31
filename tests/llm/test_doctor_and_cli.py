"""`mulebench doctor` and the openai-compatible CLI flags. Offline: httpx.MockTransport only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from mulebench.cli import main
from mulebench.doctor import MIN_NUM_CTX, print_checks, run_doctor

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
    probe = run_doctor("tiny:1b", URL, client=client)[-1]
    assert (probe.name, probe.level) == ("tool calling", level)
    assert detail in probe.detail
    assert hits.count("POST /v1/chat/completions") == 1  # exactly one probe call


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
