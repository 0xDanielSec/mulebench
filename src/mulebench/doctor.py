"""`mulebench doctor`: is a local OpenAI-compatible server ready for a run?

Checks, in order:
1. the server answers (Ollama /api/version, else /v1/models);
2. the model is pulled, and its metadata (digest, quantization, num_ctx);
3. the effective num_ctx is at least MIN_NUM_CTX (warning otherwise);
4. tool calling works: ONE tiny probe chat call, only with MB_LIVE=1.

Checks 1-3 make no inference call and run without MB_LIVE, against loopback
hosts only unless --allow-remote.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx

from mulebench.agents.llm.http_transport import (
    LocalServerClient,
    OpenAICompatTransport,
    ServerUnreachable,
)
from mulebench.agents.llm.model import ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.openai_compat import ResponseShapeError, parse_completion
from mulebench.agents.llm.transport import LIVE_ENV

MIN_NUM_CTX = 8192
Level = Literal["ok", "warn", "fail", "skip"]

PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "ping",
        "description": "Health check. Call it with the given token.",
        "parameters": {
            "type": "object",
            "properties": {"token": {"type": "string"}},
            "required": ["token"],
        },
    },
}
CONTEXT_HELP = (
    "Ollama's default context window is small. Set OLLAMA_CONTEXT_LENGTH=8192 (or more) "
    "in the environment of `ollama serve` and restart it, or set `PARAMETER num_ctx` in a "
    "Modelfile. Prompts beyond num_ctx are truncated silently, which makes the model lose "
    "the tool definitions or the session note."
)


@dataclass(frozen=True)
class Check:
    level: Level
    name: str
    detail: str


def run_doctor(
    model: str,
    base_url: str,
    *,
    allow_remote: bool = False,
    client: httpx.Client | None = None,
) -> list[Check]:
    """The checks, in order. Stops after a failure that makes the rest meaningless."""
    checks: list[Check] = []
    server = LocalServerClient(base_url, allow_remote=allow_remote, client=client)
    try:
        version = server.version()
    except ServerUnreachable as exc:
        return [Check("fail", "server", f"no answer: {exc}")]
    checks.append(
        Check("ok", "server", f"Ollama {version}" if version else "OpenAI-compatible server")
    )

    names = server.models()
    if model not in names and f"{model}:latest" not in names:
        hint = f"run `ollama pull {model}`" if version else "load it in the server"
        checks.append(Check("fail", "model", f"{model!r} is not available; {hint}"))
        return checks
    meta = server.server_meta(model)
    checks.append(
        Check(
            "ok",
            "model",
            f"{model} digest={meta.digest or '?'} quantization={meta.quantization or '?'}",
        )
    )

    if meta.num_ctx is None:
        checks.append(Check("warn", "num_ctx", "effective context window unknown. " + CONTEXT_HELP))
    elif meta.num_ctx < MIN_NUM_CTX:
        checks.append(
            Check(
                "warn",
                "num_ctx",
                f"{meta.num_ctx} ({meta.num_ctx_source}) < {MIN_NUM_CTX}. " + CONTEXT_HELP,
            )
        )
    else:
        checks.append(Check("ok", "num_ctx", f"{meta.num_ctx} ({meta.num_ctx_source})"))

    checks.append(_probe(model, base_url, allow_remote, client))
    return checks


def _probe(model: str, base_url: str, allow_remote: bool, client: httpx.Client | None) -> Check:
    if os.environ.get(LIVE_ENV) != "1":
        return Check("skip", "tool calling", f"probe needs {LIVE_ENV}=1 (one tiny chat call)")
    transport = OpenAICompatTransport(base_url, allow_remote=allow_remote, client=client)
    params = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a health check. Use the ping tool."},
            {"role": "user", "content": "Call ping with token 'mb-probe'."},
        ],
        "tools": [PROBE_TOOL],
        "tool_choice": "auto",
        "temperature": 0.0,
        "seed": 0,
        "max_tokens": 64,
        "stream": False,
    }
    try:
        response = parse_completion(transport.send(params, "doctor/probe").body)
    except (ModelCallError, ModelRequestInvalid, ResponseShapeError) as exc:
        return Check("fail", "tool calling", f"probe failed: {exc}")
    if response.invalid_tool_calls:
        bad = response.invalid_tool_calls[0]
        return Check("fail", "tool calling", f"malformed tool call ({bad.kind}): {bad.detail}")
    if not any(c.name == "ping" for c in response.tool_calls):
        return Check("fail", "tool calling", "the model answered without calling the tool")
    return Check("ok", "tool calling", "the model returned a valid tool call")


def print_checks(checks: list[Check], out: Callable[[str], None] = print) -> int:
    for c in checks:
        out(f"[{c.level:<4}] {c.name}: {c.detail}")
    return 1 if any(c.level == "fail" for c in checks) else 0
