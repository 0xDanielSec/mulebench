"""`mulebench doctor`: is a local OpenAI-compatible server ready for a run?

Checks, in order:
1. the server answers (Ollama /api/version, else /v1/models);
2. the model is pulled, and its metadata (digest, quantization, num_ctx);
3. the effective num_ctx is at least MIN_NUM_CTX (warning otherwise);
4. tool calling works: ONE probe chat call, only with MB_LIVE=1. On failure it
   prints finish_reason, whether reasoning was present and whether the content
   was empty; never model text or headers.

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
    same_model,
)
from mulebench.agents.llm.model import ChatResponse, ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.openai_compat import ResponseShapeError, parse_completion
from mulebench.agents.llm.transport import LIVE_ENV

MIN_NUM_CTX = 8192
# Reasoning models (e.g. qwen3) think before they call a tool; a small budget
# ends the probe with finish_reason=length and no tool call.
PROBE_MAX_TOKENS = 2048
TWO_TURN_CHECK = "tool calling after a tool result"
# Recommended --max-tokens for runs with a reasoning model. A probe passing at
# 2048 does not mean a trial fits: trials need several calls with longer
# prompts, and pilot 02 (qwen3-14b, 2048) had model calls cut at `length`.
REASONING_MAX_TOKENS = 4096
MAX_TOKENS_HELP = (
    f"reasoning model: run with --max-tokens {REASONING_MAX_TOKENS} or more if num_ctx "
    "leaves room (prompt + output must fit). Calls cut at max_tokens end without a tool "
    "call; reports count them as length_calls and cut_by_cap trials."
)
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
    if not any(same_model({"name": n}, model) for n in names):
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

    probe, response, second = _probe(model, base_url, allow_remote, client)
    checks.append(probe)
    if second is not None:
        checks.append(second)
    if response is not None and (response.reasoning_present or response.stop_reason == "length"):
        checks.append(Check("warn", "max_tokens", MAX_TOKENS_HELP))
    return checks


def _probe(
    model: str, base_url: str, allow_remote: bool, client: httpx.Client | None
) -> tuple[Check, ChatResponse | None, Check | None]:
    """(first-turn check, first response, second-turn check or None)."""
    if os.environ.get(LIVE_ENV) != "1":
        skip = Check("skip", "tool calling", f"probe needs {LIVE_ENV}=1 (two chat calls)")
        return skip, None, None
    transport = OpenAICompatTransport(base_url, allow_remote=allow_remote, client=client)
    messages: list[dict[str, object]] = [
        {"role": "system", "content": "You are a health check. Use the ping tool."},
        {
            "role": "user",
            "content": "Call ping with token 'mb-probe'. When you get its result, "
            "call ping again with token 'mb-probe-2'.",
        },
    ]
    params = {
        "model": model,
        "messages": messages,
        "tools": [PROBE_TOOL],
        "tool_choice": "auto",
        "temperature": 0.0,
        "seed": 0,
        "max_tokens": PROBE_MAX_TOKENS,
        "stream": False,
    }
    try:
        response = parse_completion(transport.send(params, "doctor/probe").body)
    except (ModelCallError, ModelRequestInvalid, ResponseShapeError) as exc:
        return Check("fail", "tool calling", f"probe failed: {exc}"), None, None
    first = _call_check("tool calling", response)
    if first.level != "ok":
        return first, response, None
    return first, response, _second_turn(transport, params, response)


def _call_check(name: str, response: ChatResponse) -> Check:
    if response.invalid_tool_calls:
        bad = response.invalid_tool_calls[0]
        return Check(
            "fail",
            name,
            f"malformed tool call ({bad.kind}): {bad.detail}; {probe_diagnostic(response)}",
        )
    if not any(c.name == "ping" for c in response.tool_calls):
        return Check(
            "fail",
            name,
            f"the model answered without calling the tool; {probe_diagnostic(response)}",
        )
    return Check("ok", name, "the model returned a valid tool call")


def _second_turn(
    transport: OpenAICompatTransport, params: dict[str, object], first: ChatResponse
) -> Check:
    """Send the tool result back and require a second tool call. Catches chat
    templates that drop the tools or the system prompt after a tool result
    (the model then cannot call tools again; see docs/local-models.md)."""
    name = TWO_TURN_CHECK
    call = next(c for c in first.tool_calls if c.name == "ping")
    (assistant,) = first.provider_raw  # reasoning already stripped
    messages = [
        *params["messages"],  # type: ignore[misc]
        assistant,
        {"role": "tool", "tool_call_id": call.id, "content": '{"ok": true, "token": "mb-probe"}'},
    ]
    try:
        response = parse_completion(
            transport.send({**params, "messages": messages}, "doctor/probe-2").body
        )
    except (ModelCallError, ModelRequestInvalid, ResponseShapeError) as exc:
        return Check("fail", name, f"probe failed: {exc}")
    before, after = first.prompt_tokens, response.prompt_tokens
    if before is not None and after is not None and after < before:
        return Check(
            "fail",
            name,
            f"the prompt shrank from {before} to {after} tokens after a tool result, although "
            "the history grew: the chat template likely drops the tool definitions or the "
            "system prompt (check `ollama show <tag> --template`)",
        )
    check = _call_check(name, response)
    if check.level == "ok":
        return Check("ok", name, "the model called a tool again after a tool result")
    return check


def probe_diagnostic(response: ChatResponse) -> str:
    """Short and key-free: finish_reason, reasoning present, content empty. No model text."""
    (message,) = response.provider_raw  # reasoning already stripped
    content = message.get("content")
    empty = not (isinstance(content, str) and content.strip())
    text = (
        f"finish_reason={response.stop_reason} "
        f"reasoning_present={'yes' if response.reasoning_present else 'no'} "
        f"content_empty={'yes' if empty else 'no'}"
    )
    if response.stop_reason == "length":
        text += (
            f" (the output hit max_tokens={PROBE_MAX_TOKENS} before a tool call"
            + ("; reasoning used the budget" if response.reasoning_present else "")
            + ")"
        )
    return text


def print_checks(checks: list[Check], out: Callable[[str], None] = print) -> int:
    for c in checks:
        out(f"[{c.level:<4}] {c.name}: {c.detail}")
    return 1 if any(c.level == "fail" for c in checks) else 0
