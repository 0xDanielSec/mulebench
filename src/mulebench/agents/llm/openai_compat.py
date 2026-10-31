"""OpenAI-compatible chat completions adapter (tool calling).

Targets `/v1/chat/completions` as served by Ollama (later LM Studio, vLLM).

- The session note is appended to the system prompt: local chat templates often
  mishandle more than one system message.
- `temperature` and `seed` are always sent; `tool_choice` is `auto`.
- Tool call arguments arrive as a JSON string. Arguments that do not parse to a
  JSON object are returned as `invalid_tool_calls` (kind `json`), never dropped.
  Unknown tools and schema-invalid arguments are detected by the agent.
- Reasoning ("thinking", e.g. qwen3) arrives in one of two shapes: a separate
  `reasoning` / `reasoning_content` field, or `<think>...</think>` inside
  `content` (an unclosed `<think>`, cut off by max_tokens, runs to the end).
  It is never treated as final text or as tool calls: tool calls come only from
  `message.tool_calls`. It is stripped from the assistant message sent back in
  the history, so it reaches the cassettes (raw response bodies) and nothing
  else. Each call records `reasoning_present` and, when the server reports it,
  `reasoning_tokens`; context usage counts prompt + completion tokens, which
  include the reasoning.
- Assistant messages are otherwise sent back as returned.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mulebench.agents.base import ServerMeta, SessionNoteChannel, TokenUsage
from mulebench.agents.llm.model import ChatRequest, ChatResponse, InvalidToolCall, ToolCall
from mulebench.agents.llm.transport import Transport

PROVIDER = "openai-compatible"
REASONING_FIELDS = ("reasoning", "reasoning_content")
_THINK = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL)


class ResponseShapeError(ValueError):
    """The server returned a body that is not a chat completion."""


class OpenAICompatChatModel:
    provider = PROVIDER

    def __init__(self, transport: Transport, server_meta: ServerMeta | None = None) -> None:
        self.transport = transport
        self.server_meta = server_meta

    def session_note_channel(self, model: str) -> SessionNoteChannel:
        return "system_prompt"

    def build_params(self, request: ChatRequest) -> dict[str, Any]:
        system = request.system
        messages: list[dict[str, Any]] = []
        for turn in request.turns:
            if turn.kind == "user":
                messages.append({"role": "user", "content": turn.text})
            elif turn.kind == "operator":
                system = f"{system}\n\n{turn.text}"
            elif turn.kind == "assistant":
                messages.extend(turn.provider_raw)
            else:
                messages.extend(
                    {"role": "tool", "tool_call_id": r.call_id, "content": r.content}
                    for r in turn.results
                )
        params: dict[str, Any] = {
            "model": request.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                }
                for t in request.tools
            ],
            "tool_choice": "auto",
            "max_tokens": request.max_tokens,
            "temperature": 0.0 if request.temperature is None else request.temperature,
            "stream": False,
        }
        if request.seed is not None:
            params["seed"] = request.seed
        return params

    def complete(self, request: ChatRequest) -> ChatResponse:
        response = self.transport.send(self.build_params(request), request.trial_key)
        return parse_completion(response.body, response.request_id)


def parse_completion(body: dict[str, Any], request_id: str | None = None) -> ChatResponse:
    try:
        choice = body["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ResponseShapeError(f"not a chat completion: missing {exc}") from None
    if not isinstance(message, dict):
        raise ResponseShapeError("not a chat completion: message is not an object")
    calls: list[ToolCall] = []
    invalid: list[InvalidToolCall] = []
    for i, raw in enumerate(message.get("tool_calls") or []):
        call_id = str(raw.get("id") or f"call_{i}")
        function = raw.get("function") if isinstance(raw, dict) else None
        name = str(function.get("name", "")) if isinstance(function, dict) else ""
        arguments = function.get("arguments") if isinstance(function, dict) else None
        args, problem = _parse_arguments(arguments)
        if args is None:
            invalid.append(InvalidToolCall(id=call_id, name=name, kind="json", detail=problem))
        else:
            calls.append(ToolCall(id=call_id, name=name, args=args))
    clean, reasoning = strip_reasoning(message)
    usage = body.get("usage") or {}
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    details = usage.get("completion_tokens_details") or {}
    reasoning_tokens = details.get("reasoning_tokens") if isinstance(details, dict) else None
    stop = choice.get("finish_reason")
    if message.get("refusal"):
        stop = "refusal"
    return ChatResponse(
        tool_calls=tuple(calls),
        stop_reason=stop,
        refusal_category=None,
        usage=TokenUsage(
            input_tokens=int(prompt or 0),
            output_tokens=int(completion or 0),
        ),
        served_model=str(body.get("model", "")),
        request_id=request_id or body.get("id"),
        provider_raw=(clean,),  # reasoning removed: it is not sent back
        text=clean["content"] if isinstance(clean.get("content"), str) else "",
        invalid_tool_calls=tuple(invalid),
        prompt_tokens=None if prompt is None else int(prompt),
        context_tokens=None if prompt is None else int(prompt) + int(completion or 0),
        reasoning_present=reasoning,
        reasoning_tokens=None if reasoning_tokens is None else int(reasoning_tokens),
    )


def strip_reasoning(message: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """The message without reasoning, and whether it had any (either shape)."""
    clean = {k: v for k, v in message.items() if k not in REASONING_FIELDS}
    present = any(message.get(k) for k in REASONING_FIELDS)
    content = message.get("content")
    if isinstance(content, str) and "<think>" in content:
        present = True
        clean["content"] = _THINK.sub("", content).strip()
    return clean, present


def _parse_arguments(arguments: object) -> tuple[dict[str, Any] | None, str]:
    """Arguments as an object, or (None, reason). Some servers send an object."""
    if isinstance(arguments, dict):
        return arguments, ""
    if not isinstance(arguments, str):
        return None, f"arguments of type {type(arguments).__name__}"
    try:
        parsed = json.loads(arguments) if arguments.strip() else {}
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc.msg}"
    if not isinstance(parsed, dict):
        return None, f"arguments are a JSON {type(parsed).__name__}, not an object"
    return parsed, ""
