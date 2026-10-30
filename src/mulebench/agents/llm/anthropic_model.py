"""Anthropic Messages API adapter (tool use).

- Thinking is not configured (always on for current Opus models); effort is set
  explicitly through `output_config.effort`.
- `tool_choice` is left at the default (`auto`); forced tool use is rejected by
  current models.
- No sampling parameters: the API rejects temperature/top_p/top_k.
- Refusal fallbacks are deliberately NOT enabled: a fallback would silently swap
  the model under test. A refusal is recorded as its own outcome.
- The session note goes through the operator channel (a mid-conversation
  `system` message) on models that support it, otherwise it is appended to the
  top-level system prompt.
- Assistant content blocks are sent back exactly as returned.
"""

from __future__ import annotations

from typing import Any

from anthropic.types import Message

from mulebench.agents.base import SessionNoteChannel, TokenUsage
from mulebench.agents.llm.model import ChatRequest, ChatResponse, ToolCall
from mulebench.agents.llm.transport import Transport

# Models that accept mid-conversation `system` messages (not Claude Sonnet 5).
OPERATOR_CHANNEL_MODELS = (
    "claude-opus-5-5",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-fable-5-1",
    "claude-fable-5",
    "claude-mythos-5-1",
    "claude-mythos-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
)


class AnthropicChatModel:
    provider = "anthropic"

    def __init__(self, transport: Transport) -> None:
        self.transport = transport

    def session_note_channel(self, model: str) -> SessionNoteChannel:
        if model.startswith("claude-sonnet-5") and not model.startswith("claude-sonnet-5-5"):
            return "system_prompt"
        if any(model == m or model.startswith(m + "-") for m in OPERATOR_CHANNEL_MODELS):
            return "operator"
        return "system_prompt"

    def build_params(self, request: ChatRequest) -> dict[str, Any]:
        channel = self.session_note_channel(request.model)
        system = request.system
        messages: list[dict[str, Any]] = []
        for turn in request.turns:
            if turn.kind == "user":
                messages.append({"role": "user", "content": turn.text})
            elif turn.kind == "operator":
                if channel == "operator":
                    messages.append({"role": "system", "content": turn.text})
                else:
                    system = f"{system}\n\n{turn.text}"
            elif turn.kind == "assistant":
                messages.append({"role": "assistant", "content": list(turn.provider_raw)})
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": r.call_id,
                                "content": r.content,
                                "is_error": r.is_error,
                            }
                            for r in turn.results
                        ],
                    }
                )
        return {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "system": system,
            "messages": messages,
            "tools": [t.model_dump() for t in request.tools],
            "output_config": {"effort": request.effort},
        }

    def complete(self, request: ChatRequest) -> ChatResponse:
        response = self.transport.send(self.build_params(request), request.trial_key)
        message = Message.model_validate(response.body)  # validates the shape
        usage = message.usage
        refusal = None
        if message.stop_reason == "refusal" and message.stop_details is not None:
            refusal = message.stop_details.category
        return ChatResponse(
            tool_calls=tuple(
                ToolCall(id=b.id, name=b.name, args=dict(b.input))
                for b in message.content
                if b.type == "tool_use"
            ),
            stop_reason=message.stop_reason,
            refusal_category=refusal,
            usage=TokenUsage(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_write_tokens=usage.cache_creation_input_tokens or 0,
                cache_read_tokens=usage.cache_read_input_tokens or 0,
            ),
            served_model=message.model,
            request_id=response.request_id,
            provider_raw=tuple(b.to_dict() for b in message.content),
        )
