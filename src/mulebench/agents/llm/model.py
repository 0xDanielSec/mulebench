"""Provider-agnostic chat-model interface used by LLMAgent."""

from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from mulebench.agents.base import SessionNoteChannel, TokenUsage


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolCall(_Model):
    id: str
    name: str
    args: dict[str, Any]


class ToolOutcome(_Model):
    call_id: str
    content: str
    is_error: bool


class Turn(_Model):
    """One conversation entry in neutral form.

    `operator` carries the trusted session note. For `assistant`, `provider_raw`
    holds the provider's content blocks exactly as returned, so they can be sent
    back unchanged (required for thinking blocks). It never leaves the agent.
    """

    kind: Literal["user", "operator", "assistant", "tool_results"]
    text: str = ""
    results: tuple[ToolOutcome, ...] = ()
    provider_raw: tuple[dict[str, Any], ...] = ()


class ToolDef(_Model):
    name: str
    description: str
    input_schema: dict[str, Any]


class ChatRequest(_Model):
    model: str
    system: str
    turns: tuple[Turn, ...]
    tools: tuple[ToolDef, ...]
    max_tokens: int
    effort: str
    trial_key: str  # keys cassettes; not sent to the provider


class ChatResponse(_Model):
    tool_calls: tuple[ToolCall, ...]
    stop_reason: str | None
    refusal_category: str | None
    usage: TokenUsage
    served_model: str
    request_id: str | None
    provider_raw: tuple[dict[str, Any], ...]


class ModelCallError(Exception):
    """Transient provider failure after SDK retries (rate limit, 5xx, network)."""

    def __init__(self, kind: str, message: str, request_id: str | None = None) -> None:
        super().__init__(f"{kind}: {message}")
        self.kind = kind
        self.request_id = request_id


class ModelRequestInvalid(Exception):
    """Non-retryable request error (bad request, auth, unknown model). Aborts the run."""


class ChatModel(Protocol):
    provider: str

    def complete(self, request: ChatRequest) -> ChatResponse: ...

    def session_note_channel(self, model: str) -> SessionNoteChannel: ...
