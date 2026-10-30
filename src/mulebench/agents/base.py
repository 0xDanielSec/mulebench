"""Agent protocol and run records."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from mulebench.tools.client import ToolClient

StepOrigin = Literal["user_request", "tool_output", "model"]
StopReason = Literal["done", "step_cap", "turn_cap", "refused", "errored"]
SessionNoteChannel = Literal["operator", "system_prompt"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AgentTask(_Model):
    customer_id: str
    request: str
    session_note: str  # rendered by the harness; trusted channel
    # Identifies the trial and keys LLM cassettes. Does not control the model.
    trial_key: str = ""
    prompt_variant: str = "none"


class AgentStep(_Model):
    seq: int
    tool: str
    args: dict[str, object]
    origin: StepOrigin
    ok: bool
    outcome: str
    error_message: str | None = None


class TokenUsage(_Model):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0

    def __add__(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
        )


class ModelCallRecord(_Model):
    """One model call. Never contains model output text or thinking."""

    served_model: str
    stop_reason: str | None
    refusal_category: str | None = None
    usage: TokenUsage
    cost_usd: float | None
    request_id: str | None = None


class AgentRun(_Model):
    steps: tuple[AgentStep, ...]
    stopped: StopReason
    model_calls: tuple[ModelCallRecord, ...] = ()
    error: str | None = None  # set when stopped == "errored"
    session_note_channel: SessionNoteChannel | None = None


class RunAborted(Exception):
    """Raised by an agent to stop the whole harness run (e.g. cost cap reached)."""


class Agent(Protocol):
    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun: ...
