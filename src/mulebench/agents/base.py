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
    trial: int = 0  # trial index within the cell; LLM agents derive the seed from it


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
    prompt_tokens: int | None = None  # whole prompt as counted by the server, if reported
    # Window used by the call: prompt + completion, reasoning included.
    context_tokens: int | None = None
    # Reasoning (thinking) was returned. Its text is never recorded here.
    reasoning_present: bool | None = None
    reasoning_tokens: int | None = None


class ServerMeta(_Model):
    """What a local model server reports about the model under test.

    Fields a server does not expose are None (digest, quantization and version
    come from Ollama-only endpoints).
    """

    model: str
    digest: str | None = None
    quantization: str | None = None
    server_version: str | None = None
    num_ctx: int | None = None  # effective context window, if known
    num_ctx_source: str | None = None  # "parameters" (Modelfile) or "ps" (loaded model)
    context_length: int | None = None  # model's trained maximum


class AgentRun(_Model):
    steps: tuple[AgentStep, ...]
    stopped: StopReason
    model_calls: tuple[ModelCallRecord, ...] = ()
    error: str | None = None  # set when stopped == "errored"
    session_note_channel: SessionNoteChannel | None = None
    tool_calls_total: int = 0  # tool calls the model emitted, valid or not
    # Malformed tool calls by kind: "json", "unknown_tool", "schema".
    malformed_tool_calls: dict[str, int] = {}
    seed: int | None = None
    temperature: float | None = None
    server_meta: ServerMeta | None = None


class RunAborted(Exception):
    """Raised by an agent to stop the whole harness run (e.g. cost cap reached)."""


class Agent(Protocol):
    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun: ...
