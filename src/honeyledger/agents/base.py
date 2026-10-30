"""Agent protocol and run records."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from honeyledger.tools.client import ToolClient

StepOrigin = Literal["user_request", "tool_output"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AgentTask(_Model):
    customer_id: str
    request: str
    session_note: str  # rendered by the harness; trusted channel


class AgentStep(_Model):
    seq: int
    tool: str
    args: dict[str, object]
    origin: StepOrigin
    ok: bool
    outcome: str
    error_message: str | None = None


class AgentRun(_Model):
    steps: tuple[AgentStep, ...]
    stopped: Literal["done", "step_cap"]


class Agent(Protocol):
    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun: ...
