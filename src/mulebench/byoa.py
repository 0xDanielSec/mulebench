"""Bring your own agent: the public API for agents that live outside mulebench.

A user writes a class with one method and a factory that returns it:

    from mulebench.byoa import AgentReply, ExternalTask, Tools

    class MyAgent:
        name = "my-agent"            # optional, shown in the report
        params = {"model": "x"}      # optional, JSON-safe, stored in the report

        def run(self, task: ExternalTask, tools: Tools) -> AgentReply | str:
            balance = tools.call("get_balance", {})
            return f"Your balance: {balance.data}"

    def factory() -> MyAgent:
        return MyAgent()

and runs it with `mulebench run --agent-module my_pkg.my_mod:factory`.

Trust model: the agent only gets `Tools`. The ledger, the guards, the
confirmer and the trace stay with the harness. Nothing the agent says about
its own steps is used to judge an attack: steps are recorded here, at the
tool boundary, and attacks are judged from ledger state and the tool trace.
See docs/bring-your-own-agent.md.
"""

from __future__ import annotations

import importlib
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mulebench.agents.base import (
    AgentRun,
    AgentStep,
    AgentTask,
    ModelCallRecord,
    RunAborted,
    StopReason,
    TokenUsage,
)
from mulebench.tools.client import ToolClient, ToolResult

__all__ = [
    "AgentLoadError",
    "AgentReply",
    "ExternalAgent",
    "ExternalAgentAdapter",
    "ExternalTask",
    "ModelCallRecord",
    "TokenUsage",
    "ToolResult",
    "Tools",
    "load_agent",
    "safe_error",
]

ERROR_MESSAGE_MAX = 160
REDACTED = "[redacted]"


@dataclass(frozen=True)
class ExternalTask:
    """What the agent is asked to do. The session note is the trusted channel:
    it says which customer is in session and what they authorized."""

    customer_id: str
    request: str
    session_note: str
    trial: int = 0


@dataclass(frozen=True)
class AgentReply:
    """The agent's answer. Only `final_text` is needed.

    `model_calls=None` means the adapter does not record model calls; token,
    cost and context metrics then show "not recorded", never 0.
    """

    final_text: str | None
    stopped: StopReason = "done"
    model_calls: Sequence[ModelCallRecord] | None = None
    seed: int | None = None
    temperature: float | None = None


@runtime_checkable
class ExternalAgent(Protocol):
    def run(self, task: ExternalTask, tools: Tools) -> AgentReply | str: ...


class Tools:
    """The agent's only door to the bank: call a tool by name, get a `ToolResult`.

    Every call is executed and traced by the harness, whatever the agent does
    with the result.
    """

    def __init__(self, client: ToolClient) -> None:
        self._client = client
        self._steps: list[AgentStep] = []

    def call(self, tool: str, args: Mapping[str, object]) -> ToolResult:
        result = self._client.call(tool, dict(args))
        self._steps.append(
            AgentStep(
                seq=len(self._steps) + 1,
                tool=tool,
                args=dict(args),
                # An external agent cannot be trusted to label provenance.
                origin="unknown",
                ok=result.ok,
                outcome=result.outcome,
                error_message=None if result.error is None else result.error.message,
            )
        )
        return result

    def check_call(self, tool: str, args: Mapping[str, object]) -> tuple[str, str] | None:
        """(kind, detail) if the call cannot be executed as given, else None.
        Kinds: "unknown_tool", "schema". Nothing is executed or traced."""
        return self._client.check_call(tool, args)

    def names(self) -> list[str]:
        return self._client.tool_names()

    def specs(self) -> list[dict[str, Any]]:
        """Tool definitions: name, description, JSON Schema of the input
        (`input_schema`). Sorted by name. Use them to build function-calling
        tool lists for your stack."""
        return self._client.model_tool_schemas()

    @property
    def steps(self) -> tuple[AgentStep, ...]:
        return tuple(self._steps)


_SECRETISH = re.compile(
    r"\b(?:sk|pk|rk|ghp|gho|ghu|ghs|ghr|xox[a-z])[-_][\w-]+|\bAKIA\w+|\bAIza[\w-]+"
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_WIN_PATH = re.compile(r"[A-Za-z]:[\\/][^\s'\"]*")
_POSIX_PATH = re.compile(r"(?<![\w:])/(?:[\w.\-]+/)+[\w.\-]*")
_PEM = re.compile(r"-----BEGIN[^-]*-----")


def safe_error(exc: BaseException) -> str:
    """Exception type and a truncated, redacted message. Never a traceback,
    never a path, never a key-shaped string."""
    message = " ".join(str(exc).split())
    for pattern in (_PEM, _SECRETISH, _WIN_PATH, _POSIX_PATH, _LONG_TOKEN):
        message = pattern.sub(REDACTED, message)
    if len(message) > ERROR_MESSAGE_MAX:
        message = message[: ERROR_MESSAGE_MAX - 3] + "..."
    name = type(exc).__name__
    return f"{name}: {message}" if message else name


class ExternalAgentAdapter:
    """Wraps an external agent in the harness `Agent` protocol."""

    def __init__(self, inner: ExternalAgent, spec: str) -> None:
        self.inner = inner
        self.spec = spec
        self.report_name = str(getattr(inner, "name", None) or type(inner).__name__)

    @property
    def params(self) -> dict[str, object]:
        raw = getattr(self.inner, "params", None)
        params: dict[str, object] = dict(raw) if isinstance(raw, Mapping) else {}
        params["module"] = self.spec
        params["kind"] = "external"
        return params

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        facade = Tools(tools)
        external = ExternalTask(
            customer_id=task.customer_id,
            request=task.request,
            session_note=task.session_note,
            trial=task.trial,
        )
        try:
            reply = self.inner.run(external, facade)
        except RunAborted:
            raise
        except Exception as exc:  # the agent is user code; any failure errors the trial
            return AgentRun(
                steps=facade.steps,
                stopped="errored",
                error=safe_error(exc),
                tool_calls_total=len(facade.steps),
                model_calls_recorded=False,
            )
        if isinstance(reply, str):
            reply = AgentReply(final_text=reply)
        if not isinstance(reply, AgentReply):
            return AgentRun(
                steps=facade.steps,
                stopped="errored",
                error=f"TypeError: run() returned {type(reply).__name__}, "
                "expected AgentReply or str",
                tool_calls_total=len(facade.steps),
                model_calls_recorded=False,
            )
        return AgentRun(
            steps=facade.steps,
            stopped=reply.stopped,
            error="agent reported stopped=errored" if reply.stopped == "errored" else None,
            model_calls=tuple(reply.model_calls or ()),
            model_calls_recorded=reply.model_calls is not None,
            tool_calls_total=len(facade.steps),
            seed=reply.seed,
            temperature=reply.temperature,
            final_text=reply.final_text,
        )


@dataclass
class AgentLoadError(Exception):
    message: str
    details: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return self.message


def load_agent(spec: str, extra_path: Path | None = None) -> ExternalAgentAdapter:
    """Import `package.module:factory`, call the factory with no arguments and
    wrap what it returns. Raises AgentLoadError with one clear message."""
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise AgentLoadError(
            f"--agent-module must look like 'package.module:factory', got {spec!r}"
        )
    if extra_path is not None:
        if not extra_path.is_dir():
            raise AgentLoadError(f"--agent-path is not a directory: {extra_path}")
        resolved = str(extra_path.resolve())
        if resolved not in sys.path:
            sys.path.insert(0, resolved)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise AgentLoadError(f"cannot import {module_name!r}: {safe_error(exc)}") from None
    factory = getattr(module, attr, None)
    if factory is None:
        raise AgentLoadError(f"{module_name!r} has no attribute {attr!r}")
    if not callable(factory):
        raise AgentLoadError(f"{spec!r} is not callable")
    try:
        agent = factory()
    except TypeError as exc:
        raise AgentLoadError(
            f"factory {spec!r} must take no arguments: {safe_error(exc)}"
        ) from None
    except Exception as exc:
        raise AgentLoadError(f"factory {spec!r} failed: {safe_error(exc)}") from None
    if not callable(getattr(agent, "run", None)):
        raise AgentLoadError(
            f"factory {spec!r} returned {type(agent).__name__}, which has no run(task, tools)"
        )
    return ExternalAgentAdapter(agent, spec)
