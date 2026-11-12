"""Fake external agents for the bring-your-own-agent tests.

Loaded by module path (`--agent-path tests/fixtures/byoa`), like a user's code.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from mulebench.agents import AgentTask, ScriptedAgent
from mulebench.byoa import AgentReply, ExternalTask, Tools
from mulebench.tools.client import ToolClient, ToolResult

# Key-shaped on purpose: must never reach a report.
FAKE_KEY = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class _ToolsAsClient(ToolClient):
    """Lets the scripted agent drive a `Tools` facade."""

    def __init__(self, tools: Tools) -> None:
        self._tools = tools

    def call(self, tool: str, args: Mapping[str, object]) -> ToolResult:
        return self._tools.call(tool, args)

    def check_call(self, tool: str, args: Mapping[str, object]) -> tuple[str, str] | None:
        return self._tools.check_call(tool, args)

    def tool_names(self) -> list[str]:
        return self._tools.names()

    def model_tool_schemas(self) -> list[dict[str, Any]]:
        return self._tools.specs()


class Obedient:
    """Completes benign tasks and follows instructions in tool output."""

    name = "fake-obedient"
    params: ClassVar[dict[str, object]] = {"flavour": "obedient"}

    def run(self, task: ExternalTask, tools: Tools) -> AgentReply:
        inner = AgentTask(
            customer_id=task.customer_id,
            request=task.request,
            session_note=task.session_note,
            trial=task.trial,
        )
        run = ScriptedAgent().run(inner, _ToolsAsClient(tools))
        return AgentReply(final_text=run.final_text or "done")


class Lazy:
    """Answers without calling any tool: no utility."""

    def run(self, task: ExternalTask, tools: Tools) -> str:
        return "I cannot help with that."


class Broken:
    """Calls one tool, then raises with a secret and a path in the message."""

    def run(self, task: ExternalTask, tools: Tools) -> str:
        tools.call("get_balance", {"account_id": "acc_alice"})
        raise RuntimeError(
            f"upstream rejected key {FAKE_KEY} while reading C:\\Users\\someone\\agent\\cfg.toml "
            "and /home/someone/agent/cfg.toml"
        )


class WrongReply:
    def run(self, task: ExternalTask, tools: Tools) -> object:
        return 42


def obedient() -> Obedient:
    return Obedient()


def lazy() -> Lazy:
    return Lazy()


def broken() -> Broken:
    return Broken()


def wrong_reply() -> WrongReply:
    return WrongReply()


def needs_args(model: str) -> Obedient:
    return Obedient()


def no_run() -> object:
    return object()


def explodes() -> Obedient:
    raise ValueError(f"bad config {FAKE_KEY}")


not_callable = 42
