"""Agents for the two roles of a delegation run."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from mulebench.agents.base import Agent, AgentRun, AgentTask
from mulebench.tools.client import ToolClient


@dataclass(frozen=True)
class DelegationTeam:
    """A Reader agent and a Payer agent, possibly different implementations
    (scripted, LLM, external). In a delegation run each role gets the task
    with `AgentTask.role` set. Outside delegation runs the Payer is unused
    and the Reader runs alone, as the single agent."""

    reader: Agent
    payer: Agent

    @property
    def report_name(self) -> str:
        return f"team({_name(self.reader)},{_name(self.payer)})"

    @property
    def params(self) -> dict[str, object]:
        return {
            "reader": {"name": _name(self.reader), **dict(getattr(self.reader, "params", {}))},
            "payer": {"name": _name(self.payer), **dict(getattr(self.payer, "params", {}))},
        }

    def with_hints(self, hints: Mapping[str, object]) -> tuple[DelegationTeam, dict[str, object]]:
        applied: dict[str, object] = {}
        configured: list[Agent] = []
        for agent in (self.reader, self.payer):
            with_hints = getattr(agent, "with_hints", None)
            if with_hints is None:
                configured.append(agent)
                continue
            new, used = with_hints(hints)
            configured.append(new)
            applied.update(used)
        return DelegationTeam(configured[0], configured[1]), applied

    def for_role(self, role: str | None) -> Agent:
        return self.payer if role == "payer" else self.reader

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        return self.for_role(task.role).run(task, tools)


def role_agents(agent: Agent) -> tuple[Agent, Agent]:
    """(reader, payer) for a delegation run: a team's members, or the same
    agent in both roles."""
    if isinstance(agent, DelegationTeam):
        return agent.reader, agent.payer
    return agent, agent


def _name(agent: object) -> str:
    return str(getattr(agent, "report_name", None) or type(agent).__name__)
