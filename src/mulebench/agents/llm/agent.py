"""LLM-backed agent. Implements the Agent protocol over a provider-agnostic ChatModel.

A malformed tool call (arguments that are not a JSON object, an unknown tool, or
arguments that fail the tool's schema) stops the trial as errored, before any
call of that turn runs. It is never recorded as the model resisting an attack.
"""

from __future__ import annotations

import json
from collections import Counter

from mulebench.agents.base import (
    AgentRun,
    AgentStep,
    AgentTask,
    ModelCallRecord,
    ServerMeta,
    StopReason,
)
from mulebench.agents.llm.budget import CostMeter
from mulebench.agents.llm.model import (
    ChatModel,
    ChatRequest,
    ModelCallError,
    ToolDef,
    ToolOutcome,
    Turn,
)
from mulebench.agents.llm.pricing import cost_usd
from mulebench.agents.llm.prompts import PROMPTS
from mulebench.tools.client import ToolClient, ToolResult

DEFAULT_MAX_TOKENS = 16000
DEFAULT_MAX_STEPS = 10
DEFAULT_MAX_TURNS = 12


def model_facing_result(result: ToolResult) -> str:
    """What the model sees from a tool call: no untrusted-path metadata."""
    payload = {
        "ok": result.ok,
        "outcome": result.outcome,
        "data": result.data,
        "error": None if result.error is None else result.error.model_dump(mode="json"),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


class LLMAgent:
    def __init__(
        self,
        chat: ChatModel,
        *,
        model: str,
        effort: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_steps: int = DEFAULT_MAX_STEPS,
        max_turns: int = DEFAULT_MAX_TURNS,
        meter: CostMeter | None = None,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> None:
        self.chat = chat
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        self.max_turns = max_turns
        self.meter = meter or CostMeter()
        self.temperature = temperature
        self.seed = seed  # base seed; trial t uses seed + t

    @property
    def params(self) -> dict[str, object]:
        params: dict[str, object] = {
            "provider": self.chat.provider,
            "model": self.model,
            "effort": self.effort,
            "max_tokens": self.max_tokens,
            "max_steps": self.max_steps,
            "max_turns": self.max_turns,
            "refusal_fallbacks": "off",
        }
        if self.temperature is not None:
            params["temperature"] = self.temperature
        if self.seed is not None:
            params["seed"] = self.seed
        return params

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        if task.prompt_variant not in PROMPTS:
            raise ValueError(f"unknown prompt variant {task.prompt_variant!r}")
        channel = self.chat.session_note_channel(self.model)
        tool_defs = tuple(ToolDef(**t) for t in tools.model_tool_schemas())
        turns: list[Turn] = [
            Turn(kind="user", text=task.request),
            Turn(kind="operator", text=task.session_note),
        ]
        steps: list[AgentStep] = []
        calls: list[ModelCallRecord] = []
        seed = None if self.seed is None else self.seed + task.trial
        meta: ServerMeta | None = getattr(self.chat, "server_meta", None)
        emitted = 0
        malformed: Counter[str] = Counter()

        def finish(stopped: StopReason, error: str | None = None) -> AgentRun:
            return AgentRun(
                steps=tuple(steps),
                stopped=stopped,
                model_calls=tuple(calls),
                error=error,
                session_note_channel=channel,
                tool_calls_total=emitted,
                malformed_tool_calls=dict(sorted(malformed.items())),
                seed=seed,
                temperature=self.temperature,
                server_meta=meta,
            )

        for _ in range(self.max_turns):
            self.meter.check()
            request = ChatRequest(
                model=self.model,
                system=PROMPTS[task.prompt_variant],
                turns=tuple(turns),
                tools=tool_defs,
                max_tokens=self.max_tokens,
                effort=self.effort,
                trial_key=task.trial_key,
                temperature=self.temperature,
                seed=seed,
            )
            try:
                response = self.chat.complete(request)
            except ModelCallError as exc:
                return finish("errored", exc.kind)
            cost = cost_usd(response.usage, response.served_model)
            self.meter.add(cost)
            calls.append(
                ModelCallRecord(
                    served_model=response.served_model,
                    stop_reason=response.stop_reason,
                    refusal_category=response.refusal_category,
                    usage=response.usage,
                    cost_usd=cost,
                    request_id=response.request_id,
                    prompt_tokens=response.prompt_tokens,
                    context_tokens=response.context_tokens,
                    reasoning_present=response.reasoning_present,
                    reasoning_tokens=response.reasoning_tokens,
                )
            )
            turns.append(Turn(kind="assistant", provider_raw=response.provider_raw))
            emitted += len(response.tool_calls) + len(response.invalid_tool_calls)
            malformed.update(c.kind for c in response.invalid_tool_calls)
            for call in response.tool_calls:
                problem = tools.check_call(call.name, call.args)
                if problem is not None:
                    malformed[problem[0]] += 1
            if malformed:
                return finish("errored", "malformed_tool_call:" + ",".join(sorted(malformed)))
            if response.stop_reason == "refusal":
                return finish("refused")
            if not response.tool_calls:
                return finish("done")

            outcomes: list[ToolOutcome] = []
            for call in response.tool_calls:
                if len(steps) >= self.max_steps:
                    return finish("step_cap")
                result = tools.call(call.name, call.args)
                steps.append(
                    AgentStep(
                        seq=len(steps) + 1,
                        tool=call.name,
                        args=dict(call.args),
                        origin="model",
                        ok=result.ok,
                        outcome=result.outcome,
                        error_message=None if result.error is None else result.error.message,
                    )
                )
                outcomes.append(
                    ToolOutcome(
                        call_id=call.id,
                        content=model_facing_result(result),
                        is_error=not result.ok,
                    )
                )
            # All results of one assistant turn go back in a single message.
            turns.append(Turn(kind="tool_results", results=tuple(outcomes)))
        return finish("turn_cap")
