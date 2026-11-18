"""LLM-backed agent. Implements the Agent protocol over a provider-agnostic ChatModel.

A malformed tool call (arguments that are not a JSON object, an unknown tool, or
arguments that fail the tool's schema) stops the trial as errored, before any
call of that turn runs. It is never recorded as the model resisting an attack.
A response with no native tool call whose text holds a JSON call to a known
tool counts as malformed kind `text_tool_call` (errored) and is never executed.
Integers sent as digit-only strings are coerced first (see coercion.py) unless
`arg_coercion="off"`; every coerced field is recorded.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from typing import TYPE_CHECKING

from mulebench.agents.base import (
    AgentRun,
    AgentStep,
    AgentTask,
    ModelCallRecord,
    ServerMeta,
    StopReason,
    TokenUsage,
)
from mulebench.agents.llm.budget import CostMeter
from mulebench.agents.llm.coercion import (
    DEFAULT_ARG_COERCION,
    ArgCoercion,
    coerce_args,
)
from mulebench.agents.llm.model import (
    ChatModel,
    ChatRequest,
    ModelCallError,
    ToolDef,
    ToolOutcome,
    Turn,
)
from mulebench.agents.llm.pricing import cost_usd
from mulebench.agents.llm.prompts import DEFAULT_ROLE_PROMPT, PROMPTS, system_prompt
from mulebench.agents.llm.seeds import SEED_DERIVATION, derive_seed
from mulebench.agents.llm.text_calls import text_tool_calls
from mulebench.agents.memory_extraction import DEFAULT_EXTRACTOR_CONTEXT, ExtractorContext
from mulebench.tools.client import ToolClient, ToolResult

if TYPE_CHECKING:
    from mulebench.agents.llm.extractor import LLMExtractor

DEFAULT_MAX_TOKENS = 16000
DEFAULT_MAX_STEPS = 10
DEFAULT_MAX_TURNS = 12


def operator_text(task: AgentTask) -> str:
    """The trusted session note, then the harness memory block if there is one.

    Without a memory block the text is the session note alone, so requests
    (and cassette hashes) of scenarios without automatic memory are unchanged.
    """
    if not task.memory_context:
        return task.session_note
    return f"{task.session_note}\n\n{task.memory_context}"


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
        arg_coercion: ArgCoercion = DEFAULT_ARG_COERCION,
        role_prompts: dict[str, str] | None = None,
        extractor_context: ExtractorContext = DEFAULT_EXTRACTOR_CONTEXT,
        pricer: Callable[[TokenUsage, str], float | None] = cost_usd,
    ) -> None:
        self.chat = chat
        # usage, served model -> USD; the built-in table unless a provider
        # brings its own (OpenRouter: the local price file).
        self.pricer = pricer
        # Delegation role -> role prompt variant (prompts.ROLE_PROMPT_VARIANTS);
        # roles not named use "default".
        self.role_prompts = dict(role_prompts or {})
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        self.max_turns = max_turns
        self.meter = meter or CostMeter()
        self.temperature = temperature
        self.seed = seed  # base seed; per-trial seed from derive_seed (seeds.py)
        self.arg_coercion = arg_coercion
        # System text of the memory extraction call (see LLMExtractor).
        self.extractor_context: ExtractorContext = extractor_context

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
            "arg_coercion": self.arg_coercion,
        }
        if self.temperature is not None:
            params["temperature"] = self.temperature
        if self.seed is not None:
            params["seed"] = self.seed
            params["seed_derivation"] = SEED_DERIVATION
        if self.extractor_context != DEFAULT_EXTRACTOR_CONTEXT:
            # only then, so the params (and checkpoint fingerprints) of runs
            # with the default stay unchanged; reports record it in llm.
            params["extractor_context"] = self.extractor_context
        if self.role_prompts:
            params["role_prompts"] = dict(sorted(self.role_prompts.items()))
        return params

    def memory_extractor(self) -> LLMExtractor:
        """Extractor for `memory: automatic` scenarios: this agent's model."""
        from mulebench.agents.llm.extractor import LLMExtractor

        return LLMExtractor(self)

    def run(self, task: AgentTask, tools: ToolClient) -> AgentRun:
        if task.prompt_variant not in PROMPTS:
            raise ValueError(f"unknown prompt variant {task.prompt_variant!r}")
        channel = self.chat.session_note_channel(self.model)
        tool_defs = tuple(ToolDef(**t) for t in tools.model_tool_schemas())
        turns: list[Turn] = [
            Turn(kind="user", text=task.request),
            Turn(kind="operator", text=operator_text(task)),
        ]
        steps: list[AgentStep] = []
        calls: list[ModelCallRecord] = []
        seed = None if self.seed is None else derive_seed(self.seed, task.trial_key)
        meta: ServerMeta | None = getattr(self.chat, "server_meta", None)
        schemas = {t.name: t.input_schema for t in tool_defs}
        emitted = 0
        malformed: Counter[str] = Counter()
        coerced_fields: Counter[str] = Counter()  # "tool.field" -> count
        coerced_calls = 0

        def finish(
            stopped: StopReason, error: str | None = None, final_text: str | None = None
        ) -> AgentRun:
            return AgentRun(
                steps=tuple(steps),
                stopped=stopped,
                model_calls=tuple(calls),
                error=error,
                session_note_channel=channel,
                tool_calls_total=emitted,
                malformed_tool_calls=dict(sorted(malformed.items())),
                coerced_calls=coerced_calls,
                coerced_args=dict(sorted(coerced_fields.items())),
                seed=seed,
                temperature=self.temperature,
                server_meta=meta,
                final_text=final_text,
            )

        for _ in range(self.max_turns):
            self.meter.check()
            request = ChatRequest(
                model=self.model,
                system=system_prompt(
                    task.prompt_variant,
                    task.role,
                    self.role_prompts.get(task.role, DEFAULT_ROLE_PROMPT)
                    if task.role is not None
                    else DEFAULT_ROLE_PROMPT,
                ),
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
            cost = self.pricer(response.usage, response.served_model)
            self.meter.add(cost)
            tool_calls = []
            call_coerced: list[str] = []
            for raw in response.tool_calls:
                args, fields = coerce_args(raw.args, schemas.get(raw.name), self.arg_coercion)
                tool_calls.append(raw.model_copy(update={"args": args}) if fields else raw)
                if fields:
                    coerced_calls += 1
                    call_coerced += [f"{raw.name}.{f}" for f in fields]
            coerced_fields.update(call_coerced)
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
                    requested_model=response.requested_model,
                    served_provider=response.served_provider,
                    served_quantization=response.served_quantization,
                    retries=response.retries,
                    provider_cost_usd=response.provider_cost_usd,
                    coerced_args=call_coerced,
                )
            )
            turns.append(Turn(kind="assistant", provider_raw=response.provider_raw))
            emitted += len(response.tool_calls) + len(response.invalid_tool_calls)
            malformed.update(c.kind for c in response.invalid_tool_calls)
            for call in tool_calls:
                problem = tools.check_call(call.name, call.args)
                if problem is not None:
                    malformed[problem[0]] += 1
            if not response.tool_calls and not response.invalid_tool_calls:
                written = text_tool_calls(response.text, schemas)  # counted, never run
                emitted += len(written)
                malformed["text_tool_call"] += len(written)
                if not malformed["text_tool_call"]:
                    del malformed["text_tool_call"]
            if malformed:
                return finish("errored", "malformed_tool_call:" + ",".join(sorted(malformed)))
            if response.stop_reason == "refusal":
                return finish("refused")
            if not tool_calls and not (response.text or "").strip():
                # No tool call and no answer text (reasoning already stripped): the
                # model produced nothing usable, e.g. a tool call the server failed to
                # parse and dropped. Errored, never resisted; counted with the
                # malformed kinds so tool-call validity reflects it.
                malformed["empty_output"] += 1
                return finish("errored", "empty_output")
            if not tool_calls:
                return finish("done", final_text=response.text or None)

            outcomes: list[ToolOutcome] = []
            for call in tool_calls:
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
