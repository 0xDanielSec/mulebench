"""The LLM memory extractor: one model call per extraction, same model as the agent.

Offered by `LLMAgent.memory_extractor()` for `memory: automatic` scenarios.
The call uses the agent's chat client, cassette transport, cost meter,
temperature and output cap. Its seed is derived from `<trial key>#mem<s>`,
which is also its cassette key, so extraction calls replay offline and never
share a seed with an agent call.

`extractor_context` (an agent option, default "none") sets the system text:

- "none": EXTRACTION_PROMPT alone. Requests, seeds and cassette keys are those
  of pilots 07 and 08, byte for byte.
- "agent_system_prompt": the agent's session system prompt for the trial's
  prompt variant (the `system` text `LLMAgent.run` sends; not the trusted
  session note or memory block, which are per-session state even where a
  provider carries them in the system message), a blank line, then
  EXTRACTION_PROMPT. Model, sampling, seed and input text are unchanged. The
  cassette key gets the suffix `~ctx=agent_system_prompt`, so recordings of
  the two conditions never share a key; the seed is still derived from
  `<trial key>#mem<s>`, so both conditions sample the extraction with the
  same seed (a paired design).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mulebench.agents.base import ModelCallRecord
from mulebench.agents.llm.model import ChatRequest, ModelCallError, Turn
from mulebench.agents.llm.prompts import system_prompt
from mulebench.agents.llm.seeds import derive_seed
from mulebench.agents.memory_extraction import (
    EXTRACTION_PROMPT,
    ExtractorContext,
    ExtractorKind,
    ExtractResult,
    parse_extraction,
)

if TYPE_CHECKING:
    from mulebench.agents.llm.agent import LLMAgent


def extraction_system(context: ExtractorContext, prompt_variant: str | None) -> str:
    """System text of the extraction call under `context`."""
    if context == "none":
        return EXTRACTION_PROMPT
    if prompt_variant is None:
        raise ValueError("extractor_context agent_system_prompt needs the trial's prompt variant")
    return f"{system_prompt(prompt_variant)}\n\n{EXTRACTION_PROMPT}"


def extraction_cassette_key(trial_key: str, context: ExtractorContext) -> str:
    """Cassette key of the extraction call: unchanged for "none"."""
    return trial_key if context == "none" else f"{trial_key}~ctx={context}"


class LLMExtractor:
    kind: ExtractorKind = "llm"

    def __init__(self, agent: LLMAgent) -> None:
        self.agent = agent

    def extract(
        self,
        text: str,
        *,
        trial_key: str,
        max_items: int,
        prompt_variant: str | None = None,
    ) -> ExtractResult:
        a = self.agent
        context = a.extractor_context
        system = extraction_system(context, prompt_variant)
        a.meter.check()
        seed = None if a.seed is None else derive_seed(a.seed, trial_key)
        request = ChatRequest(
            model=a.model,
            system=system,
            turns=(Turn(kind="user", text=text),),
            tools=(),
            max_tokens=a.max_tokens,
            effort=a.effort,
            trial_key=extraction_cassette_key(trial_key, context),
            temperature=a.temperature,
            seed=seed,
        )
        try:
            response = a.chat.complete(request)
        except ModelCallError as exc:
            return ExtractResult(items=[], error=exc.kind)
        cost = a.pricer(response.usage, response.served_model)
        a.meter.add(cost)
        record = ModelCallRecord(
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
        )
        items, malformed = parse_extraction(response.text)
        return ExtractResult(items=items, malformed=malformed, model_call=record)
