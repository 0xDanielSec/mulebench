"""The LLM memory extractor: one model call per extraction, same model as the agent.

Offered by `LLMAgent.memory_extractor()` for `memory: automatic` scenarios.
The call uses the agent's chat client, cassette transport, cost meter,
temperature and output cap. Its seed is derived from `<trial key>#mem<s>`,
which is also its cassette key, so extraction calls replay offline and never
share a seed with an agent call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mulebench.agents.base import ModelCallRecord
from mulebench.agents.llm.model import ChatRequest, ModelCallError, Turn
from mulebench.agents.llm.seeds import derive_seed
from mulebench.agents.memory_extraction import (
    EXTRACTION_PROMPT,
    ExtractorKind,
    ExtractResult,
    parse_extraction,
)

if TYPE_CHECKING:
    from mulebench.agents.llm.agent import LLMAgent


class LLMExtractor:
    kind: ExtractorKind = "llm"

    def __init__(self, agent: LLMAgent) -> None:
        self.agent = agent

    def extract(self, text: str, *, trial_key: str, max_items: int) -> ExtractResult:
        a = self.agent
        a.meter.check()
        seed = None if a.seed is None else derive_seed(a.seed, trial_key)
        request = ChatRequest(
            model=a.model,
            system=EXTRACTION_PROMPT,
            turns=(Turn(kind="user", text=text),),
            tools=(),
            max_tokens=a.max_tokens,
            effort=a.effort,
            trial_key=trial_key,
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
            provider_cost_usd=response.provider_cost_usd,
        )
        items, malformed = parse_extraction(response.text)
        return ExtractResult(items=items, malformed=malformed, model_call=record)
