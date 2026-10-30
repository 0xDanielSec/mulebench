"""LLM-backed agent (optional: needs the `llm` extra for the Anthropic adapter).

This package does not import the Anthropic SDK at import time; only
`mulebench.agents.llm.anthropic_model` does.
"""

from mulebench.agents.llm.agent import LLMAgent
from mulebench.agents.llm.budget import BudgetExceeded, CostMeter
from mulebench.agents.llm.model import ChatModel, ModelCallError, ModelRequestInvalid
from mulebench.agents.llm.prompts import PROMPTS

__all__ = [
    "PROMPTS",
    "BudgetExceeded",
    "ChatModel",
    "CostMeter",
    "LLMAgent",
    "ModelCallError",
    "ModelRequestInvalid",
]
