"""Banking tools exposed to agents.

Tools are thin wrappers over the ledger. Policy lives in composable guards
installed on the `ToolContext`; the same tools serve vulnerable and hardened
configurations. Agents call tools only through `call_tool`, which validates
input, runs guards, executes, and records every call in the trace.
"""

from mulebench.tools.context import ToolContext
from mulebench.tools.guards import (
    VULNERABLE,
    AccountOwnership,
    AlwaysApprove,
    AlwaysDeny,
    ConfirmationRequest,
    Confirmer,
    Guard,
    HumanConfirmation,
    NewPayeeGuard,
    RequireAuthorization,
    SessionSpendCap,
    VelocityGuard,
    hardened,
)
from mulebench.tools.marking import UntrustedContentMarking, marking_nonce
from mulebench.tools.registry import TOOLS, ToolError, ToolResult, ToolSpec, call_tool
from mulebench.tools.schemas import UNTRUSTED_KEY, untrusted_paths
from mulebench.tools.trace import GuardDecision, ToolCallRecord, TraceRecorder
from mulebench.tools.transform import ResultTransformer

__all__ = [
    "TOOLS",
    "UNTRUSTED_KEY",
    "VULNERABLE",
    "AccountOwnership",
    "AlwaysApprove",
    "AlwaysDeny",
    "ConfirmationRequest",
    "Confirmer",
    "Guard",
    "GuardDecision",
    "HumanConfirmation",
    "NewPayeeGuard",
    "RequireAuthorization",
    "ResultTransformer",
    "SessionSpendCap",
    "ToolCallRecord",
    "ToolContext",
    "ToolError",
    "ToolResult",
    "ToolSpec",
    "TraceRecorder",
    "UntrustedContentMarking",
    "VelocityGuard",
    "call_tool",
    "hardened",
    "marking_nonce",
    "untrusted_paths",
]
