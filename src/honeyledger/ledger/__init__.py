"""Simulated core banking ledger.

The ledger is deliberately policy-free about authorization and ownership:
it enforces accounting facts (funds, daily limits, frozen accounts,
idempotency) but never checks who asked for an operation. Enforcement lives
in the tools layer, so tools can be vulnerable or hardened, and invariants
judge the outcome from ledger state. See `honeyledger.ledger.ledger`.
"""

from honeyledger.ledger.clock import (
    SAO_PAULO,
    Clock,
    FixedClock,
    FlatDailyLimit,
    LimitPolicy,
    SystemClock,
    local_day_bounds_utc,
)
from honeyledger.ledger.errors import (
    AccountFrozen,
    DailyLimitExceeded,
    DuplicateEntity,
    IdempotencyConflict,
    InsufficientFunds,
    InvalidAmount,
    LedgerError,
    SelfTransfer,
    UnknownAccount,
    UnknownTransfer,
)
from honeyledger.ledger.ledger import Ledger, uuid_ids
from honeyledger.ledger.models import Account, AuditEntry, Customer, Dispute, Transfer

__all__ = [
    "SAO_PAULO",
    "Account",
    "AccountFrozen",
    "AuditEntry",
    "Clock",
    "Customer",
    "DailyLimitExceeded",
    "Dispute",
    "DuplicateEntity",
    "FixedClock",
    "FlatDailyLimit",
    "IdempotencyConflict",
    "InsufficientFunds",
    "InvalidAmount",
    "Ledger",
    "LedgerError",
    "LimitPolicy",
    "SelfTransfer",
    "SystemClock",
    "Transfer",
    "UnknownAccount",
    "UnknownTransfer",
    "local_day_bounds_utc",
    "uuid_ids",
]
