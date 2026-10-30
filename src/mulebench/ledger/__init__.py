"""Simulated core banking ledger.

The ledger is deliberately policy-free about authorization and ownership:
it enforces accounting facts (funds, daily limits, frozen accounts,
idempotency) but never checks who asked for an operation. Enforcement lives
in the tools layer, so tools can be vulnerable or hardened, and invariants
judge the outcome from ledger state. See `mulebench.ledger.ledger`.
"""

from mulebench.ledger.clock import (
    SAO_PAULO,
    Clock,
    FixedClock,
    FlatDailyLimit,
    LimitPolicy,
    SystemClock,
    local_day_bounds_utc,
)
from mulebench.ledger.errors import (
    AccountFrozen,
    AuthorizationAlreadyUsed,
    DailyLimitExceeded,
    DescriptionTooLong,
    DuplicateEntity,
    IdempotencyConflict,
    InsufficientFunds,
    InvalidAmount,
    LedgerError,
    SelfTransfer,
    UnknownAccount,
    UnknownAuthorization,
    UnknownCustomer,
    UnknownTransfer,
)
from mulebench.ledger.ledger import MAX_DESCRIPTION_CHARS, Ledger, uuid_ids
from mulebench.ledger.models import (
    Account,
    AuditEntry,
    Authorization,
    Customer,
    Dispute,
    LedgerSnapshot,
    Transfer,
)

__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "SAO_PAULO",
    "Account",
    "AccountFrozen",
    "AuditEntry",
    "Authorization",
    "AuthorizationAlreadyUsed",
    "Clock",
    "Customer",
    "DailyLimitExceeded",
    "DescriptionTooLong",
    "Dispute",
    "DuplicateEntity",
    "FixedClock",
    "FlatDailyLimit",
    "IdempotencyConflict",
    "InsufficientFunds",
    "InvalidAmount",
    "Ledger",
    "LedgerError",
    "LedgerSnapshot",
    "LimitPolicy",
    "SelfTransfer",
    "SystemClock",
    "Transfer",
    "UnknownAccount",
    "UnknownAuthorization",
    "UnknownCustomer",
    "UnknownTransfer",
    "local_day_bounds_utc",
    "uuid_ids",
]
