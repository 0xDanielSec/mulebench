"""Immutable value objects returned by the ledger."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AccountStatus = Literal["active", "frozen"]
TransferKind = Literal["pix_in", "pix_out", "internal"]
AuditOutcome = Literal["ok", "rejected"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Customer(_Frozen):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    tax_id: str = Field(min_length=1)


class Account(_Frozen):
    id: str = Field(min_length=1)
    customer_id: str = Field(min_length=1)
    pix_key: str | None = None
    balance_cents: int = Field(ge=0)
    daily_limit_cents: int = Field(ge=0)
    status: AccountStatus = "active"


class Transfer(_Frozen):
    """A money movement.

    `description` and `counterparty_name` are stored verbatim and are
    UNTRUSTED: they may contain attacker-controlled text.
    """

    id: str
    kind: TransferKind
    from_account_id: str | None
    to_account_id: str | None
    counterparty_key: str | None
    counterparty_name: str | None
    amount_cents: int = Field(gt=0)
    description: str
    idempotency_key: str | None
    authorization_id: str | None
    actor: str
    created_at: datetime


class Dispute(_Frozen):
    id: str
    transfer_id: str
    customer_id: str
    reason: str
    status: str
    created_at: datetime


class AuditEntry(_Frozen):
    seq: int
    ts: datetime
    actor: str
    action: str
    args: dict[str, object]
    result: dict[str, object]
    outcome: AuditOutcome
    prev_hash: str
    hash: str


AuditChainCode = Literal[
    "malformed_row", "seq_gap", "prev_hash_mismatch", "hash_mismatch", "head_mismatch"
]


class AuditChainProblem(_Frozen):
    seq: int | None  # None for head_mismatch on an empty log
    code: AuditChainCode
    detail: str


class AuditChainReport(_Frozen):
    """Result of `Ledger.verify_audit_chain`. `ok` is True exactly when there
    are no problems."""

    ok: bool
    rows_checked: int
    head_hash: str
    problems: tuple[AuditChainProblem, ...]


class Authorization(_Frozen):
    """Explicit customer consent for one transfer, granted via the customer channel."""

    id: str
    customer_id: str
    from_account_id: str
    payee_pix_key: str
    max_amount_cents: int = Field(gt=0)
    created_at: datetime


class LedgerSnapshot(_Frozen):
    """Read-only copy of ledger state, the input to invariant checks."""

    accounts: tuple[Account, ...]
    transfers: tuple[Transfer, ...]
    authorizations: tuple[Authorization, ...]
