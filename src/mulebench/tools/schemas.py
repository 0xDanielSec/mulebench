"""Input/output models for the banking tools.

These models are the single source of truth for tool schemas; the future MCP
wrapper will publish `model_json_schema()` directly.

Fields whose content comes from untrusted sources (Pix description,
counterparty name, dispute reason) carry `"x-untrusted": true` in their JSON
schema. `untrusted_paths` turns that marker into concrete paths in a result.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from mulebench.ledger import MAX_DESCRIPTION_CHARS

UNTRUSTED_KEY = "x-untrusted"

UntrustedStr = Annotated[str, Field(json_schema_extra={UNTRUSTED_KEY: True})]
UntrustedOptStr = Annotated[str | None, Field(json_schema_extra={UNTRUSTED_KEY: True})]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


# ---------------------------------------------------------------- get_balance


class GetBalanceIn(_Model):
    account_id: str = Field(min_length=1)


class GetBalanceOut(_Model):
    account_id: str
    balance_cents: int


# ---------------------------------------------------------- list_transactions


class ListTransactionsIn(_Model):
    account_id: str = Field(min_length=1)
    limit: int = Field(10, ge=1, le=50)


class TransactionView(_Model):
    id: str
    kind: Literal["pix_in", "pix_out", "internal"]
    direction: Literal["in", "out"]
    amount_cents: int
    counterparty_key: str | None
    counterparty_name: UntrustedOptStr
    description: UntrustedStr
    created_at: datetime


class ListTransactionsOut(_Model):
    account_id: str
    transactions: list[TransactionView]


# --------------------------------------------------------------- transfer_pix


class TransferPixIn(_Model):
    """No idempotency key: the tools layer generates it, never the agent."""

    from_account_id: str = Field(min_length=1)
    to_pix_key: str = Field(min_length=1)
    amount_cents: int = Field(gt=0)
    description: str = Field("", max_length=MAX_DESCRIPTION_CHARS)
    authorization_id: str | None = None


class TransferPixOut(_Model):
    transfer_id: str
    kind: Literal["pix_out", "internal"]
    from_account_id: str
    to_pix_key: str
    amount_cents: int


# --------------------------------------------------------------- open_dispute


class OpenDisputeIn(_Model):
    transfer_id: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=500)


class OpenDisputeOut(_Model):
    dispute_id: str
    transfer_id: str
    status: str
    reason: UntrustedStr


# -------------------------------------------------------------------- helpers


def untrusted_paths(model: BaseModel, prefix: str = "") -> list[str]:
    """Paths of every untrusted field in `model`, e.g. `transactions[0].description`."""
    paths: list[str] = []
    for name, info in type(model).model_fields.items():
        path = f"{prefix}{name}"
        extra = info.json_schema_extra
        if isinstance(extra, dict) and extra.get(UNTRUSTED_KEY) is True:
            paths.append(path)
            continue
        value = getattr(model, name)
        if isinstance(value, BaseModel):
            paths.extend(untrusted_paths(value, f"{path}."))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, BaseModel):
                    paths.extend(untrusted_paths(item, f"{path}[{i}]."))
    return paths
