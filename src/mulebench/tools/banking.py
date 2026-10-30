"""The banking tools. Each one is a thin mapping onto a single ledger call.

Tools contain no policy: ownership, authorization and confirmation checks are
guards (see `mulebench.tools.guards`). No tool creates authorizations.
"""

from __future__ import annotations

from typing import Literal

from mulebench.tools.context import ToolContext
from mulebench.tools.schemas import (
    GetBalanceIn,
    GetBalanceOut,
    ListTransactionsIn,
    ListTransactionsOut,
    OpenDisputeIn,
    OpenDisputeOut,
    TransactionView,
    TransferPixIn,
    TransferPixOut,
)


def get_balance(ctx: ToolContext, args: GetBalanceIn) -> GetBalanceOut:
    return GetBalanceOut(
        account_id=args.account_id,
        balance_cents=ctx.ledger.get_balance(args.account_id),
    )


def list_transactions(ctx: ToolContext, args: ListTransactionsIn) -> ListTransactionsOut:
    views = []
    for t in ctx.ledger.list_transfers(args.account_id, limit=args.limit):
        direction: Literal["in", "out"] = "out" if t.from_account_id == args.account_id else "in"
        views.append(
            TransactionView(
                id=t.id,
                kind=t.kind,
                direction=direction,
                amount_cents=t.amount_cents,
                counterparty_key=t.counterparty_key,
                counterparty_name=t.counterparty_name,
                description=t.description,
                created_at=t.created_at,
            )
        )
    return ListTransactionsOut(account_id=args.account_id, transactions=views)


def transfer_pix(ctx: ToolContext, args: TransferPixIn) -> TransferPixOut:
    t = ctx.ledger.transfer_pix(
        actor=ctx.customer_id,
        from_account_id=args.from_account_id,
        to_pix_key=args.to_pix_key,
        amount_cents=args.amount_cents,
        description=args.description,
        authorization_id=args.authorization_id,
        idempotency_key=ctx.new_idempotency_key(),
    )
    kind: Literal["pix_out", "internal"] = "internal" if t.kind == "internal" else "pix_out"
    return TransferPixOut(
        transfer_id=t.id,
        kind=kind,
        from_account_id=args.from_account_id,
        to_pix_key=args.to_pix_key,
        amount_cents=t.amount_cents,
    )


def open_dispute(ctx: ToolContext, args: OpenDisputeIn) -> OpenDisputeOut:
    d = ctx.ledger.open_dispute(
        actor=ctx.customer_id, transfer_id=args.transfer_id, reason=args.reason
    )
    return OpenDisputeOut(
        dispute_id=d.id, transfer_id=d.transfer_id, status=d.status, reason=d.reason
    )
