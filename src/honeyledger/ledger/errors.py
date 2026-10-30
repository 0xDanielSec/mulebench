"""Ledger exceptions.

Every exception carries structured fields so the audit log can record the
rejection reason as data rather than as free text.
"""

from __future__ import annotations


class LedgerError(Exception):
    """Base class for all ledger errors."""

    def details(self) -> dict[str, object]:
        """Structured fields describing the error, for the audit log."""
        return {}

    def to_result(self) -> dict[str, object]:
        """Audit-log `result` payload for a rejected operation."""
        return {"ok": False, "error": type(self).__name__, **self.details()}


class InvalidAmount(LedgerError):
    def __init__(self, amount: object) -> None:
        super().__init__(f"amount must be a positive int of cents, got {amount!r}")
        self.amount = amount

    def details(self) -> dict[str, object]:
        return {"amount": repr(self.amount)}


class UnknownAccount(LedgerError):
    def __init__(self, ref: str) -> None:
        super().__init__(f"unknown account or pix key: {ref!r}")
        self.ref = ref

    def details(self) -> dict[str, object]:
        return {"ref": self.ref}


class UnknownTransfer(LedgerError):
    def __init__(self, transfer_id: str) -> None:
        super().__init__(f"unknown transfer: {transfer_id!r}")
        self.transfer_id = transfer_id

    def details(self) -> dict[str, object]:
        return {"transfer_id": self.transfer_id}


class AccountFrozen(LedgerError):
    def __init__(self, account_id: str) -> None:
        super().__init__(f"account is frozen: {account_id!r}")
        self.account_id = account_id

    def details(self) -> dict[str, object]:
        return {"account_id": self.account_id}


class SelfTransfer(LedgerError):
    def __init__(self, account_id: str) -> None:
        super().__init__(f"source and destination are the same account: {account_id!r}")
        self.account_id = account_id

    def details(self) -> dict[str, object]:
        return {"account_id": self.account_id}


class InsufficientFunds(LedgerError):
    def __init__(self, account_id: str, available_cents: int, requested_cents: int) -> None:
        super().__init__(
            f"insufficient funds in {account_id!r}: "
            f"available={available_cents} requested={requested_cents}"
        )
        self.account_id = account_id
        self.available_cents = available_cents
        self.requested_cents = requested_cents

    def details(self) -> dict[str, object]:
        return {
            "account_id": self.account_id,
            "available_cents": self.available_cents,
            "requested_cents": self.requested_cents,
        }


class DailyLimitExceeded(LedgerError):
    def __init__(
        self, account_id: str, limit_cents: int, spent_cents: int, requested_cents: int
    ) -> None:
        super().__init__(
            f"daily limit exceeded for {account_id!r}: "
            f"limit={limit_cents} spent={spent_cents} requested={requested_cents}"
        )
        self.account_id = account_id
        self.limit_cents = limit_cents
        self.spent_cents = spent_cents
        self.requested_cents = requested_cents

    def details(self) -> dict[str, object]:
        return {
            "account_id": self.account_id,
            "limit_cents": self.limit_cents,
            "spent_cents": self.spent_cents,
            "requested_cents": self.requested_cents,
        }


class IdempotencyConflict(LedgerError):
    def __init__(self, idempotency_key: str, existing_transfer_id: str) -> None:
        super().__init__(
            f"idempotency key {idempotency_key!r} already used with different "
            f"parameters (transfer {existing_transfer_id!r})"
        )
        self.idempotency_key = idempotency_key
        self.existing_transfer_id = existing_transfer_id

    def details(self) -> dict[str, object]:
        return {
            "idempotency_key": self.idempotency_key,
            "existing_transfer_id": self.existing_transfer_id,
        }
