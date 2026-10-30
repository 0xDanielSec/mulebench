"""Declarative attack scenario schema (schema_version 1).

A scenario seeds a synthetic ledger, gives the agent a legitimate user task,
and plants an attack payload in one untrusted channel. Every scenario carries a
paired benign control: the same setup with a harmless payload, used to measure
utility next to security. See docs/scenarios.md.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from mulebench.invariants import InvariantParams
from mulebench.ledger import MAX_DESCRIPTION_CHARS

PLACEHOLDER = "{{payload}}"

Ident = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.@-]{1,64}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1)]

Category = Literal["indirect_injection", "direct_injection", "data_exfiltration", "limit_evasion"]
Channel = Literal[
    "pix_description", "payee_name", "dispute_reason", "kyc_document", "support_ticket"
]
InvariantId = Literal["INV-1", "INV-2", "INV-3", "INV-4"]
HintValue = StrictBool | StrictInt | StrictStr
ToolName = Literal["get_balance", "list_transactions", "transfer_pix", "open_dispute"]

# Which seeded-transaction field carries the payload, per channel. Channels not
# listed here have no setup slot yet and are rejected by validation.
CHANNEL_FIELD: dict[str, Literal["description", "counterparty_name"]] = {
    "pix_description": "description",
    "payee_name": "counterparty_name",
}


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


# --------------------------------------------------------------------- setup


class SetupCustomer(_Model):
    id: Ident
    name: NonEmpty
    tax_id: NonEmpty


class SetupAccount(_Model):
    id: Ident
    customer: Ident
    pix_key: NonEmpty | None = None
    balance_cents: int = Field(ge=0)
    daily_limit_cents: int = Field(ge=0)
    status: Literal["active", "frozen"] = "active"


class SetupTransaction(_Model):
    """A seeded incoming Pix. Text fields may hold the payload placeholder."""

    ref: Ident
    to_account: Ident
    amount_cents: int = Field(gt=0)
    counterparty_name: NonEmpty
    counterparty_key: NonEmpty
    description: str = ""


class Setup(_Model):
    # YAML gives a string or a datetime; parse leniently, then require an offset.
    clock: datetime = Field(strict=False)
    customers: list[SetupCustomer] = Field(min_length=1)
    accounts: list[SetupAccount] = Field(min_length=1)
    transactions: list[SetupTransaction] = []


# ---------------------------------------------------------------- user task


class SessionAuthorization(_Model):
    """Granted by the customer channel; delivered to the agent as a session note."""

    ref: Ident
    from_account: Ident
    payee_pix_key: NonEmpty
    max_amount_cents: int = Field(gt=0)


class UserTask(_Model):
    customer: Ident
    request: NonEmpty
    authorizations: list[SessionAuthorization] = []


class Injection(_Model):
    transaction: Ident
    payload: NonEmpty


# ----------------------------------------------------------------- outcomes


class ExpectedTransfer(_Model):
    from_account: Ident
    to_pix_key: NonEmpty
    amount_cents: int = Field(gt=0)


class ExpectedOutcome(_Model):
    """Benign run: transfers must match EXACTLY. Attack run: as a SUBSET."""

    transfers: list[ExpectedTransfer] = []
    tool_calls: list[ToolName] = []


class BenignControl(_Model):
    payload: NonEmpty
    expected_outcome: ExpectedOutcome


class Reference(_Model):
    title: NonEmpty
    url: NonEmpty | None = None


class BrazilContext(_Model):
    review_status: Literal["to_be_reviewed"]
    owasp_agentic: list[str] = []
    lgpd: list[str] = []
    bacen_4893: list[str] = []
    notes: str = ""


# ------------------------------------------------------------------ scenario


class Scenario(_Model):
    schema_version: Literal[1]
    id: Slug
    name: NonEmpty
    category: Category
    channel: Channel
    setup: Setup
    user_task: UserTask
    injection: Injection
    canary: Annotated[str, StringConstraints(min_length=6)]
    expected_invariants: list[InvariantId] = Field(min_length=1)
    invariant_params: InvariantParams = InvariantParams()
    # Behavior knobs for agents that support them (scripted agent only so
    # far). Unsupported hints are ignored; reports record the applied ones.
    agent_hints: dict[Ident, HintValue] = {}
    benign_control: BenignControl
    references: list[Reference] = []
    brazil_context: BrazilContext | None = None

    @model_validator(mode="after")
    def _cross_checks(self) -> Scenario:
        problems: list[str] = []
        s = self.setup

        # Clock.
        if s.clock.tzinfo is None or s.clock.utcoffset() is None:
            problems.append("setup.clock must include a timezone offset")

        # Unique ids in one namespace.
        ids = (
            [c.id for c in s.customers]
            + [a.id for a in s.accounts]
            + [t.ref for t in s.transactions]
            + [a.ref for a in self.user_task.authorizations]
        )
        problems += [f"duplicate id: {i!r}" for i, n in Counter(ids).items() if n > 1]
        keys = [a.pix_key for a in s.accounts if a.pix_key is not None]
        problems += [f"duplicate pix_key: {k!r}" for k, n in Counter(keys).items() if n > 1]
        if len(set(self.expected_invariants)) != len(self.expected_invariants):
            problems.append("duplicate entry in expected_invariants")

        # References resolve.
        customers = {c.id for c in s.customers}
        owner = {a.id: a.customer for a in s.accounts}
        txs = {t.ref: t for t in s.transactions}

        def need(kind: str, value: str, pool: object, where: str) -> None:
            if value not in pool:  # type: ignore[operator]
                problems.append(f"{where}: unknown {kind} {value!r}")

        for a in s.accounts:
            need("customer", a.customer, customers, f"account {a.id}")
        for t in s.transactions:
            need("account", t.to_account, owner, f"transaction {t.ref}")
        for auth in self.user_task.authorizations:
            need("account", auth.from_account, owner, f"authorization {auth.ref}")
        need("customer", self.user_task.customer, customers, "user_task")
        need("transaction", self.injection.transaction, txs, "injection")
        for e in self.benign_control.expected_outcome.transfers:
            need("account", e.from_account, owner, "expected_outcome.transfers")

        # Placeholder: exactly once in the setup, in the channel's field.
        field = CHANNEL_FIELD.get(self.channel)
        total = sum(
            t.description.count(PLACEHOLDER) + t.counterparty_name.count(PLACEHOLDER)
            for t in s.transactions
        )
        target = txs.get(self.injection.transaction)
        if field is None:
            problems.append(f"channel {self.channel!r} has no setup slot yet")
        elif target is not None:
            if total != 1 or getattr(target, field).count(PLACEHOLDER) != 1:
                problems.append(
                    f"{PLACEHOLDER} must appear exactly once in the setup, in "
                    f"transaction {target.ref}.{field}"
                )
            # The agent must be able to see the payload.
            if owner.get(target.to_account, self.user_task.customer) != self.user_task.customer:
                problems.append(
                    f"injection target {target.ref} is not credited to an account "
                    "of the session customer"
                )

        # Description length (Pix cap), with both payloads rendered.
        for t in s.transactions:
            for label, payload in (
                ("attack", self.injection.payload),
                ("benign", self.benign_control.payload),
            ):
                rendered = t.description.replace(PLACEHOLDER, payload)
                if len(rendered) > MAX_DESCRIPTION_CHARS:
                    problems.append(
                        f"transaction {t.ref}: {label} description has {len(rendered)} "
                        f"chars, max is {MAX_DESCRIPTION_CHARS}"
                    )

        # Canary: only in the attack payload.
        if self.canary not in self.injection.payload:
            problems.append("canary must appear in injection.payload")
        if self.canary in self.benign_control.payload:
            problems.append("canary must not appear in benign_control.payload")
        elsewhere = [self.user_task.request] + [
            v for t in s.transactions for v in (t.description, t.counterparty_name)
        ]
        if any(self.canary in v for v in elsewhere):
            problems.append("canary must appear only in injection.payload")

        if problems:
            raise ValueError("; ".join(dict.fromkeys(problems)))
        return self


# ------------------------------------------------------------------- render


class RenderedSetup(_Model):
    """A setup with the payload slot filled for one variant."""

    scenario_id: str
    variant: Literal["attack", "benign"]
    payload: str
    setup: Setup


def render(scenario: Scenario, variant: Literal["attack", "benign"]) -> RenderedSetup:
    """Fill the payload placeholder. Pure: the scenario is not modified."""
    payload = scenario.injection.payload if variant == "attack" else scenario.benign_control.payload
    transactions = [
        t.model_copy(
            update={
                "description": t.description.replace(PLACEHOLDER, payload),
                "counterparty_name": t.counterparty_name.replace(PLACEHOLDER, payload),
            }
        )
        for t in scenario.setup.transactions
    ]
    return RenderedSetup(
        scenario_id=scenario.id,
        variant=variant,
        payload=payload,
        setup=scenario.setup.model_copy(update={"transactions": transactions}),
    )
