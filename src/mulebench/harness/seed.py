"""Build a fresh, deterministic ledger for one matrix cell.

Seeding order: customers, accounts, past payments (actor `seed`, oldest
first, each at session clock minus `days_ago`; the clock then returns to the
session clock), transactions (list order, clock +1 s after each), then session
authorizations. The session note lists the session
customer's accounts and the authorizations, rendered for the trusted channel.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Sequence
from datetime import timedelta

from mulebench.agents import NoteAuthorization, NoteMandate, SessionNote
from mulebench.attacks import RenderedSetup, Scenario
from mulebench.attacks.schema import SessionAuthorization, Setup, UserTask
from mulebench.ledger import Account, Customer, FixedClock, Ledger

SEED_STEP = timedelta(seconds=1)


def counter_ids() -> Callable[[str], str]:
    counter = itertools.count(1)
    return lambda prefix: f"{prefix}_{next(counter):04d}"


def seed_cell(
    scenario: Scenario, rendered: RenderedSetup
) -> tuple[Ledger, FixedClock, SessionNote]:
    return seed_setup(rendered.setup, scenario.user_task)


def seed_setup(setup: Setup, task: UserTask) -> tuple[Ledger, FixedClock, SessionNote]:
    """Seed a ledger from any setup and user task (scenarios and workloads)."""
    clock = FixedClock(setup.clock)
    ledger = Ledger(clock=clock, id_factory=counter_ids())
    for c in setup.customers:
        ledger.add_customer(Customer(id=c.id, name=c.name, tax_id=c.tax_id))
    for a in setup.accounts:
        ledger.add_account(
            Account(
                id=a.id,
                customer_id=a.customer,
                pix_key=a.pix_key,
                balance_cents=a.balance_cents,
                daily_limit_cents=a.daily_limit_cents,
                status=a.status,
            )
        )
    ordered = sorted(setup.past_payments, key=lambda p: (-p.days_ago, p.ref))
    for p in ordered:
        clock.set(setup.clock - timedelta(days=p.days_ago))
        ledger.transfer_pix(
            actor="seed",
            from_account_id=p.from_account,
            to_pix_key=p.to_pix_key,
            amount_cents=p.amount_cents,
            idempotency_key=f"seed-{p.ref}",
        )
    if ordered:
        clock.set(setup.clock)
    for t in setup.transactions:
        ledger.record_incoming_pix(
            to_account_id=t.to_account,
            amount_cents=t.amount_cents,
            counterparty_name=t.counterparty_name,
            counterparty_key=t.counterparty_key,
            description=t.description,
        )
        clock.advance(SEED_STEP)

    return ledger, clock, grant_session(ledger, setup, task.customer, task.authorizations)


def grant_session(
    ledger: Ledger,
    setup: Setup,
    customer: str,
    authorizations: Sequence[SessionAuthorization],
) -> SessionNote:
    """Grant one session's authorizations at the current clock and render its
    note. Later sessions of a multi-session run call this at their start."""
    note_auths = []
    mandates = []
    for g in authorizations:
        granted = ledger.add_authorization(
            customer_id=customer,
            from_account_id=g.from_account,
            payee_pix_key=g.payee_pix_key,
            max_amount_cents=g.max_amount_cents,
        )
        if g.note_purpose is not None:
            mandates.append(
                NoteMandate(
                    authorization_id=granted.id,
                    from_account=g.from_account,
                    purpose=g.note_purpose,
                )
            )
            continue
        note_auths.append(
            NoteAuthorization(
                authorization_id=granted.id,
                from_account=g.from_account,
                payee_pix_key=g.payee_pix_key,
                max_amount_cents=g.max_amount_cents,
            )
        )
    return SessionNote(
        accounts=tuple(a.id for a in setup.accounts if a.customer == customer),
        authorizations=tuple(note_auths),
        mandates=tuple(mandates),
    )
