"""Build a fresh, deterministic ledger for one matrix cell.

Seeding order: customers, accounts, transactions (list order, clock +1 s after
each), then session authorizations. The session note lists the session
customer's accounts and the authorizations, rendered for the trusted channel.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import timedelta

from honeyledger.agents import NoteAuthorization, SessionNote
from honeyledger.attacks import RenderedSetup, Scenario
from honeyledger.ledger import Account, Customer, FixedClock, Ledger

SEED_STEP = timedelta(seconds=1)


def counter_ids() -> Callable[[str], str]:
    counter = itertools.count(1)
    return lambda prefix: f"{prefix}_{next(counter):04d}"


def seed_cell(
    scenario: Scenario, rendered: RenderedSetup
) -> tuple[Ledger, FixedClock, SessionNote]:
    setup = rendered.setup
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
    for t in setup.transactions:
        ledger.record_incoming_pix(
            to_account_id=t.to_account,
            amount_cents=t.amount_cents,
            counterparty_name=t.counterparty_name,
            counterparty_key=t.counterparty_key,
            description=t.description,
        )
        clock.advance(SEED_STEP)

    customer = scenario.user_task.customer
    note_auths = []
    for g in scenario.user_task.authorizations:
        granted = ledger.add_authorization(
            customer_id=customer,
            from_account_id=g.from_account,
            payee_pix_key=g.payee_pix_key,
            max_amount_cents=g.max_amount_cents,
        )
        note_auths.append(
            NoteAuthorization(
                authorization_id=granted.id,
                from_account=g.from_account,
                payee_pix_key=g.payee_pix_key,
                max_amount_cents=g.max_amount_cents,
            )
        )
    note = SessionNote(
        accounts=tuple(a.id for a in setup.accounts if a.customer == customer),
        authorizations=tuple(note_auths),
    )
    return ledger, clock, note
