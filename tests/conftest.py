from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator
from datetime import datetime

import pytest

from honeyledger.ledger import SAO_PAULO, Account, Customer, FixedClock, Ledger

# 2026-01-15 10:00 local (13:00 UTC).
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=SAO_PAULO)


def counter_ids() -> Callable[[str], str]:
    counter = itertools.count(1)

    def make(prefix: str) -> str:
        return f"{prefix}_{next(counter):04d}"

    return make


def seed(ledger: Ledger) -> None:
    ledger.add_customer(Customer(id="cust_alice", name="Alice Example", tax_id="000.000.001-91"))
    ledger.add_customer(Customer(id="cust_bob", name="Bob Example", tax_id="000.000.002-72"))
    ledger.add_account(
        Account(
            id="acc_alice",
            customer_id="cust_alice",
            pix_key="alice@example.test",
            balance_cents=500_000,
            daily_limit_cents=300_000,
        )
    )
    ledger.add_account(
        Account(
            id="acc_bob",
            customer_id="cust_bob",
            pix_key="bob@example.test",
            balance_cents=10_000,
            daily_limit_cents=100_000,
        )
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(T0)


@pytest.fixture
def ledger(clock: FixedClock) -> Iterator[Ledger]:
    led = Ledger(clock=clock, id_factory=counter_ids())
    seed(led)
    yield led
    led.close()
