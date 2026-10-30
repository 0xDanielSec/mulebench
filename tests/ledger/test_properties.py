"""Property-based tests for the ledger (Hypothesis).

A stateful machine drives a real `Ledger` with random operations and checks
every outcome against a small, independent plain-Python model. The model never
calls ledger helpers; it re-derives every rule (funds, frozen accounts, daily
limit per Sao Paulo local day, idempotency, one use per authorization).

Laws checked after every step:
- money conservation: sum of balances == seeded + external in - external out;
- balances never negative and equal to the model;
- daily limit: per account and local day, outgoing total <= daily limit;
- idempotency: same key + same params returns the same transfer and moves no
  money; same key + different params raises IdempotencyConflict;
- an authorization backs at most one transfer (reuse raises
  AuthorizationAlreadyUsed and moves no money);
- audit rows match state changes, and the audit hash chain verifies.

Generators draw from small fixed pools (accounts, keys, amounts near the
limits) so failures shrink to short, readable programs.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from mulebench.ledger import (
    SAO_PAULO,
    Account,
    Customer,
    FixedClock,
    Ledger,
    LedgerError,
)
from tests.conftest import counter_ids

T0 = datetime(2026, 1, 15, 22, 0, tzinfo=SAO_PAULO)  # near local midnight

ACCOUNTS = (
    # id, customer, pix_key, balance, daily_limit, status
    ("acc_a", "cust_1", "a@example.test", 50_000, 30_000, "active"),
    ("acc_b", "cust_2", "b@example.test", 20_000, 100_000, "active"),
    ("acc_c", "cust_3", "c@example.test", 10_000, 5_000, "frozen"),
    ("acc_d", "cust_1", None, 0, 10_000, "active"),
)
ACCOUNT_IDS = [a[0] for a in ACCOUNTS]
PAYEES = ["a@example.test", "b@example.test", "c@example.test", "ext1@example.test", ""]
KEYS = ["k0", "k1", "k2"]
AMOUNTS = st.one_of(
    st.integers(min_value=1, max_value=40_000),
    st.sampled_from([1, 4_999, 5_000, 5_001, 29_999, 30_000, 30_001]),
)
STEPS = [timedelta(minutes=1), timedelta(hours=1), timedelta(hours=3), timedelta(hours=30)]


@dataclass
class Model:
    """Independent re-statement of the ledger's accounting rules."""

    balances: dict[str, int]
    limits: dict[str, int]
    frozen: set[str]
    key_owner: dict[str, str]  # pix key -> account id
    owner: dict[str, str]  # account id -> customer
    external_in: int = 0
    external_out: int = 0
    spent: dict[tuple[str, date], int] = field(default_factory=lambda: defaultdict(int))
    # (source, idempotency key) -> (to_key, amount, auth id, transfer id)
    idem: dict[tuple[str, str], tuple[str, int, str | None, str]] = field(default_factory=dict)
    auths: dict[str, str] = field(default_factory=dict)  # auth id -> source account
    used_auths: set[str] = field(default_factory=set)
    transfers: set[str] = field(default_factory=set)

    def predict_transfer(
        self, src: str, to_key: str, amount: int, key: str, auth: str | None, today: date
    ) -> str:
        """Expected outcome: 'ok', 'replay:<id>' or an error class name."""
        if src not in self.balances or not to_key:
            return "UnknownAccount"
        if self.key_owner.get(to_key) == src:
            return "SelfTransfer"
        prior = self.idem.get((src, key))
        if prior is not None:
            same = prior[:3] == (to_key, amount, auth)
            return f"replay:{prior[3]}" if same else "IdempotencyConflict"
        if auth is not None:
            if auth not in self.auths:
                return "UnknownAuthorization"
            if auth in self.used_auths:
                return "AuthorizationAlreadyUsed"
        if src in self.frozen:
            return "AccountFrozen"
        if self.balances[src] < amount:
            return "InsufficientFunds"
        if self.spent[(src, today)] + amount > self.limits[src]:
            return "DailyLimitExceeded"
        return "ok"

    def apply_transfer(
        self, src: str, to_key: str, amount: int, key: str, auth: str | None, today: date, tx: str
    ) -> None:
        self.balances[src] -= amount
        dest = self.key_owner.get(to_key)
        if dest is None:
            self.external_out += amount
        else:
            self.balances[dest] += amount
        self.spent[(src, today)] += amount
        self.idem[(src, key)] = (to_key, amount, auth, tx)
        if auth is not None:
            self.used_auths.add(auth)
        self.transfers.add(tx)


class LedgerMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.clock = FixedClock(T0)
        self.ledger = Ledger(clock=self.clock, id_factory=counter_ids())
        for cid in sorted({a[1] for a in ACCOUNTS}):
            self.ledger.add_customer(Customer(id=cid, name="Example", tax_id=f"SYN-{cid}"))
        for aid, cid, key, bal, lim, status in ACCOUNTS:
            self.ledger.add_account(
                Account(
                    id=aid,
                    customer_id=cid,
                    pix_key=key,
                    balance_cents=bal,
                    daily_limit_cents=lim,
                    status=status,  # type: ignore[arg-type]
                )
            )
        self.seeded_total = sum(a[3] for a in ACCOUNTS)
        self.model = Model(
            balances={a[0]: a[3] for a in ACCOUNTS},
            limits={a[0]: a[4] for a in ACCOUNTS},
            frozen={a[0] for a in ACCOUNTS if a[5] == "frozen"},
            key_owner={a[2]: a[0] for a in ACCOUNTS if a[2] is not None},
            owner={a[0]: a[1] for a in ACCOUNTS},
        )
        self.audit_rows = len(self.ledger.audit_entries())

    def teardown(self) -> None:
        self.ledger.close()

    # ------------------------------------------------------------- helpers

    def today(self) -> date:
        return self.clock.now().astimezone(SAO_PAULO).date()

    def expect_audit(self, action: str, outcome: str, result_key: str | None = None) -> str:
        entries = self.ledger.audit_entries()
        assert len(entries) == self.audit_rows + 1, "exactly one audit row per operation"
        self.audit_rows += 1
        last = entries[-1]
        assert (last.action, last.outcome) == (action, outcome)
        return str(last.result.get(result_key)) if result_key else ""

    def do_transfer(self, src: str, to_key: str, amount: int, key: str, auth: str | None) -> None:
        today = self.today()
        expected = self.model.predict_transfer(src, to_key, amount, key, auth, today)
        before = dict(self.model.balances)
        error: str | None = None
        try:
            t = self.ledger.transfer_pix(
                actor="cust",
                from_account_id=src,
                to_pix_key=to_key,
                amount_cents=amount,
                idempotency_key=key,
                authorization_id=auth,
            )
        except LedgerError as exc:
            error = type(exc).__name__
        if error is not None:
            assert error == expected
            self.expect_audit("transfer_rejected", "rejected")
            self.check_balances(before)
            return
        if expected.startswith("replay:"):
            assert t.id == expected.removeprefix("replay:")
            assert self.expect_audit("transfer_replayed", "ok", "transfer_id") == t.id
            self.check_balances(before)
            return
        assert expected == "ok", f"ledger accepted, model expected {expected}"
        assert self.expect_audit("transfer", "ok", "transfer_id") == t.id
        assert t.kind == ("pix_out" if to_key not in self.model.key_owner else "internal")
        self.model.apply_transfer(src, to_key, amount, key, auth, today, t.id)

    def check_balances(self, expected: dict[str, int]) -> None:
        actual = {a: self.ledger.get_balance(a) for a in ACCOUNT_IDS}
        assert actual == expected, "a rejected or replayed call moved money"

    # --------------------------------------------------------------- rules

    @rule(account=st.sampled_from(ACCOUNT_IDS), amount=st.integers(1, 50_000))
    def incoming_pix(self, account: str, amount: int) -> None:
        t = self.ledger.record_incoming_pix(
            to_account_id=account,
            amount_cents=amount,
            counterparty_name="Payer Example",
            counterparty_key="payer@example.test",
            description="",
        )
        assert self.expect_audit("pix_in_recorded", "ok", "transfer_id") == t.id
        self.model.balances[account] += amount
        self.model.external_in += amount
        self.model.transfers.add(t.id)

    @rule(
        src=st.sampled_from(ACCOUNT_IDS),
        to_key=st.sampled_from(PAYEES),
        amount=AMOUNTS,
        key=st.sampled_from(KEYS),
        data=st.data(),
    )
    def transfer(self, src: str, to_key: str, amount: int, key: str, data: st.DataObject) -> None:
        choices: list[str | None] = [None, "auth_ghost", *sorted(self.model.auths)]
        auth = data.draw(st.sampled_from(choices), label="authorization_id")
        self.do_transfer(src, to_key, amount, key, auth)

    @rule(
        src=st.sampled_from(["acc_a", "acc_b", "acc_d"]),
        offset=st.sampled_from([0, 1]),
        key=st.sampled_from(KEYS),
    )
    def transfer_at_limit_edge(self, src: str, offset: int, key: str) -> None:
        """Exactly the remaining daily limit (valid) or one cent more (rejected)."""
        remaining = self.model.limits[src] - self.model.spent[(src, self.today())]
        amount = remaining + offset
        if amount < 1:
            return
        if amount > self.model.balances[src]:
            self.incoming_pix(src, amount - self.model.balances[src])
        self.do_transfer(src, "ext1@example.test", amount, f"edge-{key}-{self.audit_rows}", None)

    @rule(data=st.data())
    def replay_same_params(self, data: st.DataObject) -> None:
        if not self.model.idem:
            return
        (src, key), (to_key, amount, auth, _) = data.draw(
            st.sampled_from(sorted(self.model.idem.items())), label="replayed"
        )
        self.do_transfer(src, to_key, amount, key, auth)

    @rule(data=st.data(), delta=st.integers(1, 1_000))
    def replay_changed_amount(self, data: st.DataObject, delta: int) -> None:
        if not self.model.idem:
            return
        (src, key), (to_key, amount, auth, _) = data.draw(
            st.sampled_from(sorted(self.model.idem.items())), label="replayed"
        )
        self.do_transfer(src, to_key, amount + delta, key, auth)

    @rule(src=st.sampled_from(ACCOUNT_IDS), max_cents=st.integers(1, 40_000))
    def add_authorization(self, src: str, max_cents: int) -> None:
        a = self.ledger.add_authorization(
            customer_id=self.model.owner[src],
            from_account_id=src,
            payee_pix_key="ext1@example.test",
            max_amount_cents=max_cents,
        )
        assert self.expect_audit("authorization_added", "ok", "authorization_id") == a.id
        self.model.auths[a.id] = src

    @rule(data=st.data(), amount=st.integers(1, 100))
    def reuse_authorization(self, data: st.DataObject, amount: int) -> None:
        """A used authorization cited again (fresh key, small amount)."""
        if not self.model.used_auths:
            return
        auth = data.draw(st.sampled_from(sorted(self.model.used_auths)), label="used_auth")
        src = self.model.auths[auth]
        fresh = f"reuse-{len(self.model.idem)}-{self.audit_rows}"
        before = dict(self.model.balances)
        expected = self.model.predict_transfer(
            src, "ext1@example.test", amount, fresh, auth, self.today()
        )
        assert expected == "AuthorizationAlreadyUsed"
        self.do_transfer(src, "ext1@example.test", amount, fresh, auth)
        assert self.model.balances == before

    @rule(bad=st.sampled_from([0, -1, True, 1.5]), src=st.sampled_from(ACCOUNT_IDS))
    def invalid_amount(self, bad: object, src: str) -> None:
        before = dict(self.model.balances)
        with pytest.raises(LedgerError) as info:
            self.ledger.transfer_pix(
                actor="cust",
                from_account_id=src,
                to_pix_key="ext1@example.test",
                amount_cents=bad,  # type: ignore[arg-type]
                idempotency_key="bad",
            )
        assert type(info.value).__name__ == "InvalidAmount"
        self.expect_audit("transfer_rejected", "rejected")
        self.check_balances(before)

    @rule(data=st.data())
    def open_dispute(self, data: st.DataObject) -> None:
        target = data.draw(st.sampled_from(["tx_ghost", *sorted(self.model.transfers)]))
        if target == "tx_ghost":
            with pytest.raises(LedgerError) as info:
                self.ledger.open_dispute(actor="cust", transfer_id=target, reason="x")
            assert type(info.value).__name__ == "UnknownTransfer"
            self.expect_audit("dispute_rejected", "rejected")
            return
        self.ledger.open_dispute(actor="cust", transfer_id=target, reason="not recognized")
        assert target != "tx_ghost"
        self.expect_audit("dispute_opened", "ok")

    @rule(step=st.sampled_from(STEPS))
    def advance_clock(self, step: timedelta) -> None:
        self.clock.advance(step)

    # ---------------------------------------------------------- invariants

    @invariant()
    def money_is_conserved(self) -> None:
        total = sum(a.balance_cents for a in self.ledger.snapshot().accounts)
        assert total == self.seeded_total + self.model.external_in - self.model.external_out

    @invariant()
    def balances_match_model_and_are_non_negative(self) -> None:
        for a in self.ledger.snapshot().accounts:
            assert a.balance_cents >= 0
            assert a.balance_cents == self.model.balances[a.id]

    @invariant()
    def daily_limit_law(self) -> None:
        snap = self.ledger.snapshot()
        limits = {a.id: a.daily_limit_cents for a in snap.accounts}
        spent: dict[tuple[str, date], int] = defaultdict(int)
        for t in snap.transfers:
            if t.kind in ("pix_out", "internal") and t.from_account_id is not None:
                spent[(t.from_account_id, t.created_at.astimezone(SAO_PAULO).date())] += (
                    t.amount_cents
                )
        for (acc, _), total in spent.items():
            assert total <= limits[acc]

    @invariant()
    def one_transfer_per_authorization(self) -> None:
        cited = [t.authorization_id for t in self.ledger.snapshot().transfers if t.authorization_id]
        assert len(cited) == len(set(cited))
        assert set(cited) == self.model.used_auths

    @invariant()
    def audit_matches_state(self) -> None:
        snap = self.ledger.snapshot()
        entries = self.ledger.audit_entries()
        ok_transfers = [str(e.result["transfer_id"]) for e in entries if e.action == "transfer"]
        outgoing = [t.id for t in snap.transfers if t.kind in ("pix_out", "internal")]
        assert sorted(ok_transfers) == sorted(outgoing)
        incoming = [str(e.result["transfer_id"]) for e in entries if e.action == "pix_in_recorded"]
        assert sorted(incoming) == sorted(t.id for t in snap.transfers if t.kind == "pix_in")
        assert {t.id for t in snap.transfers} == self.model.transfers
        assert self.ledger.verify_audit_chain().ok


TestLedgerProperties = LedgerMachine.TestCase


# ------------------------------------------------------- small properties


@given(
    st.dictionaries(
        st.text(max_size=5), st.one_of(st.integers(), st.text(max_size=5), st.none()), max_size=6
    )
)
def test_canonical_json_is_key_order_independent(data: dict[str, object]) -> None:
    from mulebench.ledger.ledger import _canonical

    reordered = dict(reversed(list(data.items())))
    assert _canonical(data) == _canonical(reordered)


@given(
    st.one_of(
        st.booleans(),
        st.floats(allow_nan=False),
        st.decimals(allow_nan=False),
        st.integers(max_value=0),
        st.integers(min_value=2**62 + 1),
    )
)
def test_invalid_amounts_rejected_without_state_change(bad: object) -> None:
    clock = FixedClock(T0)
    led = Ledger(clock=clock, id_factory=counter_ids())
    led.add_customer(Customer(id="c", name="Example", tax_id="SYN"))
    led.add_account(Account(id="a", customer_id="c", balance_cents=100, daily_limit_cents=100))
    with pytest.raises(LedgerError, match="amount"):
        led.transfer_pix(
            actor="c",
            from_account_id="a",
            to_pix_key="x@example.test",
            amount_cents=bad,  # type: ignore[arg-type]
            idempotency_key="k",
        )
    assert led.get_balance("a") == 100
    assert led.audit_entries()[-1].outcome == "rejected"
    led.close()
