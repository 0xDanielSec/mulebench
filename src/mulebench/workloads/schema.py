"""Benign workload schema (schema_version 1).

A workload is a legitimate customer task with an exact expected outcome and no
attack payload. Workloads measure the usability cost of guards: tasks blocked
and confirmations requested. They reuse the scenario setup, user task and
expected-outcome models; see docs/ablation.md.
"""

from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import model_validator

from mulebench.attacks.schema import (
    ExpectedOutcome,
    NonEmpty,
    Setup,
    Slug,
    UserTask,
    _Model,
)
from mulebench.invariants import InvariantParams


class Workload(_Model):
    schema_version: Literal[1]
    id: Slug
    name: NonEmpty
    setup: Setup
    user_task: UserTask
    expected_outcome: ExpectedOutcome
    invariant_params: InvariantParams = InvariantParams()

    @model_validator(mode="after")
    def _cross_checks(self) -> Workload:
        problems: list[str] = []
        s = self.setup
        if s.clock.tzinfo is None or s.clock.utcoffset() is None:
            problems.append("setup.clock must include a UTC offset")
        if s.transactions:
            problems.append("setup.transactions: workloads seed no incoming payload carriers")
        ids = (
            [c.id for c in s.customers]
            + [a.id for a in s.accounts]
            + [p.ref for p in s.past_payments]
            + [a.ref for a in self.user_task.authorizations]
        )
        problems += [f"duplicate id: {i!r}" for i, n in Counter(ids).items() if n > 1]
        keys = [a.pix_key for a in s.accounts if a.pix_key is not None]
        problems += [f"duplicate pix_key: {k!r}" for k, n in Counter(keys).items() if n > 1]
        customers = {c.id for c in s.customers}
        owner = {a.id: a.customer for a in s.accounts}
        refs: list[tuple[str, str, object, str]] = [
            ("customer", a.customer, customers, f"account {a.id}") for a in s.accounts
        ]
        refs += [
            ("account", p.from_account, owner, f"past payment {p.ref}") for p in s.past_payments
        ]
        refs += [
            ("account", a.from_account, owner, f"authorization {a.ref}")
            for a in self.user_task.authorizations
        ]
        refs.append(("customer", self.user_task.customer, customers, "user_task"))
        refs += [
            ("account", e.from_account, owner, "expected_outcome.transfers")
            for e in self.expected_outcome.transfers
        ]
        for kind, value, pool, where in refs:
            if value not in pool:  # type: ignore[operator]
                problems.append(f"{where}: unknown {kind} {value!r}")
        if problems:
            raise ValueError("; ".join(problems))
        return self
