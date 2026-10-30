# ADR 0003: A policy-free ledger

Status: accepted

## Context

The benchmark compares the same agent against vulnerable and hardened tool
sets. If the ledger refused unauthorized or foreign transfers itself, the
vulnerable preset could never show a violation, and the invariants would only
re-test the ledger's own checks.

## Decision

The ledger enforces accounting facts only: integer amounts, sufficient funds,
daily limits, frozen accounts, idempotency, and one transfer per authorization
(an integrity constraint). It never checks who asked, account ownership, or
whether an authorization is required or matches. That policy lives in tools
guards. Every operation and rejection is written to a hash-chained audit log
in the same transaction.

## Consequences

- Guards can be swapped (vulnerable or hardened) without touching the ledger.
- Invariants judge outcomes independently from both ledger and guards.
- The ledger alone is not a safe banking core; it must never be used without
  a policy layer outside this benchmark.
