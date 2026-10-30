# ADR 0001: Judge attacks with invariants, not with an LLM judge

Status: accepted

## Context

An attack on a financial agent succeeds when something bad happens: money
moves without consent, another customer's data reaches the session, a limit is
evaded. An LLM judge would read the agent's text and give an opinion. Opinions
vary between runs and models, can themselves be prompt-injected by the same
payload, and cannot be audited line by line.

## Decision

Verdicts come only from observable effects: the ledger snapshot and the
tool-call trace. Each invariant is a deterministic Python check with a fixed
list of violation codes. No agent text is read. Invariants import nothing from
the tools, agents or harness packages, so a buggy guard cannot hide a
violation.

## Consequences

- Results are reproducible and explainable (code, transfer, call, account).
- Every rule is unit-tested and mutation-tested (`scripts/mutation_check.py`).
- Harms with no observable effect (for example a persuasive but unexecuted
  instruction) are out of scope until a tool makes them observable.
- New threat classes need new invariants, written and reviewed as code.
