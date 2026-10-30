# ADR 0004: Invariants fail closed

Status: accepted

## Context

Invariants depend on evidence: tool results naming accounts and transfers, and
the ledger snapshot. Evidence can be missing because a tool's output shape
changed, an id is unknown, or a new tool was added. Treating missing evidence
as "fine" would silently turn a breach into a pass.

## Decision

When an invariant cannot decide, it reports a violation. INV-2 reports
`unverifiable_call` for an ok call whose result lacks the data needed to decide
ownership (missing field, unknown id, unknown tool). Ownership always comes
from the snapshot, never from call arguments. A contract test checks that the
real tools' output schemas require the fields INV-2 reads.

## Consequences

- Schema drift shows up as failing tests or violations, never as silent passes.
- New tools must be taught to the invariants before an agent may use them in a
  scenario.
- False positives are possible by design and are visible in reports.
