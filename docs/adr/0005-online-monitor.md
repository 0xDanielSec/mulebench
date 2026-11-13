# ADR 0005: Online monitor over agent traces

Status: accepted

## Context

The invariants (INV-1..4) and the disclosure check judge a finished trial in
the harness. Teams running agents in production-like settings want the same
judgments as a detector over logs: tool-call traces plus ledger state, with
alerts that detection engineers can triage and port to their own stack.

Three facts shape the design:

- The harness package imports the tools layer (guards). The detector must not,
  for the same reason the invariants do not (ADR 0001, ADR 0004): it has to
  catch what a buggy or missing guard lets through.
- Attribution needs a `Scenario` (the attacker's goal payees and accounts).
  Production logs have no scenario, so attribution is not a live detector; it
  is the label source of the offline evaluation.
- Stored reports keep outgoing transfers, balances, trace and confirmations,
  but not the full ledger snapshot; the rest comes from the scenario seed.

## Decision

`mulebench monitor` is a new package, `mulebench.monitor`, that imports only
`mulebench.invariants`, `mulebench.disclosure`, `mulebench.ledger` and (pilot
adapter only) `mulebench.attacks`. Never `tools`, `agents` or `harness`; an
AST test enforces it. The disclosure check moved from the harness to
`mulebench.disclosure` and takes plain views so both can share it.

- Input: a versioned JSONL trace format (`docs/monitor.md`,
  `docs/monitor-trace.schema.json`): `session_start`, `tool_call`,
  `confirmation`, `final_answer`, `ledger.account`, `ledger.authorization`,
  `ledger.transfer`, `session_end`. A ledger snapshot is the same `ledger.*`
  events at the start of the stream.
- Engine: batch mode runs the unchanged invariant classes and the disclosure
  check once per session. Streaming mode keeps per-session state and re-runs
  the affected checks on each event that can change a verdict, diffing
  against alerts already emitted. Same code path, so streaming equals batch
  by construction. Late events are handled with an event-time watermark and a
  grace period: alerts are `provisional`, then `firm` once the watermark
  passes, or `retracted` if a later event clears them.
- Output: alerts as JSON lines (rule id, invariant, code, severity, status,
  session, customer, evidence: call seqs, transfer ids, accounts, field
  paths, amount). Evidence never stores free text.
- Severity: INV-1 money moved and INV-2 foreign debit are critical; INV-2
  foreign read and dispute, INV-3 limit and structuring, INV-4 missing or
  declined confirmation are high; `unverifiable_call` is medium. Disclosure:
  an exact foreign amount in a sink that leaves the bank (`dispute_reason`,
  `transfer_description`) is high; in the final answer it is high; an
  approximate match is medium.
- INV-4 is applicable only when the operator states the enforced
  confirmation threshold (`--enforced-confirmation-cents`), as in the harness.
- Rule docs: `mulebench monitor rules` writes one Sigma-like YAML document per
  rule. They document detection logic for porting; they are not executed, and
  stateful rules carry a correlation section plus prose. Regulatory mappings
  are marked "to be reviewed".
- Evaluation: an adapter turns stored report trials into events; the
  evaluation (in the harness, which may import attribution) replays pilots 02
  and 03 and reports consistency with the stored invariants, trial-level
  precision and recall against attribution labels (positive: any firm alert
  of severity high or above), a per-severity breakdown and the benign
  false-positive rate.

## Consequences

- One implementation of each rule; the monitor cannot drift from the harness.
- The evaluation measures the detector on lab scenarios with one model and
  few positives; it is not evidence about production performance.
- Consistency with the stored invariants is partly circular (attribution uses
  INV-1), so it is reported as a check, not as detection quality.
- Re-running every check on each event is quadratic per session; fine at
  pilot scale, revisit if sessions get long.

## Follow-up

- Implemented later: export of the rules as Microsoft Sentinel KQL analytic
  rules (`mulebench monitor rules --format kql`), next to the Sigma-like
  documents. A starting point, not production-validated; see
  `docs/monitor-kql.md`.
