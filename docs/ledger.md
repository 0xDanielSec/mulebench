# Ledger

`mulebench.ledger` is a SQLite-backed simulated core banking system. All data
in it is synthetic.

## Policy-free by design

The ledger is deliberately **policy-free about authorization and ownership**.
It never checks who asked for an operation, whether the caller owns the source
account, or whether a customer authorization exists. `transfer_pix` accepts an
optional `authorization_id` and stores it, but does not validate it.

Enforcement lives in the **tools layer** (`mulebench.tools`). This lets the
same ledger sit behind a vulnerable tool set or a hardened one. Invariants then
judge the outcome from ledger state and traces, not from what the agent said.

The ledger enforces only accounting facts:

| Check                         | Exception             |
|-------------------------------|-----------------------|
| Amount is a positive `int`    | `InvalidAmount`       |
| Account / pix key exists      | `UnknownAccount`      |
| Transfer exists (disputes)    | `UnknownTransfer`     |
| Source and destination differ | `SelfTransfer`        |
| Source is not frozen          | `AccountFrozen`       |
| Customer/account/pix key new  | `DuplicateEntity`     |
| Balance covers the amount     | `InsufficientFunds`   |
| Daily limit not exceeded      | `DailyLimitExceeded`  |
| Idempotency key reused safely | `IdempotencyConflict` |
| Authorization id exists       | `UnknownAuthorization` |
| Authorization not yet used    | `AuthorizationAlreadyUsed` |
| Customer exists (grant)       | `UnknownCustomer`     |
| Inbound description <= 140    | `DescriptionTooLong`  |

All of them subclass `LedgerError`.

A frozen account cannot send money, but it can still **receive** money
(incoming Pix and internal transfers). Only the source account's status is checked.

## Authorizations

Authorizations are explicit customer grants for one transfer. Only the
harness adds them, through `Ledger.add_authorization`, which simulates the
customer channel. No tool can create one.

The ledger enforces exactly one rule about them, as an **integrity
constraint**: an authorization backs at most one transfer. A partial
`UNIQUE` index on `transfers(authorization_id) WHERE authorization_id IS NOT
NULL` makes this race-safe. A second use raises `AuthorizationAlreadyUsed`.

The ledger still does **not** enforce ownership or authorization policy. It
does not check whether a transfer needs an authorization, or whether the
cited authorization matches the customer, account, payee or amount. Guards
in the tools layer do that.

## Money

Money is always integer cents (`INTEGER` columns with `typeof()` checks). Floats,
`Decimal` and `bool` are rejected with `InvalidAmount`.

## Atomicity and audit log

Every state change runs inside one `BEGIN IMMEDIATE` transaction, and its audit
row is written in that same transaction. If anything fails, both roll back,
including a failure raised by `COMMIT` itself (the transaction is rolled back
whenever one is still open, so the connection stays usable).

`tests/ledger/test_crash_consistency.py` injects faults between the state
change and the audit write, at every SQL statement of a transfer
(`Exception` and `KeyboardInterrupt`), in the rejected-audit path, and kills a
child process inside a transaction on a file database. Each time, nothing
partial is committed and the hash chain still verifies.

`tests/ledger/test_properties.py` (Hypothesis) checks money conservation,
non-negative balances, the daily limit, idempotency, one transfer per
authorization and audit-versus-state consistency against an independent model.
The default `ci` profile is derandomized (fixed seed); the weekly
`explore` workflow (`HYPOTHESIS_PROFILE=explore`) uses random seeds and prints
the reproduction blob on failure.

A rejected operation (any `LedgerError`) rolls back first. Then a separate
transaction appends an audit row with `outcome = 'rejected'` and the structured
error. Later invariants (for example structuring detection) need failed attempts.

The audit log is append-only. The API exposes only `audit_entries()` for reading.
SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. Each row records
`ts`, `actor`, `action`, `args` (canonical JSON), `result` (canonical JSON),
`outcome`, `prev_hash` and `hash`.

### Hash chain (tamper evidence)

```text
hash = sha256(prev_hash + "\n" + canonical_json({seq, ts, actor, action,
                                                 args_json, result_json, outcome}))
```

Canonical JSON is `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`, UTF-8. The first row's `prev_hash` is `GENESIS_HASH`
(64 zeros). `seq` is part of the hashed content, so moving a row's content to
another position changes its hash. The head is read and the row appended inside
the operation's `BEGIN IMMEDIATE` transaction, so concurrent writers cannot fork
the chain.

`Ledger.verify_audit_chain(expected_head=None)` recomputes the chain and returns
an `AuditChainReport(ok, rows_checked, head_hash, problems)`. It never raises on
tampered data. Each `AuditChainProblem(seq, code, detail)` has one of these codes:

| Code | Meaning |
|---|---|
| `malformed_row` | `prev_hash` or `hash` is not 64 lowercase hex characters |
| `seq_gap` | a sequence number is missing (row deleted) or out of place |
| `prev_hash_mismatch` | the link to the previous row's stored hash is broken |
| `hash_mismatch` | the row's content no longer matches its hash |
| `head_mismatch` | the last hash differs from `expected_head` (an anchor kept outside the database) |

**What it protects against:** edits, deletions and reorders of audit rows made
around the append-only triggers (for example with raw SQL on a copy of the file)
by someone who does not also recompute the chain. Rehashing a single row breaks
the next row's link. With an external head anchor, it also detects truncation of
the newest rows and a full rewrite.

**What it does NOT protect against:**

- A writer who recomputes the whole chain. There is no secret key (no HMAC or
  signature), so only an external anchor (`expected_head`) reveals a rewrite.
- Truncation of the newest rows, unless `expected_head` is given.
- Tampering with the state tables (`accounts`, `transfers`, ...). They are not
  hashed. The property tests check that audit rows match state changes, but
  that is a test-time check, not runtime evidence.
- Compromise of the SQLite file, the process or the host.

There is no migration: opening a database whose `audit_log` lacks the hash
columns raises `AuditSchemaOutdated`. Ledgers are created fresh per run.

## Time and the daily limit window

The ledger never reads the system clock directly. It takes a `Clock`
(`SystemClock` in production, `FixedClock` in tests).

Timestamps are stored in UTC as fixed-width ISO-8601 strings ending in `Z`, so
string order equals time order.

The daily limit window is the **local calendar day in America/Sao_Paulo**,
`[00:00, 24:00)`. We chose it over UTC because Pix limits are defined per
Brazilian day; a UTC window would reset at 21:00 local time. The bounds are
computed with `zoneinfo` (the `tzdata` package supplies the database on Windows)
and converted to UTC for the query. Only outgoing `pix_out` and `internal`
transfers count; incoming Pix does not.

Limits are per account (`accounts.daily_limit_cents`). The limit is resolved
through a `LimitPolicy`. The default, `FlatDailyLimit`, returns the account value.
A future nighttime policy can return a lower value based on `at_local.time()`.

## Idempotency

`idempotency_key` is required on every `transfer_pix`. It is unique per source
account. Reusing it with identical parameters returns the original transfer,
moves no money, and logs `transfer_replayed`. Reusing it with different
parameters raises `IdempotencyConflict`.

## Untrusted text

`transfers.description` (the Pix free-text field), `transfers.counterparty_name`
and `disputes.reason` are stored verbatim, without trimming or normalization.
They are **untrusted** and are the indirect-injection channels used by attack
scenarios.

## Concurrency

File-based databases use WAL mode and `busy_timeout`. Each `Ledger` instance owns
one connection; use one instance per thread. `BEGIN IMMEDIATE` serializes
writers, so concurrent transfers cannot overdraw an account, exceed the daily
limit, or double-spend an idempotency key. Tests in
`tests/ledger/test_concurrency.py` prove this against a real file database.
