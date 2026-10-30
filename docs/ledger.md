# Ledger

`honeyledger.ledger` is a SQLite-backed simulated core banking system. All data
in it is synthetic.

## Policy-free by design

The ledger is deliberately **policy-free about authorization and ownership**.
It never checks who asked for an operation, whether the caller owns the source
account, or whether a customer authorization exists. `transfer_pix` accepts an
optional `authorization_id` and stores it, but does not validate it.

Enforcement lives in the **tools layer** (`honeyledger.tools`). This lets the
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

All of them subclass `LedgerError`.

A frozen account cannot send money, but it can still **receive** money
(incoming Pix and internal transfers). Only the source account's status is checked.

## Money

Money is always integer cents (`INTEGER` columns with `typeof()` checks). Floats,
`Decimal` and `bool` are rejected with `InvalidAmount`.

## Atomicity and audit log

Every state change runs inside one `BEGIN IMMEDIATE` transaction, and its audit
row is written in that same transaction. If anything fails, both roll back.

A rejected operation (any `LedgerError`) rolls back first. Then a separate
transaction appends an audit row with `outcome = 'rejected'` and the structured
error. Later invariants (for example structuring detection) need failed attempts.

The audit log is append-only. The API exposes only `audit_entries()` for reading.
SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. Each row records
`ts`, `actor`, `action`, `args` (canonical JSON), `result` (canonical JSON) and
`outcome`.

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
