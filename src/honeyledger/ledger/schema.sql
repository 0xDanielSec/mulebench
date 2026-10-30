-- Honeyledger simulated core banking schema.
-- Money is always INTEGER cents. Timestamps are UTC ISO-8601 with 'Z'.

CREATE TABLE IF NOT EXISTS customers (
  id      TEXT PRIMARY KEY,
  name    TEXT NOT NULL,
  tax_id  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  id                 TEXT PRIMARY KEY,
  customer_id        TEXT NOT NULL REFERENCES customers(id),
  pix_key            TEXT UNIQUE,
  balance_cents      INTEGER NOT NULL
                     CHECK (typeof(balance_cents) = 'integer' AND balance_cents >= 0),
  daily_limit_cents  INTEGER NOT NULL
                     CHECK (typeof(daily_limit_cents) = 'integer' AND daily_limit_cents >= 0),
  status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen'))
);

-- Written by the harness; the ledger stores but never enforces authorizations.
CREATE TABLE IF NOT EXISTS authorizations (
  id               TEXT PRIMARY KEY,
  customer_id      TEXT NOT NULL REFERENCES customers(id),
  from_account_id  TEXT NOT NULL REFERENCES accounts(id),
  payee_pix_key    TEXT NOT NULL,
  max_amount_cents INTEGER NOT NULL
                   CHECK (typeof(max_amount_cents) = 'integer' AND max_amount_cents > 0),
  created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transfers (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL CHECK (kind IN ('pix_in', 'pix_out', 'internal')),
  from_account_id   TEXT REFERENCES accounts(id),
  to_account_id     TEXT REFERENCES accounts(id),
  counterparty_key  TEXT,
  counterparty_name TEXT,
  amount_cents      INTEGER NOT NULL
                    CHECK (typeof(amount_cents) = 'integer' AND amount_cents > 0),
  description       TEXT NOT NULL DEFAULT '',
  idempotency_key   TEXT,
  authorization_id  TEXT REFERENCES authorizations(id),
  actor             TEXT NOT NULL,
  created_at        TEXT NOT NULL,
  UNIQUE (from_account_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_transfers_from_time ON transfers(from_account_id, created_at);
CREATE INDEX IF NOT EXISTS ix_transfers_to_time ON transfers(to_account_id, created_at);

CREATE TABLE IF NOT EXISTS disputes (
  id           TEXT PRIMARY KEY,
  transfer_id  TEXT NOT NULL REFERENCES transfers(id),
  customer_id  TEXT NOT NULL REFERENCES customers(id),
  reason       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'open',
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  args_json   TEXT NOT NULL,
  result_json TEXT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'rejected'))
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
