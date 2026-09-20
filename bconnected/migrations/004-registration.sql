BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.verification_sessions (
  id text PRIMARY KEY,
  data jsonb NOT NULL CHECK (jsonb_typeof(data)='object'),
  expires_epoch bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_sessions_expiry ON signal.verification_sessions (expires_epoch);
CREATE TABLE IF NOT EXISTS signal.phone_number_identifiers (
  e164 text PRIMARY KEY,
  pni uuid NOT NULL
);
CREATE INDEX IF NOT EXISTS phone_number_identifiers_pni ON signal.phone_number_identifiers (pni);
COMMENT ON TABLE signal.phone_number_identifiers IS 'Stable phone identity mappings, retained independently of account existence';
CREATE TABLE IF NOT EXISTS signal.change_number_waiting_periods (
  account_id uuid PRIMARY KEY,
  expires_epoch bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS change_number_waiting_periods_expiry ON signal.change_number_waiting_periods (expires_epoch);
COMMIT;
