BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.push_challenges (
  aci uuid PRIMARY KEY,
  token bytea NOT NULL,
  expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS push_challenges_expiry ON signal.push_challenges(expires_at);
COMMIT;
