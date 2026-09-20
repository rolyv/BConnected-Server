BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.remote_configs (
  name text PRIMARY KEY,
  percentage integer NOT NULL CHECK (percentage BETWEEN 0 AND 100),
  enrolled_accounts uuid[] NOT NULL DEFAULT '{}',
  default_value text,
  value text,
  hash_key text
);
CREATE TABLE IF NOT EXISTS signal.messages (
  account_id uuid NOT NULL,
  device_generation bigint NOT NULL,
  server_timestamp bigint NOT NULL,
  message_id uuid NOT NULL,
  envelope bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (account_id, device_generation, server_timestamp, message_id)
);
CREATE INDEX IF NOT EXISTS messages_expiry ON signal.messages (expires_at);
COMMENT ON COLUMN signal.messages.envelope IS 'Serialized upstream encrypted envelope; never decrypted by the storage layer';
COMMIT;
