BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.report_messages (
  hash bytea PRIMARY KEY CHECK (octet_length(hash) > 0),
  expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS report_messages_expiry ON signal.report_messages(expires_at);
COMMENT ON COLUMN signal.report_messages.hash IS 'Existing SHA-256 report eligibility hash; message plaintext is never stored here';
COMMIT;
