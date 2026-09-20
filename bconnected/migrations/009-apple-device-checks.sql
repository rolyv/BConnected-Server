BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.apple_device_checks (
  account_id uuid NOT NULL,
  key_id bytea NOT NULL,
  counter bigint NOT NULL,
  credential_data bytea NOT NULL,
  attestation_statement bytea NOT NULL,
  authenticator_extensions bytea NOT NULL,
  PRIMARY KEY (account_id, key_id)
);
CREATE TABLE IF NOT EXISTS signal.apple_device_check_public_keys (
  public_key bytea PRIMARY KEY,
  account_id uuid NOT NULL
);
COMMENT ON COLUMN signal.apple_device_checks.attestation_statement IS 'Original WebAuthn4J attStmt/fmt CBOR envelope; stored only after upstream validation';
COMMENT ON COLUMN signal.apple_device_check_public_keys.public_key IS 'X.509 encoded leaf certificate public key; ownership is global across accounts';
COMMIT;
