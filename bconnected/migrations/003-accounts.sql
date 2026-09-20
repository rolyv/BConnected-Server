BEGIN;
-- Account identity and related key/recovery changes share one SQL transaction.
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.accounts (
  aci uuid PRIMARY KEY,
  number text UNIQUE,
  pni uuid UNIQUE,
  version integer NOT NULL CHECK (version >= 0),
  data jsonb NOT NULL,
  username_hash bytea,
  username_link uuid UNIQUE,
  CHECK ((number IS NULL) = (pni IS NULL))
);
CREATE TABLE IF NOT EXISTS signal.usernames (
  hash bytea PRIMARY KEY,
  aci uuid NOT NULL,
  confirmed boolean NOT NULL,
  reclaimable boolean NOT NULL DEFAULT false,
  expires_at bigint,
  CHECK (confirmed = (expires_at IS NULL))
);
CREATE INDEX IF NOT EXISTS usernames_expiry ON signal.usernames(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS signal.deleted_accounts (
  pni uuid PRIMARY KEY, aci uuid NOT NULL, expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS deleted_accounts_aci ON signal.deleted_accounts(aci);
CREATE INDEX IF NOT EXISTS deleted_accounts_expiry ON signal.deleted_accounts(expires_at);
CREATE TABLE IF NOT EXISTS signal.used_link_tokens (
  hash bytea PRIMARY KEY, expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS used_link_tokens_expiry ON signal.used_link_tokens(expires_at);
CREATE TABLE IF NOT EXISTS signal.signed_prekeys (
  identifier uuid NOT NULL,
  device_id smallint NOT NULL,
  kind text NOT NULL CHECK (kind IN ('ec','kem')),
  key_id bigint NOT NULL CHECK (key_id BETWEEN 0 AND 2147483647),
  public_key bytea NOT NULL,
  signature bytea NOT NULL,
  PRIMARY KEY(identifier,device_id,kind)
);
CREATE TABLE IF NOT EXISTS signal.phone_recovery_passwords (
  pni uuid PRIMARY KEY, salt text NOT NULL, hash text NOT NULL, expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS phone_recovery_passwords_expiry ON signal.phone_recovery_passwords(expires_at);
COMMIT;
