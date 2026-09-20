BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.profiles_v1 (
  account_id uuid NOT NULL,
  version text NOT NULL,
  name bytea,
  avatar text,
  about_emoji bytea,
  about bytea,
  payment_address bytea,
  phone_number_sharing bytea,
  commitment bytea NOT NULL,
  PRIMARY KEY (account_id, version)
);
CREATE TABLE IF NOT EXISTS signal.profiles_v2 (
  account_id uuid NOT NULL,
  version bytea NOT NULL,
  data bytea NOT NULL,
  data_hash bytea NOT NULL,
  payment_address bytea,
  payment_address_hash bytea,
  commitment bytea NOT NULL,
  PRIMARY KEY (account_id, version)
);
CREATE TABLE IF NOT EXISTS signal.profile_avatars (
  identity bytea PRIMARY KEY,
  url text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS profile_avatars_expiry ON signal.profile_avatars (expires_at);
COMMENT ON TABLE signal.profiles_v2 IS 'Unmodified encrypted profile ciphertext and public commitments; no profile decryption';
COMMIT;
