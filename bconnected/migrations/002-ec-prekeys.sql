BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.single_use_ec_prekeys (
  account_id uuid NOT NULL,
  device_id smallint NOT NULL CHECK (device_id BETWEEN 1 AND 127),
  key_id bigint NOT NULL CHECK (key_id BETWEEN 0 AND 2147483647),
  public_key bytea NOT NULL,
  PRIMARY KEY (account_id, device_id, key_id)
);
COMMENT ON COLUMN signal.single_use_ec_prekeys.public_key IS 'Unmodified libsignal serialized EC public key; private keys never enter this store';
COMMIT;
