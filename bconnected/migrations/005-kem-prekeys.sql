BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.single_use_kem_prekeys (
  account_id uuid NOT NULL,
  device_id smallint NOT NULL CHECK (device_id BETWEEN 1 AND 127),
  key_id bigint NOT NULL CHECK (key_id BETWEEN 0 AND 2147483647),
  public_key bytea NOT NULL,
  signature bytea NOT NULL,
  PRIMARY KEY (account_id, device_id, key_id)
);
COMMENT ON TABLE signal.single_use_kem_prekeys IS 'Unmodified libsignal KEM public keys and signatures; atomic single use without S3 pages';
COMMIT;
