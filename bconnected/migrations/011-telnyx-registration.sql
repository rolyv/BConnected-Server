BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.registration_sessions (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
  number text NOT NULL CHECK (number ~ '^\+[1-9][0-9]{1,14}$'),
  expires_ms bigint NOT NULL,
  verified boolean NOT NULL DEFAULT false,
  provider_verification_id uuid,
  code_expires_ms bigint,
  sms_count integer NOT NULL DEFAULT 0 CHECK (sms_count >= 0),
  check_count integer NOT NULL DEFAULT 0 CHECK (check_count >= 0),
  next_sms_ms bigint NOT NULL DEFAULT 0,
  next_check_ms bigint NOT NULL DEFAULT 0,
  operation_id uuid,
  operation_expires_ms bigint,
  CHECK ((provider_verification_id IS NULL) = (code_expires_ms IS NULL)),
  CHECK ((operation_id IS NULL) = (operation_expires_ms IS NULL))
);
CREATE INDEX IF NOT EXISTS registration_sessions_expiry ON signal.registration_sessions(expires_ms);
CREATE TABLE IF NOT EXISTS signal.registration_quotas (
  scope text NOT NULL,
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  window_start_ms bigint NOT NULL,
  expires_ms bigint NOT NULL,
  attempts integer NOT NULL CHECK (attempts > 0),
  PRIMARY KEY (scope, key_hash, window_start_ms)
);
CREATE INDEX IF NOT EXISTS registration_quotas_expiry ON signal.registration_quotas(expires_ms);
COMMENT ON TABLE signal.registration_sessions IS 'Durable Telnyx phone verification state; stores neither OTP codes nor provider credentials';
COMMENT ON TABLE signal.registration_quotas IS 'HMAC-keyed fixed-window budgets retained across registration sessions; failed and ambiguous provider attempts consume budget';
COMMIT;
