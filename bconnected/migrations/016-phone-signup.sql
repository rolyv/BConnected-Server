-- Native phone verification is a durable application proof, never an account or membership.
CREATE TABLE IF NOT EXISTS signal.phone_signup_operations (
  operation_id uuid PRIMARY KEY,
  nonce_hash text NOT NULL CHECK (nonce_hash ~ '^[a-f0-9]{64}$'),
  phone_lookup_hash text NOT NULL CHECK (phone_lookup_hash ~ '^[a-f0-9]{64}$'),
  requested_number text NOT NULL CHECK (requested_number ~ '^\+[1-9][0-9]{1,14}$'),
  native_session_id bytea NOT NULL UNIQUE CHECK (octet_length(native_session_id) = 32),
  native_session_expires_ms bigint NOT NULL,
  created_ms bigint NOT NULL,
  application_expires_ms bigint NOT NULL
    CHECK (application_expires_ms > created_ms AND application_expires_ms - created_ms <= 1800000),
  verified_at_ms bigint,
  proof_expires_ms bigint,
  community_confirmed boolean NOT NULL DEFAULT false,
  consumed_registration_operation_id uuid UNIQUE,
  consumed_member_id uuid,
  CHECK (native_session_expires_ms > created_ms),
  CHECK ((verified_at_ms IS NULL) = (proof_expires_ms IS NULL)),
  CHECK (proof_expires_ms IS NULL OR
    (proof_expires_ms > verified_at_ms AND proof_expires_ms - verified_at_ms <= 2592000000)),
  CHECK (NOT community_confirmed OR verified_at_ms IS NOT NULL),
  CHECK ((consumed_registration_operation_id IS NULL) = (consumed_member_id IS NULL)),
  CHECK (consumed_registration_operation_id IS NULL OR community_confirmed)
);
ALTER TABLE signal.registration_operations
  ADD COLUMN IF NOT EXISTS phone_signup_proof_id uuid UNIQUE;
COMMENT ON TABLE signal.phone_signup_operations IS
  'Durable native phone signup proof; no OTP, plaintext nonce, account or membership is stored';
