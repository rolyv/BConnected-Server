-- A retirement is permanent. Runtime may not delete this absence-lock/tombstone or its receipt.
ALTER TABLE signal.registration_sessions ADD COLUMN IF NOT EXISTS retired_ms bigint;
ALTER TABLE signal.phone_signup_operations ADD COLUMN IF NOT EXISTS retired_ms bigint;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='signal.registration_sessions'::regclass
      AND conname='retired_registration_has_no_authority') THEN
    ALTER TABLE signal.registration_sessions ADD CONSTRAINT retired_registration_has_no_authority
      CHECK (retired_ms IS NULL OR (NOT verified AND operation_id IS NULL AND operation_expires_ms IS NULL));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='signal.phone_signup_operations'::regclass
      AND conname='retired_signup_has_no_authority') THEN
    ALTER TABLE signal.phone_signup_operations ADD CONSTRAINT retired_signup_has_no_authority
      CHECK (retired_ms IS NULL OR (verified_at_ms IS NULL AND proof_expires_ms IS NULL
        AND NOT community_confirmed AND consumed_registration_operation_id IS NULL AND consumed_member_id IS NULL));
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS signal.phone_signup_supersessions (
  original_application_id uuid PRIMARY KEY,
  correction_id uuid NOT NULL UNIQUE,
  replacement_application_id uuid NOT NULL UNIQUE,
  nonce_hash text NOT NULL CHECK (nonce_hash ~ '^[a-f0-9]{64}$'),
  phone_lookup_hash text NOT NULL CHECK (phone_lookup_hash ~ '^[a-f0-9]{64}$'),
  requested_number text NOT NULL CHECK (requested_number ~ '^\+[1-9][0-9]{1,14}$'),
  replacement_nonce_hash text NOT NULL UNIQUE CHECK (replacement_nonce_hash ~ '^[a-f0-9]{64}$'),
  replacement_phone_lookup_hash text NOT NULL CHECK (replacement_phone_lookup_hash ~ '^[a-f0-9]{64}$'),
  replacement_number text NOT NULL CHECK (replacement_number ~ '^\+[1-9][0-9]{1,14}$'),
  retired_ms bigint NOT NULL CHECK (retired_ms >= 0),
  replacement_expires_ms bigint,
  CHECK (original_application_id <> correction_id AND original_application_id <> replacement_application_id
    AND correction_id <> replacement_application_id),
  CHECK (nonce_hash <> replacement_nonce_hash),
  CHECK (replacement_expires_ms IS NULL OR replacement_expires_ms > retired_ms)
);
COMMENT ON TABLE signal.phone_signup_supersessions IS
  'Permanent native retirement fence and exact private replacement outbox/receipt; no plaintext enrollment nonce or OTP';
