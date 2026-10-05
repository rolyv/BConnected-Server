-- Operator-authorized recovery is separate from immutable first-enrollment history.
ALTER TABLE signal.admissions DROP CONSTRAINT IF EXISTS admissions_status_check;
ALTER TABLE signal.admissions ADD CONSTRAINT admissions_status_check
  CHECK(status IN ('PENDING','ACTIVE','SUSPENDED','RECOVERING'));
CREATE TABLE IF NOT EXISTS signal.account_recoveries (
  recovery_id uuid PRIMARY KEY,
  attempt_hash text NOT NULL UNIQUE CHECK(attempt_hash ~ '^[0-9a-f]{64}$'),
  number text NOT NULL CHECK(number ~ '^\+[1-9][0-9]{1,14}$'),
  auth_hash text NOT NULL, auth_salt text NOT NULL,
  request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
  device_key_hash text NOT NULL CHECK(device_key_hash ~ '^[0-9a-f]{64}$'),
  registration_request jsonb NOT NULL,
  signal_agent text NOT NULL, user_agent text NOT NULL,
  session_id bytea NOT NULL UNIQUE CHECK(octet_length(session_id)=32),
  created_ms bigint NOT NULL, expires_ms bigint NOT NULL,
  verified_ms bigint, proof_expires_ms bigint,
  recovery_binding jsonb,
  aci uuid, pni uuid, expected_account_version integer,
  state text NOT NULL DEFAULT 'VERIFICATION'
    CHECK(state IN ('VERIFICATION','REQUESTED','RECOVERING','ACTIVE')),
  replacement_generation bigint, completed_ms bigint,
  completion_requested boolean NOT NULL DEFAULT false,
  CHECK((verified_ms IS NULL)=(proof_expires_ms IS NULL)),
  CHECK(proof_expires_ms IS NULL OR proof_expires_ms=verified_ms+300000),
  CHECK((recovery_binding IS NULL)=(aci IS NULL)),
  CHECK((aci IS NULL)=(pni IS NULL)),
  CHECK((aci IS NULL)=(expected_account_version IS NULL)),
  CHECK(state NOT IN ('RECOVERING','ACTIVE') OR replacement_generation IS NOT NULL),
  CHECK((state='ACTIVE')=(completed_ms IS NOT NULL))
);
ALTER TABLE signal.account_recoveries ADD COLUMN IF NOT EXISTS completion_requested boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS one_account_recovery_in_flight
  ON signal.account_recoveries(aci) WHERE state='RECOVERING';
COMMENT ON TABLE signal.account_recoveries IS
  'Exact recovery transcripts and durable cleanup fences; no OTP or plaintext password; retain completed receipts';

-- Retain first-publication tombstones while allowing the new device generation its own slot.
ALTER TABLE signal.initial_prekey_publications ADD COLUMN IF NOT EXISTS device_generation bigint NOT NULL DEFAULT -1;
UPDATE signal.initial_prekey_publications p SET device_generation=(d->>'created')::bigint
  FROM signal.accounts a, LATERAL jsonb_array_elements(a.data->'devices') d
  WHERE p.aci=a.aci AND p.device_generation=-1 AND d->>'id'='1'
    AND d->>'created' ~ '^[0-9]+$';
DO $$ DECLARE constraint_name text; BEGIN
  FOR constraint_name IN SELECT conname FROM pg_constraint
    WHERE conrelid='signal.initial_prekey_publications'::regclass AND contype='u'
      AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='aci'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='device_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='member_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='approval_epoch'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='signal_operation_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='permit_id'),
        (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='identity_type')]::smallint[]
  LOOP EXECUTE format('ALTER TABLE signal.initial_prekey_publications DROP CONSTRAINT %I',constraint_name); END LOOP;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS initial_publication_generation_slot ON signal.initial_prekey_publications
  (aci,device_id,member_id,approval_epoch,signal_operation_id,permit_id,identity_type,device_generation);
