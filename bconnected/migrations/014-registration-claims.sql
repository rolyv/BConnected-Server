-- Additive source integration state; this opens no public registration route.
ALTER TABLE signal.registration_operations ADD COLUMN IF NOT EXISTS claim_approval_epoch bigint;
ALTER TABLE signal.registration_operations ADD COLUMN IF NOT EXISTS claim_expires_ms bigint;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='registration_operation_claim_binding'
    AND conrelid='signal.registration_operations'::regclass) THEN
    ALTER TABLE signal.registration_operations ADD CONSTRAINT registration_operation_claim_binding CHECK (
      (claim_approval_epoch IS NULL AND claim_expires_ms IS NULL) OR
      (claim_approval_epoch IS NOT NULL AND claim_approval_epoch BETWEEN 0 AND 9007199254740991
        AND claim_expires_ms IS NOT NULL AND claim_expires_ms>created_ms AND claim_expires_ms<=expires_ms));
  END IF;
END $$;
