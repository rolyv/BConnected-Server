-- The original native OTP verification instant must survive a lost response.
-- Existing verified sessions deliberately remain NULL and cannot authorize recovery.
ALTER TABLE signal.registration_sessions ADD COLUMN IF NOT EXISTS verified_at_ms bigint
  CHECK (verified_at_ms IS NULL OR verified_at_ms >= 0);
