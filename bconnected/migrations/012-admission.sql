-- Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
-- Source-only: this schema grants no activation authority and does not enable registration routes.
CREATE TABLE IF NOT EXISTS signal.admissions (
  permit_id bytea PRIMARY KEY CHECK (octet_length(permit_id) = 32),
  member_id uuid NOT NULL UNIQUE,
  aci uuid NOT NULL UNIQUE,
  signal_operation_id uuid NOT NULL UNIQUE,
  registration_attempt_hash bytea NOT NULL CHECK (octet_length(registration_attempt_hash) = 32),
  server_verification_session_hash bytea NOT NULL UNIQUE CHECK (octet_length(server_verification_session_hash) = 32),
  device_key_commitment bytea NOT NULL CHECK (octet_length(device_key_commitment) = 32),
  phone_binding bytea NOT NULL CHECK (octet_length(phone_binding) = 32),
  server_request_commitment bytea NOT NULL CHECK (octet_length(server_request_commitment) = 32),
  approval_epoch bigint NOT NULL CHECK (approval_epoch BETWEEN 0 AND 9007199254740991),
  issued_at_seconds bigint NOT NULL CHECK (issued_at_seconds >= 0),
  expires_at_seconds bigint NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  suspended_at timestamptz,
  CHECK (expires_at_seconds > issued_at_seconds AND expires_at_seconds - issued_at_seconds <= 30)
);
-- Deliberately no cascading account FK: deleting an account must not erase a spent permit and enable replay.
CREATE TABLE IF NOT EXISTS signal.admission_confirmation_outbox (
  permit_id bytea PRIMARY KEY REFERENCES signal.admissions(permit_id),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_id uuid,
  lease_expires_at timestamptz,
  confirmed_at timestamptz,
  CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL))
);
CREATE INDEX IF NOT EXISTS admission_confirmation_due ON signal.admission_confirmation_outbox(next_attempt_at)
  WHERE confirmed_at IS NULL;
COMMENT ON TABLE signal.admissions IS 'Application admission redemptions; PENDING by default; never stores raw passwords or OTPs';
COMMENT ON TABLE signal.admission_confirmation_outbox IS 'Atomic pending-account confirmation work; no autonomous activation';
