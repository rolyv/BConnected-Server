-- Source-only prerequisite; this enables no controller, SMS, recovery or account activation path.
CREATE TABLE IF NOT EXISTS signal.registration_operations (
  operation_id uuid PRIMARY KEY,
  member_id uuid NOT NULL,
  registration_attempt_hash bytea NOT NULL CHECK(octet_length(registration_attempt_hash)=32),
  challenge_hash bytea NOT NULL CHECK(octet_length(challenge_hash)=32),
  device_key_commitment bytea NOT NULL CHECK(octet_length(device_key_commitment)=32),
  server_request_commitment bytea NOT NULL CHECK(octet_length(server_request_commitment)=32),
  requested_number text NOT NULL CHECK(requested_number ~ '^\+[1-9][0-9]{1,14}$'),
  authentication_hash text NOT NULL CHECK(authentication_hash ~ '^2\.[a-f0-9]{64}$'),
  authentication_salt text NOT NULL CHECK(authentication_salt ~ '^[a-f0-9]{32}$'),
  created_ms bigint NOT NULL,
  expires_ms bigint NOT NULL CHECK(expires_ms>created_ms AND expires_ms-created_ms<=300000),
  verification_session_id bytea UNIQUE CHECK(octet_length(verification_session_id)=32),
  verification_session_hash bytea UNIQUE CHECK(octet_length(verification_session_hash)=32),
  verification_session_expires_ms bigint,
  UNIQUE(member_id,registration_attempt_hash),
  CHECK((verification_session_id IS NULL AND verification_session_hash IS NULL AND verification_session_expires_ms IS NULL) OR
    (verification_session_id IS NOT NULL AND verification_session_hash IS NOT NULL AND verification_session_expires_ms IS NOT NULL))
);
COMMENT ON TABLE signal.registration_operations IS 'Server-owned immutable admission requests and salted auth verifiers; no raw passwords, registration recovery secrets, OTPs or canonical request payload';
