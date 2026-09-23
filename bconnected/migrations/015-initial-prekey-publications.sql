-- Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
-- Immutable initial-publication outcomes; no key material, credential, or activation authority.
CREATE TABLE IF NOT EXISTS signal.initial_prekey_publications (
  aci uuid NOT NULL,
  device_id smallint NOT NULL CHECK (device_id = 1),
  operation_id uuid NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('aci', 'pni')),
  service_identifier uuid NOT NULL,
  member_id uuid NOT NULL,
  approval_epoch bigint NOT NULL CHECK (approval_epoch BETWEEN 0 AND 9007199254740991),
  signal_operation_id uuid NOT NULL,
  permit_id bytea NOT NULL CHECK (octet_length(permit_id) = 32),
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
  response_status smallint NOT NULL DEFAULT 204 CHECK (response_status = 204),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (aci, device_id, operation_id),
  UNIQUE (aci, device_id, member_id, approval_epoch, signal_operation_id, permit_id, identity_type)
);
-- No cascading account FK: account deletion must not turn an old operation into a new publication.
COMMENT ON TABLE signal.initial_prekey_publications IS
  'Applied once with native EC/PQ pool replacement; replay never repopulates consumed keys; retain operation tombstones';
