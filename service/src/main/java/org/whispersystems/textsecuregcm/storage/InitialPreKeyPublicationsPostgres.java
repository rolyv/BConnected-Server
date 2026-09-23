// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.identity.IdentityType;

/** Immutable ledger coordinated under the existing EC/KEM transaction and advisory locks. */
final class InitialPreKeyPublicationsPostgres {
  enum Decision { APPLY, REPLAY, CONFLICT }
  private InitialPreKeyPublicationsPostgres() {}

  static Decision reserve(Connection connection, AdmissionServiceClient.Binding binding, UUID operation,
      IdentityType identity, UUID identifier, byte[] digest) throws SQLException {
    byte[] permit = Base64.getUrlDecoder().decode(binding.permitId());
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.initial_prekey_publications
        (aci,device_id,operation_id,identity_type,service_identifier,member_id,approval_epoch,signal_operation_id,permit_id,payload_digest)
        VALUES (?,1,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
        """)) {
      statement.setObject(1, binding.aci()); statement.setObject(2, operation);
      statement.setString(3, identity.name().toLowerCase(java.util.Locale.ROOT)); statement.setObject(4, identifier);
      statement.setObject(5, binding.memberId()); statement.setLong(6, binding.approvalEpoch());
      statement.setObject(7, binding.signalOperationId()); statement.setBytes(8, permit); statement.setBytes(9, digest);
      if (statement.executeUpdate() == 1) return Decision.APPLY;
    }
    // A conflicting initial slot under another operation also returns CONFLICT. No pool write is allowed.
    try (var statement = connection.prepareStatement("""
        SELECT * FROM signal.initial_prekey_publications WHERE aci=? AND device_id=1 AND operation_id=?
        """)) {
      statement.setObject(1, binding.aci()); statement.setObject(2, operation);
      try (var row = statement.executeQuery()) {
        return row.next() && row.getString("identity_type").equals(identity.name().toLowerCase(java.util.Locale.ROOT))
            && identifier.equals(row.getObject("service_identifier", UUID.class))
            && binding.memberId().equals(row.getObject("member_id", UUID.class))
            && binding.approvalEpoch() == row.getLong("approval_epoch")
            && binding.signalOperationId().equals(row.getObject("signal_operation_id", UUID.class))
            && Arrays.equals(permit, row.getBytes("permit_id"))
            && Arrays.equals(digest, row.getBytes("payload_digest")) && row.getInt("response_status") == 204
            ? Decision.REPLAY : Decision.CONFLICT;
      }
    }
  }
}
