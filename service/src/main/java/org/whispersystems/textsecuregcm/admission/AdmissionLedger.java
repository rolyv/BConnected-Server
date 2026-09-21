// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.sql.SQLException;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.VerifiedPermit;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountMutation;

/**
 * Account-transaction participant only. No standalone redemption or activation API exists. This is
 * not wired into registration. A mandatory PENDING/ACTIVE entitlement gate across all account
 * capabilities must exist before callers use this mutation; the ledger alone does not block
 * authentication.
 */
public final class AdmissionLedger {
  private final DataSource dataSource;
  private final Clock clock;

  public AdmissionLedger(DataSource dataSource, Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
  }

  public static final class AdmissionConflictException extends RuntimeException {
    private AdmissionConflictException() {
      super("Admission binding is already used or invalid");
    }
  }

  public record AdmissionRecord(
      String permitId,
      UUID memberId,
      UUID aci,
      UUID signalOperationId,
      long approvalEpoch,
      String registrationAttemptHash,
      String serverVerificationSessionHash,
      String deviceKeyCommitment,
      String phoneBinding,
      String serverRequestCommitment,
      String status,
      long issuedAt,
      long expiresAt,
      int confirmationAttempts,
      boolean confirmed) {}

  public AccountMutation.Sql pendingMutation(VerifiedPermit permit, Account account) {
    Objects.requireNonNull(permit);
    Objects.requireNonNull(account);
    final UUID aci = Objects.requireNonNull(account.getAccountIdentifier());
    final var binding = permit.binding();
    if (!account.getNumber().filter(binding.canonicalVerifiedNumber()::equals).isPresent()) {
      throw new AdmissionConflictException();
    }
    return new AccountMutation.Sql(
        connection -> {
          // The normal AccountMutation guard also checks this. Keep it here because Sql.operation
          // is public.
          if (connection.getAutoCommit())
            throw new IllegalStateException("Admission requires the account transaction");
          try (var statement =
              connection.prepareStatement(
                  "SELECT number FROM signal.accounts WHERE aci=? FOR KEY SHARE")) {
            statement.setObject(1, aci);
            try (var rows = statement.executeQuery()) {
              if (!rows.next() || !binding.canonicalVerifiedNumber().equals(rows.getString(1)))
                throw new AdmissionConflictException();
            }
          }
          // Check after acquiring the account lock, not before a potentially long transaction wait.
          requireCurrent(permit);
          try (var statement =
              connection.prepareStatement(
                  """
                  INSERT INTO signal.admissions(permit_id,member_id,aci,signal_operation_id,registration_attempt_hash,
                    server_verification_session_hash,device_key_commitment,phone_binding,server_request_commitment,
                    approval_epoch,issued_at_seconds,expires_at_seconds,status)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'PENDING') ON CONFLICT DO NOTHING
                  """)) {
            statement.setBytes(1, AdmissionPermitVerifier.decode(permit.permitId(), 32));
            statement.setObject(2, binding.memberId());
            statement.setObject(3, aci);
            statement.setObject(4, binding.signalOperationId());
            statement.setBytes(5, hex(binding.registrationAttemptHash()));
            statement.setBytes(6, hex(binding.serverVerificationSessionHash()));
            statement.setBytes(7, hex(binding.deviceKeyCommitment()));
            statement.setBytes(8, hex(binding.phoneBinding()));
            statement.setBytes(9, hex(binding.serverRequestCommitment()));
            statement.setLong(10, binding.approvalEpoch());
            statement.setLong(11, permit.issuedAt());
            statement.setLong(12, permit.expiresAt());
            if (statement.executeUpdate() != 1) throw new AdmissionConflictException();
          }
          // A conflicting uncommitted insertion can wait and then roll back after our deadline.
          requireCurrent(permit);
          try (var statement =
              connection.prepareStatement(
                  "INSERT INTO signal.admission_confirmation_outbox(permit_id) VALUES(?)")) {
            statement.setBytes(1, AdmissionPermitVerifier.decode(permit.permitId(), 32));
            statement.executeUpdate();
          }
          requireCurrent(permit);
        });
  }

  /**
   * A status lookup is not authorization. Future gates must additionally establish current
   * entitlement.
   */
  public Optional<AdmissionRecord> findByOperation(UUID operation) throws SQLException {
    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(
                """
                SELECT a.*,o.attempt_count,o.confirmed_at FROM signal.admissions a
                JOIN signal.admission_confirmation_outbox o USING(permit_id) WHERE a.signal_operation_id=?
                """)) {
      statement.setObject(1, Objects.requireNonNull(operation));
      try (var rows = statement.executeQuery()) {
        if (!rows.next()) return Optional.empty();
        return Optional.of(
            new AdmissionRecord(
                Base64.getUrlEncoder().withoutPadding().encodeToString(rows.getBytes("permit_id")),
                rows.getObject("member_id", UUID.class),
                rows.getObject("aci", UUID.class),
                rows.getObject("signal_operation_id", UUID.class),
                rows.getLong("approval_epoch"),
                HexFormat.of().formatHex(rows.getBytes("registration_attempt_hash")),
                HexFormat.of().formatHex(rows.getBytes("server_verification_session_hash")),
                HexFormat.of().formatHex(rows.getBytes("device_key_commitment")),
                HexFormat.of().formatHex(rows.getBytes("phone_binding")),
                HexFormat.of().formatHex(rows.getBytes("server_request_commitment")),
                rows.getString("status"),
                rows.getLong("issued_at_seconds"),
                rows.getLong("expires_at_seconds"),
                rows.getInt("attempt_count"),
                rows.getObject("confirmed_at") != null));
      }
    }
  }

  private void requireCurrent(VerifiedPermit permit) {
    long now = clock.instant().getEpochSecond();
    if (permit.expiresAt() <= now || permit.issuedAt() > now + 5)
      throw new AdmissionConflictException();
  }

  private static byte[] hex(String value) {
    return HexFormat.of().parseHex(value);
  }
}
