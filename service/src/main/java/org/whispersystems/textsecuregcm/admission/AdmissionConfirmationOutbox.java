// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.Binding;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.FreshEntitlement;

/**
 * Bounded durable confirmation work. Explicit DM alpha composition owns its runtime scheduler. Before enabling
 * this worker, every account capability must require ACTIVE state AND fresh current entitlement;
 * the ACTIVE flag by itself is never authorization. No provider or HTTP call holds a SQL lock.
 */
public final class AdmissionConfirmationOutbox {
  public enum Outcome {
    IDLE,
    ACTIVATED,
    RETRY,
    STALE
  }

  public static final class OutboxUnavailableException extends RuntimeException {
    private OutboxUnavailableException() {
      super("Admission confirmation storage unavailable");
    }
  }

  static final class Lease {
    private final UUID id;
    private final Binding binding;
    private final int attempt;

    private Lease(UUID id, Binding binding, int attempt) {
      this.id = id;
      this.binding = binding;
      this.attempt = attempt;
    }

    Binding binding() {
      return binding;
    }

    @Override
    public String toString() {
      return "AdmissionConfirmationLease[redacted]";
    }
  }

  private final DataSource dataSource;
  private final AdmissionServiceClient client;
  private final Set<UUID> memberIds;

  public AdmissionConfirmationOutbox(DataSource dataSource, AdmissionServiceClient client) {
    this(dataSource, client, null);
  }

  /** Restrict confirmation work to an immutable member cohort. */
  public AdmissionConfirmationOutbox(DataSource dataSource, AdmissionServiceClient client,
      Set<UUID> memberIds) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.client = Objects.requireNonNull(client);
    if (memberIds != null && memberIds.isEmpty()) {
      throw new IllegalArgumentException("A confirmation cohort must not be empty");
    }
    this.memberIds = memberIds == null ? null : Set.copyOf(memberIds);
  }

  /** One row, one authenticated request, bounded retry scheduling; caller owns worker lifecycle. */
  public Outcome runOne() {
    Optional<Lease> claimed = claim();
    if (claimed.isEmpty()) return Outcome.IDLE;
    Lease lease = claimed.get();
    try {
      return complete(lease, client.confirm(lease.binding)) ? Outcome.ACTIVATED : Outcome.STALE;
    } catch (AdmissionServiceClient.AdmissionServiceException failure) {
      // Unknown/denied/late results never set ACTIVE. An issuer-side committed confirmation can
      // be recovered by the exact tuple on a later attempt, without minting another permit.
      return retry(lease) ? Outcome.RETRY : Outcome.STALE;
    }
  }

  Optional<Lease> claim() {
    return transaction(
        connection -> {
          java.sql.Array cohort = null;
          try (var statement =
                  connection.prepareStatement(
                      """
                      SELECT a.member_id,a.approval_epoch,a.signal_operation_id,a.permit_id,a.aci,o.attempt_count
                      FROM signal.admission_confirmation_outbox o JOIN signal.admissions a USING(permit_id)
                      WHERE o.confirmed_at IS NULL AND a.status='PENDING'
                        AND o.next_attempt_at<=clock_timestamp()
                        AND (o.lease_id IS NULL OR o.lease_expires_at<=clock_timestamp())
                        AND EXISTS(SELECT 1 FROM signal.accounts accounts WHERE accounts.aci=a.aci)
                        %s
                      ORDER BY o.next_attempt_at,o.permit_id LIMIT 1 FOR UPDATE OF o SKIP LOCKED
                      """.formatted(memberIds == null ? "" : "AND a.member_id=ANY (?)"))) {
            if (memberIds != null) {
              cohort = connection.createArrayOf("uuid", memberIds.toArray(UUID[]::new));
            }
            if (cohort != null) statement.setArray(1, cohort);
            try (var rows = statement.executeQuery()) {
              if (!rows.next()) return Optional.empty();
              Binding binding = binding(rows);
              int attempt =
                  (int) Math.min(Integer.MAX_VALUE, (long) rows.getInt("attempt_count") + 1);
              UUID leaseId = UUID.randomUUID();
              try (var update =
                  connection.prepareStatement(
                      """
                      UPDATE signal.admission_confirmation_outbox SET lease_id=?,
                        lease_expires_at=clock_timestamp()+interval '30 seconds',attempt_count=? WHERE permit_id=?
                      """)) {
                update.setObject(1, leaseId);
                update.setInt(2, attempt);
                update.setBytes(3, permit(binding));
                if (update.executeUpdate() != 1) throw new SQLException("Missing outbox row");
              }
              return Optional.of(new Lease(leaseId, binding, attempt));
            }
          } finally {
            if (cohort != null) cohort.free();
          }
        });
  }

  boolean complete(Lease lease, FreshEntitlement receipt) {
    Objects.requireNonNull(lease);
    Objects.requireNonNull(receipt);
    receipt.requireFreshConfirmation();
    if (!lease.binding.equals(receipt.binding())) return false;
    return transaction(
        connection -> {
          // Lock in account -> admission -> outbox order, consistent with account/redemption
          // writes.
          // A deleted account never becomes activated merely because its durable spent permit
          // remains.
          try (var account =
              connection.prepareStatement(
                  "SELECT aci FROM signal.accounts WHERE aci=? FOR KEY SHARE")) {
            account.setObject(1, lease.binding.aci());
            try (var rows = account.executeQuery()) {
              if (!rows.next()) return false;
            }
          }
          try (var admission =
              connection.prepareStatement(
                  "SELECT * FROM signal.admissions WHERE permit_id=? FOR UPDATE")) {
            admission.setBytes(1, permit(lease.binding));
            try (var rows = admission.executeQuery()) {
              if (!rows.next()
                  || !"PENDING".equals(rows.getString("status"))
                  || !binding(rows).equals(lease.binding)) return false;
            }
          }
          try (var outbox =
              connection.prepareStatement(
                  """
                  SELECT lease_id,confirmed_at
                  FROM signal.admission_confirmation_outbox WHERE permit_id=? FOR UPDATE
                  """)) {
            outbox.setBytes(1, permit(lease.binding));
            try (var rows = outbox.executeQuery()) {
              if (!rows.next()
                  || !lease.id.equals(rows.getObject("lease_id", UUID.class))
                  || rows.getObject("confirmed_at") != null) return false;
            }
          }
          // Sample the database deadline only after the row lock is held, not in its blocking
          // SELECT.
          try (var current =
              connection.prepareStatement(
                  "SELECT lease_expires_at>clock_timestamp() FROM"
                      + " signal.admission_confirmation_outbox WHERE permit_id=?")) {
            current.setBytes(1, permit(lease.binding));
            try (var rows = current.executeQuery()) {
              if (!rows.next() || !rows.getBoolean(1)) return false;
            }
          }
          // SQL lock waits must consume, never reset, the receipt's request-start freshness budget.
          receipt.requireFreshConfirmation();
          try (var update =
              connection.prepareStatement(
                  """
                  UPDATE signal.admissions SET status='ACTIVE',activated_at=clock_timestamp() WHERE permit_id=?
                  """)) {
            update.setBytes(1, permit(lease.binding));
            if (update.executeUpdate() != 1) throw new SQLException("Missing admission row");
          }
          try (var update =
              connection.prepareStatement(
                  """
                  UPDATE signal.admission_confirmation_outbox SET confirmed_at=clock_timestamp(),
                    lease_id=NULL,lease_expires_at=NULL WHERE permit_id=? AND lease_id=? AND lease_expires_at>clock_timestamp()
                  """)) {
            update.setBytes(1, permit(lease.binding));
            update.setObject(2, lease.id);
            if (update.executeUpdate() != 1) throw new SQLException("Changed outbox lease");
          }
          receipt.requireFreshConfirmation();
          return true;
        });
  }

  boolean retry(Lease lease) {
    return transaction(
        connection -> {
          int seconds = Math.min(60, 1 << Math.min(6, Math.max(0, lease.attempt - 1)));
          try (var statement =
              connection.prepareStatement(
                  """
                  UPDATE signal.admission_confirmation_outbox SET lease_id=NULL,lease_expires_at=NULL,
                    next_attempt_at=clock_timestamp()+(? * interval '1 second')
                  WHERE permit_id=? AND lease_id=? AND confirmed_at IS NULL AND lease_expires_at>clock_timestamp()
                  """)) {
            statement.setInt(1, seconds);
            statement.setBytes(2, permit(lease.binding));
            statement.setObject(3, lease.id);
            return statement.executeUpdate() == 1;
          }
        });
  }

  private static Binding binding(ResultSet rows) throws SQLException {
    return new Binding(
        rows.getObject("member_id", UUID.class),
        rows.getLong("approval_epoch"),
        rows.getObject("signal_operation_id", UUID.class),
        Base64.getUrlEncoder().withoutPadding().encodeToString(rows.getBytes("permit_id")),
        rows.getObject("aci", UUID.class));
  }

  private static byte[] permit(Binding binding) {
    return AdmissionPermitVerifier.decode(binding.permitId(), 32);
  }

  @FunctionalInterface
  private interface Work<T> {
    T apply(Connection connection) throws SQLException;
  }

  private <T> T transaction(Work<T> work) {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      try {
        try (var statement = connection.createStatement()) {
          statement.execute("SET LOCAL statement_timeout='5s'");
          statement.execute("SET LOCAL lock_timeout='3s'");
        }
        T result = work.apply(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException error) {
        try {
          connection.rollback();
        } catch (SQLException ignored) {
        }
        throw error;
      }
    } catch (SQLException ignored) {
      throw new OutboxUnavailableException();
    }
  }
}
