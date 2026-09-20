// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;

/** Salted recovery hashes; account changes and recovery-password mutations share one SQL transaction. */
public final class PhoneNumberRecoveryPasswordsPostgres implements PhoneNumberRecoveryPasswordStore {
  private final DataSource dataSource;
  private final Duration expiration;
  private final Clock clock;

  public PhoneNumberRecoveryPasswordsPostgres(final DataSource dataSource, final Duration expiration, final Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.expiration = Objects.requireNonNull(expiration);
    this.clock = Objects.requireNonNull(clock);
  }

  @Override
  public Optional<SaltedTokenHash> lookup(final UUID phoneNumberIdentifier) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        SELECT salt, hash FROM signal.phone_recovery_passwords WHERE pni = ?
        """)) {
      statement.setObject(1, phoneNumberIdentifier);
      try (var result = statement.executeQuery()) {
        return result.next() ? Optional.of(new SaltedTokenHash(result.getString("hash"), result.getString("salt")))
            : Optional.empty();
      }
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL recovery-password lookup failed", e);
    }
  }

  @Override
  public boolean addOrReplace(final UUID phoneNumberIdentifier, final SaltedTokenHash data) {
    return transaction(connection -> {
      lock(connection, phoneNumberIdentifier);
      final boolean existed;
      try (var statement = connection.prepareStatement("SELECT 1 FROM signal.phone_recovery_passwords WHERE pni = ? FOR UPDATE")) {
        statement.setObject(1, phoneNumberIdentifier);
        try (var result = statement.executeQuery()) { existed = result.next(); }
      }
      buildMutationForAddOrReplace(phoneNumberIdentifier, data).applySql(connection);
      return !existed;
    });
  }

  @Override
  public boolean removeEntry(final UUID phoneNumberIdentifier) {
    return transaction(connection -> {
      lock(connection, phoneNumberIdentifier);
      try (var statement = connection.prepareStatement("DELETE FROM signal.phone_recovery_passwords WHERE pni = ?")) {
        statement.setObject(1, phoneNumberIdentifier);
        return statement.executeUpdate() > 0;
      }
    });
  }

  @Override
  public AccountMutation buildMutationForAddOrReplace(final UUID phoneNumberIdentifier, final SaltedTokenHash data) {
    Objects.requireNonNull(phoneNumberIdentifier);
    Objects.requireNonNull(data);
    final long expiresAt = clock.instant().plus(expiration).getEpochSecond();
    return new AccountMutation.Sql(connection -> {
      lock(connection, phoneNumberIdentifier);
      try (var statement = connection.prepareStatement("""
          INSERT INTO signal.phone_recovery_passwords (pni, salt, hash, expires_at) VALUES (?, ?, ?, ?)
          ON CONFLICT (pni) DO UPDATE SET salt = EXCLUDED.salt, hash = EXCLUDED.hash, expires_at = EXCLUDED.expires_at
          """)) {
        statement.setObject(1, phoneNumberIdentifier);
        statement.setString(2, data.salt());
        statement.setString(3, data.hash());
        statement.setLong(4, expiresAt);
        statement.executeUpdate();
      }
    });
  }

  @Override
  public AccountMutation buildMutationForRemove(final UUID phoneNumberIdentifier) {
    Objects.requireNonNull(phoneNumberIdentifier);
    return new AccountMutation.Sql(connection -> {
      lock(connection, phoneNumberIdentifier);
      try (var statement = connection.prepareStatement("DELETE FROM signal.phone_recovery_passwords WHERE pni = ?")) {
        statement.setObject(1, phoneNumberIdentifier);
        statement.executeUpdate();
      }
    });
  }

  @Override
  public AccountMutation buildConditionMutationForMigration(final UUID phoneNumberIdentifier,
      final SaltedTokenHash expectedPassword) {
    Objects.requireNonNull(phoneNumberIdentifier);
    Objects.requireNonNull(expectedPassword);
    return new AccountMutation.Sql(connection -> {
      lock(connection, phoneNumberIdentifier);
      try (var statement = connection.prepareStatement("""
          SELECT 1 FROM signal.phone_recovery_passwords
          WHERE pni = ? AND salt = ? AND hash = ? FOR UPDATE
          """)) {
        statement.setObject(1, phoneNumberIdentifier);
        statement.setString(2, expectedPassword.salt());
        statement.setString(3, expectedPassword.hash());
        try (var result = statement.executeQuery()) {
          if (!result.next()) throw new ContestedOptimisticLockException();
        }
      }
    });
  }

  /** Match upstream eventual TTL deletion: extant rows remain usable until this maintenance pass removes them. */
  public int deleteExpired(final int batchSize) {
    if (batchSize < 1 || batchSize > 10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        WITH expired AS (
          SELECT pni FROM signal.phone_recovery_passwords WHERE expires_at < ?
          ORDER BY expires_at, pni LIMIT ? FOR UPDATE SKIP LOCKED
        )
        DELETE FROM signal.phone_recovery_passwords password USING expired WHERE password.pni = expired.pni
        """)) {
      statement.setLong(1, clock.instant().getEpochSecond());
      statement.setInt(2, batchSize);
      return statement.executeUpdate();
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL recovery-password expiry failed", e);
    }
  }

  private static void lock(final Connection connection, final UUID pni) throws SQLException {
    // Recovery mutations, including ones invoked within an account transaction, take the same per-PNI lock. Keeping the
    // lock statement separate makes a following READ COMMITTED statement see the previous writer's commit.
    try (var statement = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
      statement.setLong(1, pni.getMostSignificantBits() ^ Long.rotateLeft(pni.getLeastSignificantBits(), 17)
          ^ 0x42435245434F5652L);
      statement.execute();
    }
  }

  private <T> T transaction(final SqlOperation<T> operation) {
    try (var connection = dataSource.getConnection()) {
      connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      connection.setAutoCommit(false);
      try {
        final T result = operation.apply(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        try { connection.rollback(); }
        catch (SQLException rollbackFailure) { e.addSuppressed(rollbackFailure); }
        throw e;
      }
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL recovery-password transaction failed", e);
    }
  }

  @FunctionalInterface
  private interface SqlOperation<T> {
    T apply(Connection connection) throws SQLException;
  }
}
