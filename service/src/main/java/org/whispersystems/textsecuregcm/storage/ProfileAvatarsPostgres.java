// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import javax.sql.DataSource;

/** Avatar ownership and expiry metadata. Object bytes are stored separately. */
public final class ProfileAvatarsPostgres implements ProfileAvatarStore {
  private final DataSource dataSource;
  private final Duration expiration;
  private final Clock clock;

  public ProfileAvatarsPostgres(DataSource dataSource, Duration expiration, Clock clock) {
    if (expiration.isZero() || expiration.isNegative()) throw new IllegalArgumentException("Positive expiration required");
    this.dataSource = dataSource;
    this.expiration = expiration;
    this.clock = clock;
  }

  @Override public Optional<String> setAvatarUrl(byte[] identity, String url) {
    return transaction(identity, connection -> {
      Optional<String> previous;
      try (var statement = connection.prepareStatement("SELECT url FROM signal.profile_avatars WHERE identity=?")) {
        statement.setBytes(1, identity);
        try (var rows = statement.executeQuery()) { previous = rows.next() ? Optional.of(rows.getString(1)) : Optional.empty(); }
      }
      try (var statement = connection.prepareStatement("""
          INSERT INTO signal.profile_avatars (identity, url, expires_at) VALUES (?, ?, ?)
          ON CONFLICT (identity) DO UPDATE SET url=EXCLUDED.url, expires_at=EXCLUDED.expires_at
          """)) {
        statement.setBytes(1, identity);
        statement.setString(2, url);
        statement.setTimestamp(3, Timestamp.from(clock.instant().plus(expiration)));
        statement.executeUpdate();
      }
      return previous;
    });
  }

  @Override public Optional<String> updateAvatarTtl(byte[] identity) {
    return transaction(identity, connection -> {
      try (var statement = connection.prepareStatement(
          "UPDATE signal.profile_avatars SET expires_at=? WHERE identity=? RETURNING url")) {
        statement.setTimestamp(1, Timestamp.from(clock.instant().plus(expiration)));
        statement.setBytes(2, identity);
        try (var rows = statement.executeQuery()) { return rows.next() ? Optional.of(rows.getString(1)) : Optional.empty(); }
      }
    });
  }

  @Override public Optional<String> deleteAvatarUrl(byte[] identity) {
    return transaction(identity, connection -> {
      try (var statement = connection.prepareStatement("DELETE FROM signal.profile_avatars WHERE identity=? RETURNING url")) {
        statement.setBytes(1, identity);
        try (var rows = statement.executeQuery()) { return rows.next() ? Optional.of(rows.getString(1)) : Optional.empty(); }
      }
    });
  }

  public int deleteExpired(int limit) {
    if (limit < 1 || limit > 10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        WITH expired AS (SELECT identity FROM signal.profile_avatars WHERE expires_at <= ?
          ORDER BY expires_at LIMIT ? FOR UPDATE SKIP LOCKED)
        DELETE FROM signal.profile_avatars a USING expired e WHERE a.identity=e.identity
        """)) {
      statement.setTimestamp(1, Timestamp.from(clock.instant()));
      statement.setInt(2, limit);
      return statement.executeUpdate();
    } catch (SQLException e) { throw new IllegalStateException("Cannot expire avatar metadata", e); }
  }

  private <T> T transaction(byte[] identity, SqlWork<T> work) {
    final long lock;
    try { lock = ByteBuffer.wrap(MessageDigest.getInstance("SHA-256").digest(identity)).getLong() ^ 0x4243415641544152L; }
    catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    try (var connection = dataSource.getConnection()) {
      connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      connection.setAutoCommit(false);
      try {
        try (var statement = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
          statement.setLong(1, lock);
          statement.execute();
        }
        T result = work.execute(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        try { connection.rollback(); } catch (SQLException rollback) { e.addSuppressed(rollback); }
        throw e;
      }
    } catch (SQLException e) { throw new IllegalStateException("PostgreSQL avatar transaction failed", e); }
  }

  @FunctionalInterface private interface SqlWork<T> { T execute(Connection connection) throws SQLException; }
}
