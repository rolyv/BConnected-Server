// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.apache.commons.lang3.StringUtils;

/** Native profile storage; ciphertext and commitments are retained without cryptographic changes. */
public final class ProfilesPostgres implements ProfileDataStore {
  private final DataSource dataSource;
  private final Executor executor;

  public ProfilesPostgres(DataSource dataSource, Executor executor) {
    this.dataSource = dataSource;
    this.executor = executor;
  }

  public ProfileAvatarsPostgres avatarStore(Duration expiration, Clock clock) {
    return new ProfileAvatarsPostgres(dataSource, expiration, clock);
  }

  @Override public void setV1(UUID account, VersionedProfileV1 profile) {
    uncontestedTransaction(account, connection -> { writeV1(connection, account, profile); return null; });
  }

  static void writeV1(Connection connection, UUID account, VersionedProfileV1 p) throws SQLException {
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.profiles_v1
        (account_id, version, name, avatar, about_emoji, about, payment_address, phone_number_sharing, commitment)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (account_id, version) DO UPDATE SET name=EXCLUDED.name, avatar=EXCLUDED.avatar,
          about_emoji=EXCLUDED.about_emoji, about=EXCLUDED.about, payment_address=EXCLUDED.payment_address,
          phone_number_sharing=EXCLUDED.phone_number_sharing
        """)) {
      statement.setObject(1, account);
      statement.setString(2, p.version());
      statement.setBytes(3, p.name());
      statement.setString(4, StringUtils.isNotBlank(p.avatar()) ? p.avatar() : null);
      statement.setBytes(5, p.aboutEmoji());
      statement.setBytes(6, p.about());
      statement.setBytes(7, p.paymentAddress());
      statement.setBytes(8, p.phoneNumberSharing());
      statement.setBytes(9, p.commitment());
      statement.executeUpdate();
    }
  }

  @Override public void setBoth(UUID account, VersionedProfileV1 v1, VersionedProfile v2, byte[] expectedDataHash) throws WriteConflictException {
    transaction(account, connection -> { writeBoth(connection, account, v1, v2, expectedDataHash); return null; });
  }

  static void writeBoth(Connection connection, UUID account, VersionedProfileV1 v1, VersionedProfile v2,
      byte[] expectedDataHash) throws SQLException, WriteConflictException {
    if (expectedDataHash == null && v2.commitment() == null) throw new IllegalArgumentException("Commitment is required for initial write");
    final Optional<VersionedProfile> previous = getV2(connection, account, v2.version());
    if (previous.isPresent()) {
      final VersionedProfile old = previous.get();
      if (v2.commitment() != null && !Arrays.equals(old.commitment(), v2.commitment())) {
        throw new IllegalArgumentException("Commitment is immutable");
      }
      if (v2.commitment() == null && old.commitment().length != 97) throw new WriteConflictException();
      if (expectedDataHash == null || !Arrays.equals(old.dataHash(), expectedDataHash)) throw new WriteConflictException();
    } else if (expectedDataHash != null) {
      throw new WriteConflictException();
    }
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.profiles_v2
        (account_id, version, data, data_hash, payment_address, payment_address_hash, commitment)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (account_id, version) DO UPDATE SET data=EXCLUDED.data, data_hash=EXCLUDED.data_hash,
          payment_address=EXCLUDED.payment_address, payment_address_hash=EXCLUDED.payment_address_hash
        """)) {
      statement.setObject(1, account);
      statement.setBytes(2, v2.version());
      statement.setBytes(3, v2.data());
      statement.setBytes(4, v2.dataHash());
      statement.setBytes(5, v2.paymentAddress());
      statement.setBytes(6, v2.paymentAddress() == null ? null : v2.paymentAddressHash());
      statement.setBytes(7, v2.commitment() != null ? v2.commitment() : previous.orElseThrow().commitment());
      statement.executeUpdate();
    }
    // A failure in either write rolls back both generations.
    writeV1(connection, account, v1);
  }

  @Override public Optional<VersionedProfileV1> getV1(UUID account, String version) {
    try (var connection = dataSource.getConnection()) { return getV1(connection, account, version); }
    catch (SQLException e) { throw new IllegalStateException("Cannot read encrypted v1 profile", e); }
  }

  static Optional<VersionedProfileV1> getV1(Connection connection, UUID account, String version) throws SQLException {
    try (var statement = connection.prepareStatement("SELECT * FROM signal.profiles_v1 WHERE account_id=? AND version=?")) {
      statement.setObject(1, account); statement.setString(2, version);
      try (var rows = statement.executeQuery()) { return rows.next() ? Optional.of(v1FromRow(rows)) : Optional.empty(); }
    }
  }

  @Override public Optional<VersionedProfile> getV2(UUID account, byte[] version) {
    try (var connection = dataSource.getConnection()) { return getV2(connection, account, version); }
    catch (SQLException e) { throw new IllegalStateException("Cannot read encrypted v2 profile", e); }
  }

  static Optional<VersionedProfile> getV2(Connection connection, UUID account, byte[] version) throws SQLException {
    try (var statement = connection.prepareStatement("SELECT * FROM signal.profiles_v2 WHERE account_id=? AND version=?")) {
      statement.setObject(1, account);
      statement.setBytes(2, version);
      try (var rows = statement.executeQuery()) {
        return rows.next() ? Optional.of(new VersionedProfile(rows.getBytes("version"), rows.getBytes("data"),
            rows.getBytes("data_hash"), rows.getBytes("payment_address"), rows.getBytes("payment_address_hash"),
            rows.getBytes("commitment"))) : Optional.empty();
      }
    }
  }

  private static VersionedProfileV1 v1FromRow(ResultSet rows) throws SQLException {
    return new VersionedProfileV1(rows.getString("version"), rows.getBytes("name"), rows.getString("avatar"),
        rows.getBytes("about_emoji"), rows.getBytes("about"), rows.getBytes("payment_address"),
        rows.getBytes("phone_number_sharing"), rows.getBytes("commitment"));
  }

  @Override public CompletableFuture<List<String>> deleteV1(UUID account) {
    return CompletableFuture.supplyAsync(() -> uncontestedTransaction(account, connection -> {
      try (var statement = connection.prepareStatement("DELETE FROM signal.profiles_v1 WHERE account_id=? RETURNING avatar")) {
        statement.setObject(1, account);
        var avatars = new ArrayList<String>();
        try (var rows = statement.executeQuery()) {
          while (rows.next()) { String avatar = rows.getString(1); if (avatar != null) avatars.add(avatar); }
        }
        return avatars;
      }
    }), executor);
  }

  @Override public CompletableFuture<Void> deleteV2(UUID account) {
    return CompletableFuture.supplyAsync(() -> uncontestedTransaction(account, connection -> {
      try (var statement = connection.prepareStatement("DELETE FROM signal.profiles_v2 WHERE account_id=?")) {
        statement.setObject(1, account);
        statement.executeUpdate();
      }
      return null;
    }), executor);
  }

  @Override public VersionedProfileV1 setV1Avatar(UUID account, String version, String avatar, byte[] commitment) {
    return uncontestedTransaction(account, connection -> writeV1Avatar(connection, account, version, avatar, commitment));
  }

  static VersionedProfileV1 writeV1Avatar(Connection connection, UUID account, String version, String avatar, byte[] commitment) throws SQLException {
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.profiles_v1 (account_id, version, avatar, commitment) VALUES (?, ?, ?, ?)
        ON CONFLICT (account_id, version) DO UPDATE SET avatar=EXCLUDED.avatar RETURNING *
        """)) {
      statement.setObject(1, account);
      statement.setString(2, version);
      statement.setString(3, avatar);
      statement.setBytes(4, commitment);
      try (var rows = statement.executeQuery()) { rows.next(); return v1FromRow(rows); }
    }
  }

  private <T> T uncontestedTransaction(UUID account, SqlWork<T> work) {
    try { return transaction(account, work); }
    catch (WriteConflictException e) { throw new AssertionError("Unexpected profile conflict", e); }
  }

  private <T> T transaction(UUID account, SqlWork<T> work) throws WriteConflictException {
    try (var connection = dataSource.getConnection()) {
      connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      connection.setAutoCommit(false);
      try {
        lock(connection, account);
        T value = work.execute(connection);
        connection.commit();
        return value;
      } catch (SQLException | RuntimeException | WriteConflictException e) {
        try { connection.rollback(); } catch (SQLException rollback) { e.addSuppressed(rollback); }
        throw e;
      }
    } catch (SQLException e) { throw new IllegalStateException("PostgreSQL profile transaction failed", e); }
  }

  static void lock(Connection connection, UUID account) throws SQLException {
    try (var statement = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
      statement.setLong(1, account.getMostSignificantBits() ^ Long.rotateLeft(account.getLeastSignificantBits(), 17)
          ^ 0x424350524F46494CL);
      statement.execute();
    }
  }

  @FunctionalInterface private interface SqlWork<T> { T execute(Connection connection) throws SQLException, WriteConflictException; }
}
