// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.whispersystems.textsecuregcm.entities.ECPreKey;

/** Native PostgreSQL storage of public pre-keys using libsignal's existing wire encoding. */
public class SingleUseECPreKeysPostgres implements SingleUseECPreKeyStorage {
  private final DataSource dataSource;
  private final Executor executor;

  public SingleUseECPreKeysPostgres(final DataSource dataSource, final Executor executor) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.executor = Objects.requireNonNull(executor);
  }

  @Override
  public CompletableFuture<Void> store(final UUID identifier, final byte deviceId, final List<ECPreKey> preKeys) {
    final List<ECPreKey> snapshot = List.copyOf(preKeys);
    return transaction(identifier, connection -> {
      deleteForDevice(connection, identifier, deviceId);
      try (var statement = connection.prepareStatement("""
          INSERT INTO signal.single_use_ec_prekeys (account_id, device_id, key_id, public_key)
          VALUES (?, ?, ?, ?)
          ON CONFLICT (account_id, device_id, key_id) DO UPDATE SET public_key = EXCLUDED.public_key
          """)) {
        int pending = 0;
        for (final ECPreKey preKey : snapshot) {
          if (!KeyIdUtil.keyIdValid(preKey.keyId())) {
            throw new IllegalArgumentException("Pre-key ID is outside the supported range");
          }
          statement.setObject(1, identifier);
          statement.setByte(2, deviceId);
          statement.setLong(3, preKey.keyId());
          statement.setBytes(4, preKey.serializedPublicKey());
          statement.addBatch();
          if (++pending == 100) {
            statement.executeBatch();
            statement.clearBatch();
            pending = 0;
          }
        }
        if (pending > 0) statement.executeBatch();
      }
      return null;
    });
  }

  @Override
  public CompletableFuture<Optional<ECPreKey>> take(final UUID identifier, final byte deviceId) {
    return transaction(identifier, connection -> {
      try (var statement = connection.prepareStatement("""
          DELETE FROM signal.single_use_ec_prekeys
          WHERE account_id = ? AND device_id = ? AND key_id = (
            SELECT key_id FROM signal.single_use_ec_prekeys
            WHERE account_id = ? AND device_id = ? ORDER BY key_id LIMIT 1 FOR UPDATE
          )
          RETURNING key_id, public_key
          """)) {
        statement.setObject(1, identifier);
        statement.setByte(2, deviceId);
        statement.setObject(3, identifier);
        statement.setByte(4, deviceId);
        try (var result = statement.executeQuery()) {
          if (!result.next()) return Optional.empty();
          try {
            return Optional.of(new ECPreKey(result.getLong("key_id"), new ECPublicKey(result.getBytes("public_key"))));
          } catch (InvalidKeyException e) {
            // Fail and roll back the deletion rather than consume a key we cannot return to the caller.
            throw new IllegalStateException("Stored EC pre-key has invalid libsignal encoding", e);
          }
        }
      }
    });
  }

  @Override
  public CompletableFuture<Integer> getCount(final UUID identifier, final byte deviceId) {
    return transaction(identifier, connection -> {
      try (var statement = connection.prepareStatement("""
          SELECT count(*) FROM signal.single_use_ec_prekeys WHERE account_id = ? AND device_id = ?
          """)) {
        statement.setObject(1, identifier);
        statement.setByte(2, deviceId);
        try (var result = statement.executeQuery()) {
          result.next();
          return Math.toIntExact(result.getLong(1));
        }
      }
    });
  }

  @Override
  public CompletableFuture<Void> delete(final UUID identifier) {
    return transaction(identifier, connection -> {
      try (var statement = connection.prepareStatement("DELETE FROM signal.single_use_ec_prekeys WHERE account_id = ?")) {
        statement.setObject(1, identifier);
        statement.executeUpdate();
      }
      return null;
    });
  }

  @Override
  public CompletableFuture<Void> delete(final UUID identifier, final byte deviceId) {
    return transaction(identifier, connection -> {
      deleteForDevice(connection, identifier, deviceId);
      return null;
    });
  }

  private static void deleteForDevice(final Connection connection, final UUID identifier, final byte deviceId)
      throws SQLException {
    try (var statement = connection.prepareStatement("""
        DELETE FROM signal.single_use_ec_prekeys WHERE account_id = ? AND device_id = ?
        """)) {
      statement.setObject(1, identifier);
      statement.setByte(2, deviceId);
      statement.executeUpdate();
    }
  }

  private <T> CompletableFuture<T> transaction(final UUID identifier, final SqlOperation<T> operation) {
    Objects.requireNonNull(identifier);
    return CompletableFuture.supplyAsync(() -> {
      try (var connection = dataSource.getConnection()) {
        connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        connection.setAutoCommit(false);
        try {
          // All operations, including account-wide deletion, use the same account lock. Acquiring it in its own
          // READ COMMITTED statement makes subsequent reads see the preceding operation's committed result.
          // A 64-bit hash collision can only serialize unrelated accounts; it cannot mix their rows.
          try (var lock = connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
            lock.setLong(1, identifier.getMostSignificantBits()
                ^ Long.rotateLeft(identifier.getLeastSignificantBits(), 17) ^ 0x424345435052454BL);
            lock.execute();
          }
          final T result = operation.apply(connection);
          connection.commit();
          return result;
        } catch (SQLException | RuntimeException e) {
          try {
            connection.rollback();
          } catch (SQLException rollbackFailure) {
            e.addSuppressed(rollbackFailure);
          }
          throw e;
        }
      } catch (SQLException e) {
        throw new CompletionException("PostgreSQL EC pre-key operation failed", e);
      }
    }, executor);
  }

  @FunctionalInterface
  private interface SqlOperation<T> {
    T apply(Connection connection) throws SQLException;
  }
}
