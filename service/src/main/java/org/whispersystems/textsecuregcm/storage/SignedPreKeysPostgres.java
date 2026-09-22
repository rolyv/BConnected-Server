// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.SignedPreKey;

/** Repeated-use EC and KEM keys with mutations that join the owning account's JDBC transaction. */
public final class SignedPreKeysPostgres<K extends SignedPreKey<?>> implements SignedPreKeyStore<K> {
  private final DataSource dataSource;
  private final Executor executor;
  private final String kind;
  private final KeyDecoder<K> decoder;

  private SignedPreKeysPostgres(final DataSource dataSource, final Executor executor, final String kind,
      final KeyDecoder<K> decoder) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.executor = Objects.requireNonNull(executor);
    this.kind = kind;
    this.decoder = decoder;
  }

  public static SignedPreKeysPostgres<ECSignedPreKey> ec(final DataSource dataSource, final Executor executor) {
    return new SignedPreKeysPostgres<>(dataSource, executor, "ec",
        (id, key, signature) -> new ECSignedPreKey(id, new ECPublicKey(key), signature));
  }

  public static SignedPreKeysPostgres<KEMSignedPreKey> kem(final DataSource dataSource, final Executor executor) {
    return new SignedPreKeysPostgres<>(dataSource, executor, "kem",
        (id, key, signature) -> new KEMSignedPreKey(id, new KEMPublicKey(key), signature));
  }

  @Override
  public CompletableFuture<Void> store(final UUID identifier, final byte deviceId, final K signedPreKey) {
    final AccountMutation mutation = buildInsertion(identifier, deviceId, signedPreKey);
    return CompletableFuture.runAsync(() -> {
      try (var connection = dataSource.getConnection()) {
        connection.setAutoCommit(false);
        try {
          mutation.applySql(connection);
          connection.commit();
        } catch (SQLException | RuntimeException e) {
          try { connection.rollback(); }
          catch (SQLException rollbackFailure) { e.addSuppressed(rollbackFailure); }
          throw e;
        }
      } catch (SQLException e) {
        throw new CompletionException("PostgreSQL signed pre-key write failed", e);
      }
    }, executor);
  }

  @Override
  public CompletableFuture<Optional<K>> find(final UUID identifier, final byte deviceId) {
    return CompletableFuture.supplyAsync(() -> {
      try (var connection = dataSource.getConnection()) {
        return find(connection, identifier, deviceId);
      } catch (SQLException e) {
        throw new CompletionException("PostgreSQL signed pre-key read failed", e);
      }
    }, executor);
  }

  Optional<K> find(final java.sql.Connection connection, final UUID identifier, final byte deviceId) throws SQLException {
    try (var statement = connection.prepareStatement("""
        SELECT key_id, public_key, signature FROM signal.signed_prekeys
        WHERE identifier = ? AND device_id = ? AND kind = ?
        """)) {
      statement.setObject(1, identifier);
      statement.setByte(2, deviceId);
      statement.setString(3, kind);
      try (var result = statement.executeQuery()) {
        if (!result.next()) return Optional.empty();
        final long keyId = result.getLong("key_id");
        if (!KeyIdUtil.keyIdValid(keyId)) throw new IllegalStateException("Stored signed pre-key ID is out of range");
        return Optional.of(decoder.decode(keyId, result.getBytes("public_key"), result.getBytes("signature")));
      } catch (InvalidKeyException e) {
        throw new CompletionException("PostgreSQL signed pre-key read failed", e);
      }
    }
  }

  @Override
  public AccountMutation buildInsertion(final UUID identifier, final byte deviceId, final K signedPreKey) {
    Objects.requireNonNull(identifier);
    if (!KeyIdUtil.keyIdValid(signedPreKey.keyId())) {
      throw new IllegalArgumentException("Signed pre-key ID is outside the supported range");
    }
    final long keyId = signedPreKey.keyId();
    final byte[] publicKey = signedPreKey.serializedPublicKey().clone();
    final byte[] signature = signedPreKey.signature().clone();
    return new AccountMutation.Sql(connection -> {
      try (var statement = connection.prepareStatement("""
          INSERT INTO signal.signed_prekeys (identifier, device_id, kind, key_id, public_key, signature)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT (identifier, device_id, kind) DO UPDATE
          SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key, signature = EXCLUDED.signature
          """)) {
        statement.setObject(1, identifier);
        statement.setByte(2, deviceId);
        statement.setString(3, kind);
        statement.setLong(4, keyId);
        statement.setBytes(5, publicKey);
        statement.setBytes(6, signature);
        statement.executeUpdate();
      }
    });
  }

  @Override
  public AccountMutation buildDeletion(final UUID identifier, final byte deviceId) {
    Objects.requireNonNull(identifier);
    return new AccountMutation.Sql(connection -> {
      try (var statement = connection.prepareStatement("""
          DELETE FROM signal.signed_prekeys WHERE identifier = ? AND device_id = ? AND kind = ?
          """)) {
        statement.setObject(1, identifier);
        statement.setByte(2, deviceId);
        statement.setString(3, kind);
        statement.executeUpdate();
      }
    });
  }

  @FunctionalInterface
  private interface KeyDecoder<K> {
    K decode(long id, byte[] publicKey, byte[] signature) throws InvalidKeyException;
  }
}
