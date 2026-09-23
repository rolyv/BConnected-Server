// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionKeyGuard;
import org.whispersystems.textsecuregcm.entities.ECPreKey;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.PreKeyCount;
import org.whispersystems.textsecuregcm.identity.IdentityType;

/** Atomic pilot key bundles: membership locks and every key operation share one native transaction. */
public final class AdmittedKeysPostgres {
  private final DataSource dataSource;
  private final Executor executor;
  private final SignedPreKeysPostgres<ECSignedPreKey> signedEc;
  private final SignedPreKeysPostgres<KEMSignedPreKey> lastResort;

  public AdmittedKeysPostgres(DataSource dataSource, Executor executor) {
    this.dataSource = dataSource; this.executor = executor;
    signedEc = SignedPreKeysPostgres.ec(dataSource, executor);
    lastResort = SignedPreKeysPostgres.kem(dataSource, executor);
  }
  public CompletableFuture<PreKeyCount> count(AdmissionKeyGuard guard, IdentityType identity) {
    return transaction(guard, identity, (connection, identifier) -> new PreKeyCount(
        SingleUseECPreKeysPostgres.getCount(connection, identifier, Device.PRIMARY_ID),
        SingleUseKEMPreKeysPostgres.getCount(connection, identifier, Device.PRIMARY_ID)));
  }
  public record RepeatedKeys(Optional<ECSignedPreKey> ec, Optional<KEMSignedPreKey> kem) {}
  public CompletableFuture<RepeatedKeys> repeated(AdmissionKeyGuard guard, IdentityType identity) {
    return transaction(guard, identity, (connection, identifier) -> new RepeatedKeys(
        signedEc.find(connection, identifier, Device.PRIMARY_ID), lastResort.find(connection, identifier, Device.PRIMARY_ID)));
  }
  /** A null collection leaves that key class unchanged; an empty collection replaces it with no keys. */
  public CompletableFuture<Void> publish(AdmissionKeyGuard guard, IdentityType identity,
      List<ECPreKey> ec, ECSignedPreKey signed, List<KEMSignedPreKey> kem, KEMSignedPreKey fallback) {
    guard.requirePublication();
    final List<ECPreKey> ecCopy = ec == null ? null : List.copyOf(ec);
    final List<KEMSignedPreKey> kemCopy = kem == null ? null : List.copyOf(kem);
    return transaction(guard, identity, (connection, identifier) -> {
      if (ecCopy != null) SingleUseECPreKeysPostgres.store(connection, identifier, Device.PRIMARY_ID, ecCopy);
      if (signed != null) signedEc.buildInsertion(identifier, Device.PRIMARY_ID, signed).applySql(connection);
      if (kemCopy != null) SingleUseKEMPreKeysPostgres.store(connection, identifier, Device.PRIMARY_ID, kemCopy);
      if (fallback != null) lastResort.buildInsertion(identifier, Device.PRIMARY_ID, fallback).applySql(connection);
      return null;
    });
  }
  /** Initial-only durable operation: recorded replay must never execute either replacing store again. */
  public CompletableFuture<Boolean> publishInitial(AdmissionKeyGuard guard, IdentityType identity, UUID operation,
      org.whispersystems.textsecuregcm.entities.InitialPreKeyPublication publication) {
    guard.requirePublication();
    java.util.Objects.requireNonNull(operation); java.util.Objects.requireNonNull(publication);
    var account = guard.account();
    if (!publication.signedFor(identity == IdentityType.ACI ? account.getAccountIdentityKey()
        : account.getPhoneNumberIdentityKey().orElse(null))) throw AdmissionKeyGuard.unavailable();
    return transaction(guard, identity, (connection, identifier) -> {
      var decision = InitialPreKeyPublicationsPostgres.reserve(connection, guard.publicationBinding(connection),
          operation, identity, identifier, publication.digest());
      if (decision == InitialPreKeyPublicationsPostgres.Decision.CONFLICT) return false;
      if (decision == InitialPreKeyPublicationsPostgres.Decision.APPLY) {
        SingleUseECPreKeysPostgres.store(connection, identifier, Device.PRIMARY_ID, publication.ec());
        SingleUseKEMPreKeysPostgres.store(connection, identifier, Device.PRIMARY_ID, publication.kem());
      }
      return true;
    });
  }
  public CompletableFuture<Optional<KeysManager.DevicePreKeys>> take(AdmissionKeyGuard guard, IdentityType identity) {
    return transaction(guard, identity, (connection, identifier) -> {
      final var signed = signedEc.find(connection, identifier, Device.PRIMARY_ID);
      if (signed.isEmpty()) return Optional.empty();
      var kem = SingleUseKEMPreKeysPostgres.take(connection, identifier, Device.PRIMARY_ID);
      if (kem.isEmpty()) kem = lastResort.find(connection, identifier, Device.PRIMARY_ID);
      if (kem.isEmpty()) return Optional.empty();
      final var ec = SingleUseECPreKeysPostgres.take(connection, identifier, Device.PRIMARY_ID);
      return Optional.of(new KeysManager.DevicePreKeys(signed.orElseThrow(), ec, kem.orElseThrow()));
    });
  }
  private <T> CompletableFuture<T> transaction(AdmissionKeyGuard guard, IdentityType identity, Operation<T> operation) {
    final UUID identifier = guard.identifier(identity);
    try {
      return CompletableFuture.supplyAsync(() -> {
        try {
          guard.requireFresh(); // the bounded executor wait consumes the original proof
          final T result;
          try (var connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setAutoCommit(false);
            try {
              guard.requireCurrent(connection);
              // Same locks as ungated maintenance stores; fixed EC then KEM order.
              SingleUseECPreKeysPostgres.lock(connection, identifier);
              SingleUseKEMPreKeysPostgres.lock(connection, identifier);
              guard.requireCurrent(connection);
              result = operation.apply(connection, identifier);
              guard.requireCurrent(connection); // includes row-lock/key-write waits; rejection rolls back
              connection.commit();
            } catch (SQLException | RuntimeException failure) {
              try { connection.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
              throw failure;
            }
          }
          guard.requireFresh(); // includes commit and connection-close time
          return result;
        } catch (SQLException | RuntimeException failure) {
          throw AdmissionKeyGuard.failure(failure);
        }
      }, executor);
    } catch (RuntimeException rejected) {
      return CompletableFuture.failedFuture(AdmissionKeyGuard.unavailable());
    }
  }
  @FunctionalInterface private interface Operation<T> {
    T apply(Connection connection, UUID identifier) throws SQLException;
  }
}
