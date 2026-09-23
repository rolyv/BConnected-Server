// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionAccountMutationGuard;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionProfileReadGuard;
import org.whispersystems.textsecuregcm.avatars.AvatarObjectStorage;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;

/** Native profile/account atomicity and original-proof checks through provider work and response construction. */
public final class AdmittedProfiles {
  public enum Reason { CAPABILITY, VERSION_CONFLICT, DATA_CONFLICT, PAYMENTS, COMMITMENT_REQUIRED }
  public static final class Rejected extends RuntimeException {
    private final Reason reason;
    public Rejected(Reason reason) { super("Profile request rejected"); this.reason = reason; }
    public Reason reason() { return reason; }
  }
  public record ReadSnapshot(Account account, Optional<VersionedProfileV1> v1, Optional<VersionedProfile> v2) {}
  public static final class Publication {
    private final Connection connection;
    private final Account account;
    private String oldAvatar;
    private final AdmissionAccountMutationGuard guard;
    private Publication(Connection connection, Account account, AdmissionAccountMutationGuard guard) { this.connection = connection; this.account = account; this.guard = guard; }
    public org.whispersystems.textsecuregcm.avatars.AvatarUploadPolicyGenerator.UploadPolicy uploadPolicy(
        org.whispersystems.textsecuregcm.avatars.AvatarUploadPolicyGenerator generator, String name, int length, java.time.Instant time) {
      guard.requireResult();
      var policy = generator.createFor(name, length, time, guard::requireResult);
      guard.requireResult();
      return policy;
    }
    public Account account() { return account; }
    public Optional<VersionedProfileV1> v1(String version) {
      try { return ProfilesPostgres.getV1(connection, account.getAccountIdentifier(), version); }
      catch (SQLException failure) { throw AdmissionAccountMutationGuard.unavailable(); }
    }
    public Optional<VersionedProfile> v2(byte[] version) {
      try { return ProfilesPostgres.getV2(connection, account.getAccountIdentifier(), version); }
      catch (SQLException failure) { throw AdmissionAccountMutationGuard.unavailable(); }
    }
    public void setV1(VersionedProfileV1 profile) {
      try {
        ProfilesPostgres.writeV1(connection, account.getAccountIdentifier(), profile);
        try (var statement = connection.prepareStatement("DELETE FROM signal.profiles_v2 WHERE account_id=?")) {
          statement.setObject(1, account.getAccountIdentifier()); statement.executeUpdate();
        }
      } catch (SQLException failure) { throw AdmissionAccountMutationGuard.unavailable(); }
    }
    public void setBoth(VersionedProfileV1 v1, VersionedProfile v2, byte[] expectedHash) {
      try { ProfilesPostgres.writeBoth(connection, account.getAccountIdentifier(), v1, v2, expectedHash); }
      catch (WriteConflictException conflict) { throw new Rejected(Reason.DATA_CONFLICT); }
      catch (SQLException failure) { throw AdmissionAccountMutationGuard.unavailable(); }
    }
    public void setV1Avatar(String version, String avatar, byte[] commitment) {
      try { ProfilesPostgres.writeV1Avatar(connection, account.getAccountIdentifier(), version, avatar, commitment); }
      catch (SQLException failure) { throw AdmissionAccountMutationGuard.unavailable(); }
    }
    public void deleteOldAvatar(Optional<String> avatar) { oldAvatar = avatar.orElse(null); }
  }
  private final DataSource dataSource;
  private final AccountsPostgres accounts;
  private final AccountsManager cache;
  private final Consumer<UUID> evictProfiles;
  private final AvatarObjectStorage avatars;
  private final AdmissionEntitlementGate gate;
  private final Executor executor;

  public AdmittedProfiles(DataSource dataSource, AccountsPostgres accounts, AccountsManager cache,
      Consumer<UUID> evictProfiles, AvatarObjectStorage avatars, AdmissionEntitlementGate gate, Executor executor) {
    this.dataSource = dataSource; this.accounts = accounts; this.cache = cache; this.evictProfiles = evictProfiles;
    this.avatars = avatars; this.gate = gate; this.executor = executor;
  }
  public <T> T http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal,
      Function<Publication, Supplier<T>> mutation) {
    try { return publish(AdmissionAccountMutationGuard.profileHttp(gate, principal), mutation); }
    catch (RuntimeException failure) {
      if (cause(failure) instanceof Rejected rejected) throw rejected;
      throw AdmissionAccountMutationGuard.failure(failure).http();
    }
  }
  public <T> T grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal,
      Function<Publication, Supplier<T>> mutation) {
    try { return publish(AdmissionAccountMutationGuard.profileGrpc(gate, principal), mutation); }
    catch (RuntimeException failure) {
      if (cause(failure) instanceof Rejected rejected) throw rejected;
      throw AdmissionAccountMutationGuard.failure(failure).grpc();
    }
  }
  private <T> T publish(AdmissionAccountMutationGuard guard, Function<Publication, Supplier<T>> mutation) {
    guard.requireProfilePublication();
    try {
      T result = CompletableFuture.supplyAsync(() -> {
        final Account original = guard.begin();
        final Publication[] publication = new Publication[1];
        final Supplier<T> finish;
        try {
          finish = accounts.updateAdmittedWithSql(guard, original, (connection, account) -> {
            ProfilesPostgres.lock(connection, account.getAccountIdentifier());
            guard.requireCurrent(connection);
            publication[0] = new Publication(connection, account, guard);
            return mutation.apply(publication[0]);
          });
        } finally {
          // Maintenance is deliberately independent of receipt freshness, including uncertain commit.
          try { cache.invalidateCacheAfterAdmittedUpdate(original); }
          finally { evictProfiles.accept(original.getAccountIdentifier()); }
        }
        guard.requireResult();
        if (publication[0].oldAvatar != null) {
          // Worker stays occupied through provider completion, bounding unfinished provider calls.
          avatars.delete(publication[0].oldAvatar, guard::requireResult).join();
          guard.requireResult();
        }
        final T built = finish.get(); // signing/provider waits consume the same original receipt
        guard.requireResult();
        return built;
      }, executor).join();
      guard.requireResult();
      return result;
    } catch (RuntimeException failure) {
      if (cause(failure) instanceof Rejected rejected) throw rejected;
      throw AdmissionAccountMutationGuard.failure(failure);
    }
  }
  public <T> T httpRead(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal,
      ServiceIdentifier identifier, String version, Function<ReadSnapshot, T> response) {
    try { return read(AdmissionProfileReadGuard.http(gate, principal), identifier, version, null, response); }
    catch (RuntimeException failure) {
      if (cause(failure) instanceof jakarta.ws.rs.WebApplicationException http) throw http;
      throw AdmissionProfileReadGuard.failure(failure).http();
    }
  }
  public <T> T grpcRead(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal,
      ServiceIdentifier identifier, byte[] version, Function<ReadSnapshot, T> response) {
    try { return read(AdmissionProfileReadGuard.grpc(gate, principal), identifier, HexFormat.of().formatHex(version), version, response); }
    catch (RuntimeException failure) {
      if (cause(failure) instanceof io.grpc.StatusRuntimeException grpc) throw grpc;
      throw AdmissionProfileReadGuard.failure(failure).grpc();
    }
  }
  private <T> T read(AdmissionProfileReadGuard caller, ServiceIdentifier identifier, String v1Version, byte[] version,
      Function<ReadSnapshot, T> response) {
    final UUID aci;
    if (identifier.identityType() == IdentityType.ACI) aci = identifier.uuid();
    else {
      var candidate = cache.getByServiceIdentifier(identifier);
      caller.requireCurrent();
      aci = candidate.orElseThrow(() -> AdmissionProfileReadGuard.targetNotFound()).getAccountIdentifier();
    }
    final var guard = caller.forTarget(aci, identifier);
    final Account account = guard.account();
    try {
      T result = CompletableFuture.supplyAsync(() -> {
        guard.requireFresh();
        final ReadSnapshot snapshot;
        try (var connection = dataSource.getConnection()) {
          connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED); connection.setAutoCommit(false);
          try {
            guard.requireCurrent(connection);
            ProfilesPostgres.lock(connection, aci);
            guard.requireCurrent(connection);
            snapshot = new ReadSnapshot(account,
                v1Version == null ? Optional.empty() : ProfilesPostgres.getV1(connection, aci, v1Version),
                version == null ? Optional.empty() : ProfilesPostgres.getV2(connection, aci, version));
            guard.requireCurrent(connection);
            connection.commit();
          } catch (SQLException | RuntimeException failure) {
            try { connection.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
            throw failure;
          }
        } catch (SQLException failure) { throw AdmissionProfileReadGuard.unavailable(); }
        guard.requireCurrent();
        T built = response.apply(snapshot);
        guard.requireCurrent();
        return built;
      }, executor).join();
      guard.requireCurrent();
      return result;
    } catch (RuntimeException failure) {
      if (cause(failure) instanceof jakarta.ws.rs.WebApplicationException http) throw http;
      if (cause(failure) instanceof io.grpc.StatusRuntimeException grpc) throw grpc;
      throw AdmissionProfileReadGuard.failure(failure);
    }
  }
  private static Throwable cause(Throwable error) {
    while ((error instanceof java.util.concurrent.CompletionException) && error.getCause() != null) error = error.getCause();
    return error;
  }
}
