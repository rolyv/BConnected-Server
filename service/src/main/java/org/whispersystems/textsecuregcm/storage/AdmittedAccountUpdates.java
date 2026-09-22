// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import org.whispersystems.textsecuregcm.admission.AdmissionAccountMutationGuard;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;

/** Bounded native account mutations; no optimistic retry may adopt a newer credential snapshot. */
public final class AdmittedAccountUpdates {
  private final AccountsPostgres accounts;
  private final Consumer<Account> evict;
  private final AdmissionEntitlementGate gate;
  private final Executor executor;
  public AdmittedAccountUpdates(AccountsPostgres accounts, Consumer<Account> evict,
      AdmissionEntitlementGate gate, Executor executor) {
    this.accounts = accounts; this.evict = evict; this.gate = gate; this.executor = executor;
  }
  public void http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal, Consumer<Account> mutation) {
    try { update(AdmissionAccountMutationGuard.http(gate, principal), mutation); }
    catch (RuntimeException failure) { throw AdmissionAccountMutationGuard.failure(failure).http(); }
  }
  public void grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal, Consumer<Account> mutation) {
    try { update(AdmissionAccountMutationGuard.grpc(gate, principal), mutation); }
    catch (RuntimeException failure) { throw AdmissionAccountMutationGuard.failure(failure).grpc(); }
  }
  public void update(AdmissionAccountMutationGuard guard, Consumer<Account> mutation) {
    try {
      CompletableFuture.runAsync(() -> {
        final Account original = guard.begin();
        try { accounts.updateAdmitted(guard, original, mutation); }
        finally {
          // Eviction is maintenance, even after rollback or uncertain commit. Never cache a result
          // after releasing SQL locks: a concurrent mutation could otherwise be overwritten there.
          evict.accept(original);
        }
        guard.requireResult();
      }, executor).join();
      guard.requireResult(); // dispatch/join/connection-close/cache waits consume the original proof
    } catch (RuntimeException failure) { throw AdmissionAccountMutationGuard.failure(failure); }
  }
}
