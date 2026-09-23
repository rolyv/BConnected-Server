// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import java.util.concurrent.CompletableFuture;

/** Operations on encrypted avatar objects. Callers retain account/anonymous-credential authorization. */
public interface AvatarObjectStorage {
  /** Idempotently deletes an avatar selected by the profile manager. */
  CompletableFuture<Void> delete(String key);

  /** Check at actual provider dispatch, including any internal executor wait; unsupported stores fail closed. */
  default CompletableFuture<Void> delete(String key, Runnable requireCurrent) {
    return CompletableFuture.failedFuture(new UnsupportedOperationException("Guarded avatar deletion unavailable"));
  }

  /** Renews an existing object's age without recreating a concurrently deleted object; false means missing. */
  CompletableFuture<Boolean> refresh(String key);
}
