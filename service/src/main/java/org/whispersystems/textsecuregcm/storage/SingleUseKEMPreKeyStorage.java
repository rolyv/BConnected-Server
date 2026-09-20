// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;

/** Persistence boundary for one-time KEM pre-keys; a consumed key must never be returned twice. */
public interface SingleUseKEMPreKeyStorage {
  CompletableFuture<Void> store(UUID identifier, byte deviceId, List<KEMSignedPreKey> preKeys);

  CompletableFuture<Optional<KEMSignedPreKey>> take(UUID identifier, byte deviceId);

  CompletableFuture<Integer> getCount(UUID identifier, byte deviceId);

  CompletableFuture<Void> delete(UUID identifier);

  CompletableFuture<Void> delete(UUID identifier, byte deviceId);
}
