// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.whispersystems.textsecuregcm.entities.SignedPreKey;

public interface SignedPreKeyStore<K extends SignedPreKey<?>> {
  CompletableFuture<Void> store(UUID identifier, byte deviceId, K signedPreKey);

  CompletableFuture<Optional<K>> find(UUID identifier, byte deviceId);

  AccountMutation buildInsertion(UUID identifier, byte deviceId, K signedPreKey);

  AccountMutation buildDeletion(UUID identifier, byte deviceId);
}
