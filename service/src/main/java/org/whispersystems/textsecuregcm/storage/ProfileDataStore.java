// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;

/** Both profile generations must commit together when a client publishes a v2 profile. */
public interface ProfileDataStore {
  void setV1(UUID account, VersionedProfileV1 profile);
  void setBoth(UUID account, VersionedProfileV1 v1, VersionedProfile v2, @Nullable byte[] expectedDataHash) throws WriteConflictException;
  Optional<VersionedProfileV1> getV1(UUID account, String version);
  Optional<VersionedProfile> getV2(UUID account, byte[] version);
  CompletableFuture<List<String>> deleteV1(UUID account);
  CompletableFuture<Void> deleteV2(UUID account);
  VersionedProfileV1 setV1Avatar(UUID account, String version, String avatar, byte[] commitment);
}
