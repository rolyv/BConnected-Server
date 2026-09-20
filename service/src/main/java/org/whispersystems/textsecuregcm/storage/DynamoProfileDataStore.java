// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/** Keeps the upstream DynamoDB transaction wholly inside the legacy storage adapter. */
public record DynamoProfileDataStore(Profiles v1, ProfilesV2 v2) implements ProfileDataStore {
  @Override public void setV1(UUID account, VersionedProfileV1 profile) { v1.set(account, profile); }
  @Override public void setBoth(UUID account, VersionedProfileV1 first, VersionedProfile second, byte[] expected) throws WriteConflictException {
    v2.set(account, second.version(), second.data(), second.dataHash(), second.commitment(),
        second.paymentAddress(), second.paymentAddressHash(), expected, v1.getTransactWriteItem(account, first));
  }
  @Override public Optional<VersionedProfileV1> getV1(UUID account, String version) { return v1.get(account, version); }
  @Override public Optional<VersionedProfile> getV2(UUID account, byte[] version) { return v2.get(account, version); }
  @Override public CompletableFuture<List<String>> deleteV1(UUID account) { return v1.deleteAll(account); }
  @Override public CompletableFuture<Void> deleteV2(UUID account) { return v2.deleteAll(account); }
  @Override public VersionedProfileV1 setV1Avatar(UUID account, String version, String avatar, byte[] commitment) {
    return v1.setAvatar(account, version, avatar, commitment);
  }
}
