// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.avatars.AvatarObjectStorage;
import org.whispersystems.textsecuregcm.redis.ClusterLuaScript;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;

class ProfilesManagerAvatarStorageTest {
  private static final String KEY = "profiles/AAAAAAAAAAAAAAAAAAAAAA==";
  private static final byte[] IDENTITY = new byte[32];
  private ProfileAvatarStore mappings;
  private AvatarObjectStorage objects;
  private ProfilesManager manager;

  @BeforeEach void setUp() {
    mappings = mock(ProfileAvatarStore.class);
    objects = mock(AvatarObjectStorage.class);
    manager = new ProfilesManager(mock(ProfileDataStore.class), mappings,
        mock(FaultTolerantRedisClusterClient.class), mock(ScheduledExecutorService.class), objects, mock(ClusterLuaScript.class));
  }

  @Test void identityDeletionUsesOnlyItsStoredObject() {
    when(mappings.deleteAvatarUrl(IDENTITY)).thenReturn(Optional.of(KEY));
    when(objects.delete(KEY)).thenReturn(CompletableFuture.completedFuture(null));
    manager.deleteAvatarForIdentity(IDENTITY);
    verify(objects).delete(KEY);
    verifyNoMoreInteractions(objects);
  }

  @Test void replacementDeletesOnlyPreviousMapping() {
    String replacement = "profiles/AQEBAQEBAQEBAQEBAQEBAQ==";
    when(mappings.setAvatarUrl(IDENTITY, replacement)).thenReturn(Optional.of(KEY));
    when(objects.delete(KEY)).thenReturn(CompletableFuture.completedFuture(null));
    manager.setAvatarForIdentity(IDENTITY, replacement);
    verify(objects).delete(KEY);
    verifyNoMoreInteractions(objects);
  }

  @Test void missingObjectClearsMappingWithoutRetryOrUpload() {
    when(mappings.updateAvatarTtl(IDENTITY)).thenReturn(Optional.of(KEY));
    when(objects.refresh(KEY)).thenReturn(CompletableFuture.completedFuture(false));
    assertThat(manager.extendAvatarTtlForIdentity(IDENTITY)).isEmpty();
    verify(objects).refresh(KEY);
    verify(mappings).deleteAvatarUrl(IDENTITY);
    verifyNoMoreInteractions(objects);
  }

  @Test void refreshRetriesConcurrentFailureFromFreshReadAndPreservesMapping() {
    when(mappings.updateAvatarTtl(IDENTITY)).thenReturn(Optional.of(KEY));
    when(objects.refresh(KEY)).thenReturn(CompletableFuture.failedFuture(new IllegalStateException("retry")),
        CompletableFuture.completedFuture(true));
    assertThat(manager.extendAvatarTtlForIdentity(IDENTITY)).contains(KEY);
    verify(objects, times(2)).refresh(KEY);
    verify(mappings, never()).deleteAvatarUrl(any());
  }
}
