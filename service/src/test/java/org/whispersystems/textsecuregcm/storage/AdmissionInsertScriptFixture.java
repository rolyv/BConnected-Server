// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import org.whispersystems.textsecuregcm.admission.AdmissionMessageSendGuard;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;

/** Package bridge so native admission tests exercise the actual private Redis insertion/retry path. */
public final class AdmissionInsertScriptFixture {
  public static CompletionStage<Boolean> insert(FaultTolerantRedisClusterClient redis,
      ScheduledExecutorService retries, UUID destination, Envelope envelope, AdmissionMessageSendGuard guard)
      throws IOException {
    return new MessagesCacheInsertScript(redis, retries).executeAsync(destination, (byte) 1, envelope, guard);
  }
}
