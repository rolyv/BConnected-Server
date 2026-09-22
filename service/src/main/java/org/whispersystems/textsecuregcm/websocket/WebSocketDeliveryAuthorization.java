// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.websocket;

import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import org.whispersystems.textsecuregcm.storage.MessageDeliveryGuard;

/** Each use captures the current verified lineage before dispatch; queued work cannot renew it. */
@FunctionalInterface
public interface WebSocketDeliveryAuthorization {
  CompletableFuture<Void> execute(Function<MessageDeliveryGuard, CompletableFuture<Void>> action);
}
