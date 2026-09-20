// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.reactivestreams.Publisher;
import org.whispersystems.textsecuregcm.entities.MessageProtos;

/** Durable storage of encrypted envelopes; does not decrypt message content. */
public interface PersistentMessageStore {
  void store(List<MessageProtos.Envelope> messages, UUID accountIdentifier, Device device);
  CompletableFuture<Boolean> mayHaveMessages(UUID accountIdentifier, Device device);
  CompletableFuture<Boolean> mayHaveUrgentMessages(UUID accountIdentifier, Device device);
  Publisher<MessageProtos.Envelope> load(UUID accountIdentifier, Device device, Integer pageSize);
  CompletableFuture<Optional<MessageProtos.Envelope>> deleteMessage(UUID accountIdentifier, Device device,
      UUID messageIdentifier, long serverTimestamp);
}
