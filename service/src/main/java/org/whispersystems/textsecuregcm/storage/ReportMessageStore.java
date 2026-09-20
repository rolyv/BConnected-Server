// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.concurrent.CompletableFuture;

/** Stores report eligibility hashes and consumes each stored hash at most once. */
public interface ReportMessageStore {
  CompletableFuture<Void> store(byte[] hash);

  boolean remove(byte[] hash);
}
