// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.time.Duration;
import java.util.UUID;

public interface PushChallengeStore {
  boolean add(UUID account, byte[] token, Duration ttl);
  boolean remove(UUID account, byte[] token);
}
