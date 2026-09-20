// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
public interface ChangeNumberWaitingPeriodStore {
  void setExpiration(UUID account, Instant expiration);
  Optional<Instant> getExpiration(UUID account);
  void delete(UUID account);
}
