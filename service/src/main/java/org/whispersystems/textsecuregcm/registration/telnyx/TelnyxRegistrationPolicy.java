// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import java.time.Duration;

/** Explicit deployment policy; no values are silently enabled by selecting the Telnyx provider. */
public record TelnyxRegistrationPolicy(
    Duration sessionLifetime,
    Duration quotaWindow,
    int maxSessionsPerNumber,
    int maxSessionsPerSource,
    int maxSmsPerNumber,
    int maxSmsPerSession,
    int maxChecksPerNumber,
    int maxChecksPerSession,
    Duration smsCooldown,
    Duration checkCooldown) {

  public TelnyxRegistrationPolicy {
    requireDuration(sessionLifetime, Duration.ofMinutes(1), Duration.ofHours(1), "sessionLifetime");
    requireDuration(quotaWindow, sessionLifetime, Duration.ofDays(7), "quotaWindow");
    requireDuration(smsCooldown, Duration.ofSeconds(1), sessionLifetime, "smsCooldown");
    requireDuration(checkCooldown, Duration.ofSeconds(1), sessionLifetime, "checkCooldown");
    for (int limit : new int[] {maxSessionsPerNumber, maxSessionsPerSource, maxSmsPerNumber,
        maxSmsPerSession, maxChecksPerNumber, maxChecksPerSession}) {
      if (limit < 1 || limit > 10000) throw new IllegalArgumentException("Registration quota limits must be 1..10000");
    }
  }

  private static void requireDuration(final Duration value, final Duration minimum, final Duration maximum,
      final String name) {
    if (value == null || value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0
        || value.getNano() != 0) {
      throw new IllegalArgumentException(name + " must be whole seconds within the supported policy bounds");
    }
  }
}
