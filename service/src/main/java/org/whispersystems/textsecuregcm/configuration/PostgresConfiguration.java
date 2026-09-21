// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;

/** Required native storage configuration. Production passwords are read from the environment. */
public record PostgresConfiguration(
    @NotBlank String jdbcUrl,
    @NotBlank String username,
    String passwordEnvironmentVariable,
    @Min(1) @Max(30) int maximumPoolSize,
    Duration messageRetention,
    Duration recoveryRetention) {
  public PostgresConfiguration(String jdbcUrl, String username, String passwordEnvironmentVariable, int maximumPoolSize) {
    this(jdbcUrl, username, passwordEnvironmentVariable, maximumPoolSize, null, null);
  }
  public PostgresConfiguration {
    if (maximumPoolSize == 0) maximumPoolSize = 5;
    for (Duration retention : new Duration[] {messageRetention, recoveryRetention}) {
      if (retention != null && (retention.isNegative() || retention.isZero())) {
        throw new IllegalArgumentException("PostgreSQL retention durations must be positive");
      }
    }
  }
}
