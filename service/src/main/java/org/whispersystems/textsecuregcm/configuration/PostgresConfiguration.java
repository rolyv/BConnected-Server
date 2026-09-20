// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/** Optional during the incremental migration. Credentials never appear in YAML. */
public record PostgresConfiguration(
    @NotBlank String jdbcUrl,
    @NotBlank String username,
    String passwordEnvironmentVariable,
    @Min(1) @Max(30) int maximumPoolSize) {
  public PostgresConfiguration {
    if (maximumPoolSize == 0) maximumPoolSize = 5;
  }
}
