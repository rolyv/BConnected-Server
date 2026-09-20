// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import java.time.Duration;
import java.util.Objects;
import java.util.UUID;

/** The environment variable should be supplied by a GCP Secret Manager secret reference at deployment. */
public record TelnyxVerifyConfiguration(String apiKeyEnvironmentVariable, UUID verifyProfileId,
                                        Duration verificationTimeout) {
  public TelnyxVerifyConfiguration {
    if (apiKeyEnvironmentVariable == null) apiKeyEnvironmentVariable = "TELNYX_API_KEY";
    if (!apiKeyEnvironmentVariable.matches("[A-Z][A-Z0-9_]{0,127}")) {
      throw new IllegalArgumentException("Invalid Telnyx API key environment variable name");
    }
    Objects.requireNonNull(verifyProfileId, "Telnyx Verify profile ID is required");
    if (verificationTimeout == null) verificationTimeout = Duration.ofMinutes(5);
    TelnyxVerifyClient.validateVerificationLifetime(verificationTimeout);
  }

  public TelnyxVerifyClient build() {
    final String key = System.getenv(apiKeyEnvironmentVariable);
    TelnyxVerifyClient.validateApiKey(key);
    return new TelnyxVerifyClient(verifyProfileId, () -> key, verificationTimeout);
  }
}
