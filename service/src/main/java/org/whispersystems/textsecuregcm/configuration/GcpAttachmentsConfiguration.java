/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import io.dropwizard.validation.ValidationMethod;
import jakarta.validation.constraints.NotBlank;
import org.apache.commons.lang3.StringUtils;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

public record GcpAttachmentsConfiguration(@NotBlank String domain,
                                          @NotBlank String email,
                                          String pathPrefix,
                                          SecretString rsaSigningKey,
                                          boolean useIamSigning) {
  public GcpAttachmentsConfiguration(String domain, String email, String pathPrefix, SecretString rsaSigningKey) {
    this(domain, email, pathPrefix, rsaSigningKey, false);
  }

  @SuppressWarnings("unused")
  @ValidationMethod(message = "Select either IAM signing with a service-account email or a legacy RSA key")
  public boolean isSigningConfigurationValid() {
    return useIamSigning
        ? rsaSigningKey == null && email != null && email.matches("[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.gserviceaccount\\.com")
        : rsaSigningKey != null;
  }
  @SuppressWarnings("unused")
  @ValidationMethod(message = "pathPrefix must be empty or start with /")
  public boolean isPathPrefixValid() {
    return StringUtils.isEmpty(pathPrefix) || pathPrefix.startsWith("/");
  }
}
