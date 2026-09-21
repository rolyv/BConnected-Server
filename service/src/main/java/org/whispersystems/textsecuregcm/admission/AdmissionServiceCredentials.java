// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/** Owned runtime ADC ID token for the exact Cloud Run audience; no access-token fallback. */
final class AdmissionServiceCredentials implements AdmissionServiceClient.TokenProvider {
  private static final String SIGNAL_IDENTITY =
      "bconnected-signal@roly-dev.iam.gserviceaccount.com";
  private static final ObjectMapper JSON =
      new ObjectMapper(
              JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final IdTokenCredentials credentials;
  private final String audience;

  AdmissionServiceCredentials(
      IdTokenProvider provider, AdmissionServiceConfiguration configuration) {
    audience = configuration.origin().toString();
    credentials =
        IdTokenCredentials.newBuilder()
            .setIdTokenProvider(Objects.requireNonNull(provider))
            .setTargetAudience(audience)
            .setOptions(
                List.of(IdTokenProvider.Option.FORMAT_FULL, IdTokenProvider.Option.INCLUDE_EMAIL))
            .build();
  }

  static AdmissionServiceCredentials applicationDefault(AdmissionServiceConfiguration configuration)
      throws IOException {
    var adc = GoogleCredentials.getApplicationDefault();
    if (!(adc instanceof IdTokenProvider provider))
      throw new IOException("Runtime ID-token credentials unavailable");
    return new AdmissionServiceCredentials(provider, configuration);
  }

  @Override
  public String token() throws IOException {
    credentials.refreshIfExpired();
    var token = credentials.getIdToken();
    if (token == null) throw new IOException("Runtime ID-token credentials unavailable");
    final String value = token.getTokenValue();
    try {
      if (value == null || value.length() > 4096) throw new IllegalArgumentException();
      String[] parts = value.split("\\.", -1);
      if (parts.length != 3) throw new IllegalArgumentException();
      var claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
      if (!claims.path("aud").isTextual()
          || !audience.equals(claims.path("aud").textValue())
          || !claims.path("email").isTextual()
          || !SIGNAL_IDENTITY.equals(claims.path("email").textValue())
          || !claims.path("exp").isIntegralNumber()
          || !claims.path("exp").canConvertToLong()
          || claims.path("exp").longValue() <= Instant.now().getEpochSecond())
        throw new IllegalArgumentException();
      return value;
    } catch (IOException | RuntimeException ignored) {
      throw new IOException("Runtime ID-token identity unavailable");
    }
  }

  @Override
  public String toString() {
    return "AdmissionServiceCredentials[redacted]";
  }
}
