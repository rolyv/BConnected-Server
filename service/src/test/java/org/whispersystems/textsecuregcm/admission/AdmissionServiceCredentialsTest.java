// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.auth.oauth2.IdToken;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AdmissionServiceCredentialsTest {
  @Test
  void requestsIdTokenForExactCloudRunAudienceAndReusesUnexpiredSdkCache() throws Exception {
    String audience = AdmissionServiceConfiguration.PILOT_ORIGIN.toString();
    String jwt =
        encode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}")
            + "."
            + encode(
                "{\"aud\":\""
                    + audience
                    + "\",\"email\":\"bconnected-signal@roly-dev.iam.gserviceaccount.com\",\"exp\":"
                    + (Instant.now().getEpochSecond() + 3600)
                    + ",\"iat\":"
                    + Instant.now().getEpochSecond()
                    + "}")
            + "."
            + encode("synthetic-signature");
    var calls = new AtomicInteger();
    var credentials =
        new AdmissionServiceCredentials(
            (requestedAudience, options) -> {
              calls.incrementAndGet();
              assertThat(requestedAudience).isEqualTo(audience);
              assertThat(options)
                  .containsExactly(
                      com.google.auth.oauth2.IdTokenProvider.Option.FORMAT_FULL,
                      com.google.auth.oauth2.IdTokenProvider.Option.INCLUDE_EMAIL);
              return IdToken.create(jwt);
            },
            AdmissionServiceConfiguration.pilot());
    assertThat(credentials.token()).isEqualTo(jwt);
    assertThat(credentials.token()).isEqualTo(jwt);
    assertThat(calls.get()).isEqualTo(1);
    assertThat(credentials.toString()).isEqualTo("AdmissionServiceCredentials[redacted]");
  }

  @Test
  void rejectsWrongRuntimeIdentityOrAudienceWithoutDisclosingToken() throws Exception {
    for (String changed : java.util.List.of("email", "aud")) {
      var fields = new java.util.LinkedHashMap<String, Object>();
      fields.put("aud", AdmissionServiceConfiguration.PILOT_ORIGIN.toString());
      fields.put("email", "bconnected-signal@roly-dev.iam.gserviceaccount.com");
      fields.put("exp", Instant.now().getEpochSecond() + 3600);
      fields.put(changed, "unapproved-identity-or-audience");
      String jwt =
          encode("{\"alg\":\"RS256\"}")
              + "."
              + encode(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(fields))
              + "."
              + encode("synthetic");
      var credentials =
          new AdmissionServiceCredentials(
              (aud, options) -> IdToken.create(jwt), AdmissionServiceConfiguration.pilot());
      var error =
          org.junit.jupiter.api.Assertions.assertThrows(
              java.io.IOException.class, credentials::token);
      assertThat(error.getMessage()).isEqualTo("Runtime ID-token identity unavailable");
      assertThat(error.getCause()).isNull();
    }
  }

  private static String encode(String value) {
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }
}
