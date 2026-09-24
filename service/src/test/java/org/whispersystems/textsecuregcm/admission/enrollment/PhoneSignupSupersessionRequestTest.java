// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PhoneSignupSupersessionRequestTest {
  private static final String ID = "80e5a3b0-7a89-4e43-ae40-ec9ff4aad1e7";
  private static final String CORRECTION = "80e5a3b0-7a89-4e43-ae40-ec9ff4aad1e8";
  private static final String NONCE = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  private static final String BODY = """
      {"applicationId":"%s","enrollmentNonce":"%s","phoneNumber":"+13055550123",
       "correctionId":"%s","replacementPhoneNumber":"+13055550124","replacementEnrollmentNonce":"%s"}
      """.formatted(ID, NONCE, CORRECTION, NONCE);
  private PhoneSignupSupersessionRequest parse(String body) {
    return PhoneSignupSupersessionRequest.parse(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
  }
  @Test void acceptsOnlyExactImmutableTupleAndRedactsCredentials() {
    var request = parse(BODY);
    assertThat(request.applicationId().toString()).isEqualTo(ID);
    assertThat(request.correctionId().toString()).isEqualTo(CORRECTION);
    assertThat(request.toString()).isEqualTo("PhoneSignupSupersessionRequest[redacted]");
    for (String field : new String[] {"cancelled", "phoneVerified", "replacementApplicationId", "fullName", "code"}) {
      assertThrows(IllegalArgumentException.class, () -> parse(BODY.stripTrailing().replace("}",
          ",\"" + field + "\":true}")));
    }
  }
  @Test void rejectsAmbiguityMalformedIdentifiersAndNoncanonicalCredentials() {
    for (String invalid : new String[] {BODY + "{}", "[]", " ".repeat(2049) + BODY,
        BODY.replace(ID, ID.toUpperCase()), BODY.replace(CORRECTION, "1-1-1-1-1"),
        BODY.replace(NONCE, NONCE + "="), BODY.replace("+13055550123", "3055550123"),
        BODY.replace("{", "{\"correctionId\":\"" + CORRECTION + "\","),
        BODY.replace("\"replacementPhoneNumber\"", "\"phoneNumber\"")}) {
      assertThrows(IllegalArgumentException.class, () -> parse(invalid));
    }
    assertThrows(IllegalArgumentException.class, () -> PhoneSignupSupersessionRequest.parse(
        new ByteArrayInputStream(new byte[] {(byte) 0xc3, (byte) 0x28})));
  }
}
