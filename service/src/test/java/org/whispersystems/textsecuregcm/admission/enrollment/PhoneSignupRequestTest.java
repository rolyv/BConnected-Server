// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PhoneSignupRequestTest {
  private static final String ID = "80e5a3b0-7a89-4e43-ae40-ec9ff4aad1e7";
  private static final String NONCE = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  private static final String BODY = "{\"applicationId\":\"" + ID + "\",\"enrollmentNonce\":\"" + NONCE
      + "\",\"phoneNumber\":\"+13055550123\"}";
  private PhoneSignupRequest parse(String body, MobileEnrollmentParser.Operation action) {
    return PhoneSignupRequest.parse(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), action);
  }

  @Test void acceptsOnlyPhoneChallengeInputsAndNeverClientApprovalAssertions() {
    var request = parse(BODY, MobileEnrollmentParser.Operation.BEGIN);
    assertThat(request.applicationId().toString()).isEqualTo(ID);
    assertThat(request.toString()).isEqualTo("PhoneSignupRequest[redacted]");
    for (String extra : new String[] {"memberId", "phoneVerified", "approved", "registrationAuthorized", "code"}) {
      String forged = BODY.substring(0, BODY.length()-1) + ",\"" + extra + "\":true}";
      assertThrows(IllegalArgumentException.class, () -> parse(forged, MobileEnrollmentParser.Operation.BEGIN));
    }
    String code = BODY.substring(0, BODY.length()-1) + ",\"code\":\"123456\"}";
    assertThat(parse(code, MobileEnrollmentParser.Operation.CHECK_CODE).code()).isEqualTo("123456");
    assertThrows(IllegalArgumentException.class, () -> parse(BODY, MobileEnrollmentParser.Operation.CHECK_CODE));
    assertThrows(IllegalArgumentException.class, () -> parse(BODY, MobileEnrollmentParser.Operation.COMPLETE));
  }

  @Test void rejectsAmbiguousOrOversizedJsonAndNoncanonicalIdentifiers() {
    for (String malformed : new String[] {BODY + " {}", BODY.replace("{", "{\"applicationId\":\"" + ID + "\","),
        BODY.replace(ID, "1-1-1-1-1"), BODY.replace(ID, ID.toUpperCase()),
        BODY.replace(NONCE, NONCE + "="), BODY.replace("+13055550123", "3055550123"),
        " ".repeat(2049) + BODY, "[]"})
      assertThrows(IllegalArgumentException.class, () -> parse(malformed, MobileEnrollmentParser.Operation.BEGIN));
    byte[] invalidUtf8 = {(byte) 0xc3, (byte) 0x28};
    assertThrows(IllegalArgumentException.class, () -> PhoneSignupRequest.parse(new ByteArrayInputStream(invalidUtf8), MobileEnrollmentParser.Operation.BEGIN));
  }
}
