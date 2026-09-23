// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Minimal preapproval wire contract; it accepts no membership or verification assertions. */
public record PhoneSignupRequest(UUID applicationId, String enrollmentNonce, String phoneNumber, String code) {
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(3).maxStringLength(256)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  static PhoneSignupRequest parse(InputStream input, MobileEnrollmentParser.Operation action) {
    byte[] bytes = null;
    try {
      if (action == null || action == MobileEnrollmentParser.Operation.COMPLETE) throw new IllegalArgumentException();
      bytes = input.readNBytes(2049);
      if (bytes.length == 0 || bytes.length > 2048) throw new IllegalArgumentException();
      var body = JSON.readTree(StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString());
      if (!body.isObject()) throw new IllegalArgumentException();
      var fields = new HashSet<String>(); body.fieldNames().forEachRemaining(fields::add);
      var expected = new HashSet<>(Set.of("applicationId", "enrollmentNonce", "phoneNumber"));
      if (action == MobileEnrollmentParser.Operation.CHECK_CODE) expected.add("code");
      if (!fields.equals(expected)) throw new IllegalArgumentException();
      String application = text(body, "applicationId");
      UUID id = UUID.fromString(application);
      if (!id.toString().equals(application) || id.equals(new UUID(0, 0))) throw new IllegalArgumentException();
      String nonce = text(body, "enrollmentNonce");
      if (!nonce.matches("[A-Za-z0-9_-]{43}") || !Base64.getUrlEncoder().withoutPadding()
          .encodeToString(Base64.getUrlDecoder().decode(nonce)).equals(nonce)) throw new IllegalArgumentException();
      String phone = text(body, "phoneNumber");
      if (!phone.matches("\\+[1-9][0-9]{1,14}")) throw new IllegalArgumentException();
      String code = action == MobileEnrollmentParser.Operation.CHECK_CODE ? text(body, "code") : null;
      if (code != null && !code.matches("[0-9]{4,10}")) throw new IllegalArgumentException();
      return new PhoneSignupRequest(id, nonce, phone, code);
    } catch (Exception invalid) {
      throw new IllegalArgumentException("Invalid phone signup request");
    } finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
  }

  private static String text(JsonNode body, String field) {
    var value = body.get(field);
    if (value == null || !value.isTextual()) throw new IllegalArgumentException();
    return value.textValue();
  }
  @Override public String toString() { return "PhoneSignupRequest[redacted]"; }
}
