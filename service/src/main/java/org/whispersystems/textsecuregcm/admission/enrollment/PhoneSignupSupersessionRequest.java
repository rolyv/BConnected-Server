// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Exact immutable correction tuple. Neither a cancellation assertion nor SMS authorization. */
public record PhoneSignupSupersessionRequest(UUID applicationId, String enrollmentNonce, String phoneNumber,
    UUID correctionId, String replacementPhoneNumber, String replacementEnrollmentNonce) {
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(3).maxStringLength(256)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  static PhoneSignupSupersessionRequest parse(InputStream input) {
    byte[] bytes = null;
    try {
      bytes = input.readNBytes(2049);
      if (bytes.length == 0 || bytes.length > 2048) throw new IllegalArgumentException();
      var body = JSON.readTree(StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString());
      if (!body.isObject()) throw new IllegalArgumentException();
      var fields = new HashSet<String>(); body.fieldNames().forEachRemaining(fields::add);
      if (!fields.equals(Set.of("applicationId", "enrollmentNonce", "phoneNumber", "correctionId",
          "replacementPhoneNumber", "replacementEnrollmentNonce"))) throw new IllegalArgumentException();
      return new PhoneSignupSupersessionRequest(id(body, "applicationId"), nonce(body, "enrollmentNonce"),
          phone(body, "phoneNumber"), id(body, "correctionId"), phone(body, "replacementPhoneNumber"),
          nonce(body, "replacementEnrollmentNonce"));
    } catch (Exception invalid) {
      throw new IllegalArgumentException("Invalid phone signup correction");
    } finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
  }

  private static String nonce(JsonNode body, String field) {
    String nonce = text(body, field);
    if (!nonce.matches("[A-Za-z0-9_-]{43}") || !Base64.getUrlEncoder().withoutPadding()
        .encodeToString(Base64.getUrlDecoder().decode(nonce)).equals(nonce)) throw new IllegalArgumentException();
    return nonce;
  }
  private static String phone(JsonNode body, String field) {
    String phone = text(body, field);
    if (!phone.matches("\\+[1-9][0-9]{1,14}")) throw new IllegalArgumentException();
    return phone;
  }
  private static UUID id(JsonNode body, String field) {
    String text = text(body, field);
    UUID id = UUID.fromString(text);
    if (!id.toString().equals(text) || id.equals(new UUID(0, 0))) throw new IllegalArgumentException();
    return id;
  }
  private static String text(JsonNode body, String field) {
    var value = body.get(field);
    if (value == null || !value.isTextual()) throw new IllegalArgumentException();
    return value.textValue();
  }
  @Override public String toString() { return "PhoneSignupSupersessionRequest[redacted]"; }
}
