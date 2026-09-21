// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.admission.CanonicalRegistrationRequest;
import org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentParser.Operation;

class MobileEnrollmentParserTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String NUMBER = "+13055550123";

  private ObjectNode fixture() throws Exception {
    try (var input = getClass().getResourceAsStream("/admission/mobile-enrollment-v1.json")) {
      return (ObjectNode) JSON.readTree(input);
    }
  }

  private MobileEnrollmentRequest parse(JsonNode node, Operation operation) throws Exception {
    return parse(JSON.writeValueAsBytes(node), operation);
  }

  private MobileEnrollmentRequest parse(byte[] bytes, Operation operation) {
    return MobileEnrollmentParser.parse(new ByteArrayInputStream(bytes), operation, NUMBER);
  }

  private void invalid(byte[] bytes, Operation operation) {
    var error = assertThrows(MobileEnrollmentParser.InvalidRequestException.class,
        () -> parse(bytes, operation));
    assertThat(error.getMessage()).isEqualTo("Invalid mobile enrollment request");
    assertThat(error.getCause()).isNull();
  }

  @Test
  void sharedPublicFixtureMapsToActualSignedRegistrationKeysAndFrozenMetadata() throws Exception {
    for (Operation operation : List.of(Operation.BEGIN, Operation.SEND_CODE, Operation.COMPLETE, Operation.STATUS)) {
      var parsed = parse(fixture(), operation);
      assertThat(parsed.memberId().toString()).isEqualTo("00000000-0000-4000-8000-000000000001");
      assertThat(parsed.registrationRequest().deviceActivationRequest().pniPqLastResortPreKey()).isPresent();
      assertThat(parsed.registrationRequest().accountAttributes().getPhoneNumberIdentityRegistrationId()).isPresent();
      assertThat(parsed.originalSignalAgent()).isEqualTo("BConnected-iOS");
      assertThat(parsed.originalUserAgent()).isEqualTo("BConnected/0.1 iOS");
      assertThat(parsed.code()).isNull();
      assertThat(parsed.toString()).isEqualTo("MobileEnrollmentRequest[redacted]");
      try (var canonical = CanonicalRegistrationRequest.beforeVerification(parsed.registrationRequest(),
          NUMBER, parsed.originalSignalAgent(), parsed.originalUserAgent())) {
        assertThat(canonical.keyCommitment()).hasSize(64);
      }
    }
  }

  @Test
  void sharedNegativeMutationsRejectClaimsCoercionUnknownFieldsAndInvalidKeys() throws Exception {
    try (var input = getClass().getResourceAsStream("/admission/mobile-enrollment-v1-invalid.json")) {
      for (JsonNode mutation : JSON.readTree(input)) {
        ObjectNode root = fixture();
        ObjectNode target = root;
        JsonNode path = mutation.get("path");
        for (int i = 0; i < path.size() - 1; i++) target = (ObjectNode) target.get(path.get(i).textValue());
        target.set(path.get(path.size() - 1).textValue(), mutation.get("value"));
        invalid(JSON.writeValueAsBytes(root), Operation.BEGIN);
      }
    }
  }

  @Test
  void codeIsRequiredOnlyOnCheckAndIsAnAsciiString() throws Exception {
    for (String code : List.of("0000", "1234567890")) {
      var root = fixture().put("code", code);
      assertThat(parse(root, Operation.CHECK_CODE).code()).isEqualTo(code);
      for (Operation operation : List.of(Operation.BEGIN, Operation.SEND_CODE, Operation.COMPLETE, Operation.STATUS))
        invalid(JSON.writeValueAsBytes(root), operation);
    }
    for (String code : List.of("123", "12345678901", "１２３４", "1234\n", " 1234", ""))
      invalid(JSON.writeValueAsBytes(fixture().put("code", code)), Operation.CHECK_CODE);
    invalid(JSON.writeValueAsBytes(fixture().put("code", 1234)), Operation.CHECK_CODE);
    invalid(JSON.writeValueAsBytes(fixture()), Operation.CHECK_CODE);
  }

  @Test
  void duplicatesTrailingValuesNullsAndMalformedUnicodeAreRejected() throws Exception {
    String body = JSON.writeValueAsString(fixture());
    for (String invalid : List.of(
        body.replaceFirst("\\{", "{\"memberId\":\"00000000-0000-4000-8000-000000000001\","),
        body.replace("\"fetchesMessages\":true", "\"fetchesMessages\":true,\"fetchesMessages\":true"),
        body + " {}", "null", "[]", "{}",
        body.replace("BConnected-iOS", "\\ud800")))
      invalid(invalid.getBytes(StandardCharsets.UTF_8), Operation.BEGIN);
    invalid(new byte[] {(byte) 0xc0, (byte) 0xaf}, Operation.BEGIN);
    invalid(body.getBytes(StandardCharsets.UTF_16LE), Operation.BEGIN);
  }

  @Test
  void boundsApplyBeforeParsingAndDoNotDrainOversizedStream() throws Exception {
    var count = new AtomicInteger();
    InputStream unbounded = new InputStream() {
      @Override public int read() { count.incrementAndGet(); return ' '; }
    };
    assertThrows(MobileEnrollmentParser.InvalidRequestException.class,
        () -> MobileEnrollmentParser.parse(unbounded, Operation.BEGIN, NUMBER));
    assertThat(count.get()).isEqualTo(MobileEnrollmentParser.MAX_BODY_BYTES + 1);
    byte[] original = JSON.writeValueAsBytes(fixture());
    byte[] bounded = new byte[MobileEnrollmentParser.MAX_BODY_BYTES];
    java.util.Arrays.fill(bounded, (byte) ' ');
    System.arraycopy(original, 0, bounded, 0, original.length);
    assertThat(parse(bounded, Operation.STATUS)).isNotNull();
    invalid(new byte[0], Operation.BEGIN);
  }

  @Test
  void metadataLimitsUseUtf8BytesAndMissingFieldsNeverDefaultSilently() throws Exception {
    assertThat(parse(fixture().put("originalSignalAgent", "é".repeat(128)), Operation.BEGIN)).isNotNull();
    invalid(JSON.writeValueAsBytes(fixture().put("originalSignalAgent", "é".repeat(129))), Operation.BEGIN);
    invalid(JSON.writeValueAsBytes(fixture().put("originalUserAgent", "x".repeat(513))), Operation.BEGIN);
    var root = fixture();
    ((ObjectNode) root.get("registrationRequest").get("accountAttributes")).remove("discoverableByPhoneNumber");
    invalid(JSON.writeValueAsBytes(root), Operation.BEGIN);
  }

  @Test
  void apnsVariantUsesTheRealActivationShape() throws Exception {
    var root = fixture();
    var registration = (ObjectNode) root.get("registrationRequest");
    ((ObjectNode) registration.get("accountAttributes")).put("fetchesMessages", false);
    registration.putObject("apnToken").put("apnRegistrationId", "synthetic-not-a-provider-token");
    assertThat(parse(root, Operation.BEGIN).registrationRequest().deviceActivationRequest().apnToken()).isPresent();
    ((ObjectNode) registration.get("apnToken")).put("unknown", true);
    invalid(JSON.writeValueAsBytes(root), Operation.BEGIN);
  }
}
