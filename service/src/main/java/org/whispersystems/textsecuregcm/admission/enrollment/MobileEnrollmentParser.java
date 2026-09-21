// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.whispersystems.textsecuregcm.admission.CanonicalRegistrationRequest;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Strict v1 wire boundary. No routes, authentication, provider calls or account writes live here. */
public final class MobileEnrollmentParser {
  public static final int MAX_BODY_BYTES = 65_536;

  public enum Operation { BEGIN, SEND_CODE, CHECK_CODE, COMPLETE, STATUS }

  private static final Set<String> ENVELOPE = Set.of("memberId", "registrationAttemptId",
      "bindingChallenge", "registrationRequest", "originalSignalAgent", "originalUserAgent");
  private static final Set<String> REGISTRATION_REQUIRED = Set.of("accountAttributes", "skipDeviceTransfer",
      "aciIdentityKey", "pniIdentityKey", "aciSignedPreKey", "pniSignedPreKey",
      "aciPqLastResortPreKey", "pniPqLastResortPreKey");
  private static final Set<String> ATTRIBUTE_REQUIRED = Set.of("fetchesMessages", "registrationId",
      "pniRegistrationId", "capabilities", "unidentifiedAccessKey", "unrestrictedUnidentifiedAccess",
      "discoverableByPhoneNumber");
  private static final Set<String> CAPABILITIES = Arrays.stream(DeviceCapability.values())
      .map(DeviceCapability::getName).collect(Collectors.toUnmodifiableSet());
  private static final ObjectMapper MAPPER = SystemMapper.configureMapper(new ObjectMapper(
      JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
          .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(12)
              .maxStringLength(MAX_BODY_BYTES).maxNumberLength(20).build()).build()))
      .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  // Upstream capability adapters recursively call readValueAs on nested objects. Trailing-token
  // validation belongs to the complete wire tree above, not those nested adapter reads.
  private static final ObjectMapper ENTITY_MAPPER = MAPPER.copy()
      .disable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  private MobileEnrollmentParser() {}

  public static final class InvalidRequestException extends IllegalArgumentException {
    private InvalidRequestException() { super("Invalid mobile enrollment request"); }
  }

  /** Reads at most 64 KiB plus one sentinel byte before parsing; caller owns stream/deadline. */
  public static MobileEnrollmentRequest parse(InputStream input, Operation operation, String number) {
    byte[] body = null;
    try {
      if (operation == null) throw new InvalidRequestException();
      body = input.readNBytes(MAX_BODY_BYTES + 1);
      if (body.length == 0 || body.length > MAX_BODY_BYTES) throw new InvalidRequestException();
      // Reject malformed UTF-8, including overlong encodings, before Jackson can accept alternatives.
      String decoded = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(body)).toString();
      JsonNode root = MAPPER.readTree(decoded);
      fields(root, ENVELOPE, operation == Operation.CHECK_CODE ? Set.of("code") : Set.of());
      String code = null;
      if (operation == Operation.CHECK_CODE) {
        code = text(root.get("code"));
        if (!code.matches("[0-9]{4,10}")) throw new InvalidRequestException();
      }
      String member = text(root.get("memberId"));
      UUID memberId = UUID.fromString(member);
      if (!memberId.toString().equals(member)
          || (memberId.getMostSignificantBits() == 0 && memberId.getLeastSignificantBits() == 0))
        throw new InvalidRequestException();
      String attempt = nonce(root.get("registrationAttemptId"));
      String challenge = nonce(root.get("bindingChallenge"));
      String signalAgent = metadata(root.get("originalSignalAgent"), 256);
      String userAgent = metadata(root.get("originalUserAgent"), 512);
      JsonNode registration = root.get("registrationRequest");
      fields(registration, REGISTRATION_REQUIRED, Set.of("apnToken", "gcmToken"));
      bool(registration.get("skipDeviceTransfer"));
      encoded(registration.get("aciIdentityKey"), false);
      encoded(registration.get("pniIdentityKey"), false);
      for (String key : Set.of("aciSignedPreKey", "pniSignedPreKey", "aciPqLastResortPreKey", "pniPqLastResortPreKey")) {
        JsonNode value = registration.get(key);
        fields(value, Set.of("keyId", "publicKey", "signature"), Set.of());
        integer(value.get("keyId"));
        encoded(value.get("publicKey"), false);
        encoded(value.get("signature"), false);
      }
      for (String kind : Set.of("apn", "gcm")) {
        JsonNode token = registration.get(kind + "Token");
        if (token != null) {
          fields(token, Set.of(kind + "RegistrationId"), Set.of());
          metadata(token.get(kind + "RegistrationId"), 4096);
        }
      }
      JsonNode attributes = registration.get("accountAttributes");
      fields(attributes, ATTRIBUTE_REQUIRED, Set.of("name", "registrationLock", "recoveryPassword"));
      for (String key : Set.of("fetchesMessages", "unrestrictedUnidentifiedAccess", "discoverableByPhoneNumber"))
        bool(attributes.get(key));
      integer(attributes.get("registrationId"));
      integer(attributes.get("pniRegistrationId"));
      encoded(attributes.get("unidentifiedAccessKey"), true);
      for (String key : Set.of("name", "recoveryPassword")) {
        JsonNode value = attributes.get(key);
        if (value != null && !value.isNull()) encoded(value, true);
      }
      JsonNode lock = attributes.get("registrationLock");
      if (lock != null && !lock.isNull()) text(lock);
      JsonNode capabilities = attributes.get("capabilities");
      fields(capabilities, Set.of(), CAPABILITIES);
      capabilities.elements().forEachRemaining(MobileEnrollmentParser::bool);
      RegistrationRequest request = ENTITY_MAPPER.treeToValue(registration, RegistrationRequest.class);
      // Validates both identity keys, signed EC/KEM keys, registration IDs and channel semantics.
      try (var ignored = CanonicalRegistrationRequest.beforeVerification(request, number, signalAgent, userAgent)) {
        return new MobileEnrollmentRequest(memberId, attempt, challenge, request, signalAgent, userAgent, code);
      }
    } catch (Exception ignored) {
      // No parser/source/input fragments in exceptions or chained causes.
      throw new InvalidRequestException();
    } finally {
      if (body != null) Arrays.fill(body, (byte) 0);
    }
  }

  private static void fields(JsonNode value, Set<String> required, Set<String> optional) {
    if (value == null || !value.isObject()) throw new InvalidRequestException();
    for (String key : required) if (!value.has(key)) throw new InvalidRequestException();
    value.fieldNames().forEachRemaining(key -> {
      if (!required.contains(key) && !optional.contains(key)) throw new InvalidRequestException();
    });
  }

  private static String text(JsonNode value) {
    if (value == null || !value.isTextual()) throw new InvalidRequestException();
    String text = value.textValue();
    if (!StandardCharsets.UTF_8.newEncoder().canEncode(text)) throw new InvalidRequestException();
    return text;
  }

  private static String metadata(JsonNode value, int limit) {
    String text = text(value);
    if (text.isEmpty() || text.getBytes(StandardCharsets.UTF_8).length > limit
        || text.codePoints().anyMatch(Character::isISOControl)) throw new InvalidRequestException();
    return text;
  }

  private static String nonce(JsonNode value) {
    String text = text(value);
    byte[] bytes = Base64.getUrlDecoder().decode(text);
    if (bytes.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text))
      throw new InvalidRequestException();
    return text;
  }

  private static void encoded(JsonNode value, boolean allowEmpty) {
    String text = text(value);
    byte[] bytes = Base64.getDecoder().decode(text);
    if ((!allowEmpty && bytes.length == 0) || !Base64.getEncoder().encodeToString(bytes).equals(text))
      throw new InvalidRequestException();
  }

  private static void bool(JsonNode value) {
    if (value == null || !value.isBoolean()) throw new InvalidRequestException();
  }

  private static void integer(JsonNode value) {
    if (value == null || !value.isIntegralNumber() || !value.canConvertToInt())
      throw new InvalidRequestException();
  }
}
