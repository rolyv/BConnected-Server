// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Strict application admission verification; never changes libsignal cryptography. */
public final class AdmissionPermitVerifier {
  private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;
  private static final Set<String> HEADER = Set.of("alg", "kid", "typ");
  private static final Set<String> CLAIMS =
      Set.of(
          "iss",
          "aud",
          "jti",
          "memberId",
          "approvalEpoch",
          "signalOperationId",
          "registrationAttemptHash",
          "serverVerificationSessionHash",
          "deviceKeyCommitment",
          "phoneBinding",
          "serverRequestCommitment",
          "iat",
          "exp");
  private static final ObjectMapper JSON =
      new ObjectMapper(
              JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final Map<String, PublicKey> keys;
  private final Clock clock;

  /** Construct this from the persisted, server-owned operation, never an HTTP DTO. */
  public record ExpectedBinding(
      UUID memberId,
      long approvalEpoch,
      UUID signalOperationId,
      String registrationAttemptHash,
      String serverVerificationSessionHash,
      String deviceKeyCommitment,
      String phoneBinding,
      String serverRequestCommitment,
      String canonicalVerifiedNumber) {
    public ExpectedBinding {
      requireUuid(memberId);
      requireUuid(signalOperationId);
      if (approvalEpoch < 0 || approvalEpoch > MAX_SAFE_INTEGER)
        throw new IllegalArgumentException("Invalid approval epoch");
      for (String hash :
          new String[] {
            registrationAttemptHash,
            serverVerificationSessionHash,
            deviceKeyCommitment,
            phoneBinding,
            serverRequestCommitment
          }) requireHash(hash);
      if (canonicalVerifiedNumber == null
          || !canonicalVerifiedNumber.matches("\\+[1-9][0-9]{1,14}")) {
        throw new IllegalArgumentException("A canonical server-verified phone number is required");
      }
    }
  }

  /**
   * No public constructor or deserialization factory: only signature verification creates this
   * capability.
   */
  public static final class VerifiedPermit {
    private final String permitId;
    private final ExpectedBinding binding;
    private final long issuedAt;
    private final long expiresAt;

    private VerifiedPermit(
        String permitId, ExpectedBinding binding, long issuedAt, long expiresAt) {
      this.permitId = permitId;
      this.binding = binding;
      this.issuedAt = issuedAt;
      this.expiresAt = expiresAt;
    }

    public String permitId() {
      return permitId;
    }

    public ExpectedBinding binding() {
      return binding;
    }

    public long issuedAt() {
      return issuedAt;
    }

    public long expiresAt() {
      return expiresAt;
    }
  }

  public static final class InvalidPermitException extends RuntimeException {
    private InvalidPermitException() {
      super("Admission permit is invalid");
    }
  }

  public AdmissionPermitVerifier(Map<String, PublicKey> keys, Clock clock) {
    if (keys == null || keys.isEmpty())
      throw new IllegalArgumentException("Pinned admission keys are required");
    keys.forEach(
        (id, key) -> {
          if (id == null
              || !id.matches("[A-Za-z0-9_-]{1,64}")
              || !(key instanceof EdECPublicKey ed)
              || !ed.getParams().getName().equals("Ed25519")) {
            throw new IllegalArgumentException("Only pinned Ed25519 admission keys are supported");
          }
        });
    this.keys = Map.copyOf(keys);
    this.clock = Objects.requireNonNull(clock);
  }

  public VerifiedPermit verify(String compact, ExpectedBinding expected) {
    Objects.requireNonNull(expected);
    try {
      if (compact == null || compact.length() > 8192) throw new IllegalArgumentException();
      String[] parts = compact.split("\\.", -1);
      if (parts.length != 3) throw new IllegalArgumentException();
      byte[] headerBytes = decode(parts[0], 1024);
      byte[] payloadBytes = decode(parts[1], 4096);
      byte[] signatureBytes = decode(parts[2], 64);
      if (signatureBytes.length != 64) throw new IllegalArgumentException();
      JsonNode header = JSON.readTree(headerBytes);
      exactFields(header, HEADER);
      if (!string(header, "alg").equals("EdDSA")
          || !string(header, "typ").equals("bconnected-admission-v1")) {
        throw new IllegalArgumentException();
      }
      PublicKey key = keys.get(string(header, "kid"));
      if (key == null) throw new IllegalArgumentException();
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key);
      verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      if (!verifier.verify(signatureBytes)) throw new IllegalArgumentException();

      JsonNode claims = JSON.readTree(payloadBytes);
      exactFields(claims, CLAIMS);
      if (!string(claims, "iss").equals("bconnected-community")
          || !string(claims, "aud").equals("bconnected-signal-registration"))
        throw new IllegalArgumentException();
      String id = string(claims, "jti");
      if (decode(id, 32).length != 32) throw new IllegalArgumentException();
      ExpectedBinding actual =
          new ExpectedBinding(
              uuid(claims, "memberId"),
              integer(claims, "approvalEpoch"),
              uuid(claims, "signalOperationId"),
              string(claims, "registrationAttemptHash"),
              string(claims, "serverVerificationSessionHash"),
              string(claims, "deviceKeyCommitment"),
              string(claims, "phoneBinding"),
              string(claims, "serverRequestCommitment"),
              expected.canonicalVerifiedNumber());
      if (!actual.equals(expected)) throw new IllegalArgumentException();
      long issued = integer(claims, "iat");
      long expires = integer(claims, "exp");
      long now = clock.instant().getEpochSecond();
      if (issued > now + 5 || expires <= now || expires <= issued || expires - issued > 30) {
        throw new IllegalArgumentException();
      }
      return new VerifiedPermit(id, actual, issued, expires);
    } catch (Exception ignored) {
      // Never retain a JWT/parser exception that can disclose proof or payload fragments.
      throw new InvalidPermitException();
    }
  }

  static byte[] decode(String value, int maximumBytes) {
    if (!value.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException();
    byte[] decoded = Base64.getUrlDecoder().decode(value);
    if (decoded.length > maximumBytes
        || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
      throw new IllegalArgumentException();
    }
    return decoded;
  }

  private static void exactFields(JsonNode value, Set<String> expected) {
    if (value == null || !value.isObject()) throw new IllegalArgumentException();
    Set<String> actual = new HashSet<>();
    value.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(expected)) throw new IllegalArgumentException();
  }

  private static String string(JsonNode object, String field) {
    JsonNode value = object.get(field);
    if (value == null || !value.isTextual()) throw new IllegalArgumentException();
    return value.textValue();
  }

  private static long integer(JsonNode object, String field) {
    JsonNode value = object.get(field);
    if (value == null
        || !value.isIntegralNumber()
        || !value.canConvertToLong()
        || value.longValue() < 0
        || value.longValue() > MAX_SAFE_INTEGER) throw new IllegalArgumentException();
    return value.longValue();
  }

  private static UUID uuid(JsonNode object, String field) {
    String value = string(object, field);
    UUID id = UUID.fromString(value);
    requireUuid(id);
    if (!id.toString().equals(value)) throw new IllegalArgumentException();
    return id;
  }

  private static void requireUuid(UUID value) {
    if (value == null || value.equals(new UUID(0, 0)))
      throw new IllegalArgumentException("A non-nil identifier is required");
  }

  private static void requireHash(String value) {
    if (value == null || !value.matches("[a-f0-9]{64}"))
      throw new IllegalArgumentException("Invalid binding commitment");
  }
}
