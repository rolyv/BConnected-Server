// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.ExpectedBinding;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.InvalidPermitException;
import org.whispersystems.textsecuregcm.util.MutableClock;

class AdmissionPermitVerifierTest {
  private KeyPair key;
  private MutableClock clock;
  private ExpectedBinding expected;
  private AdmissionPermitVerifier verifier;
  private Map<String, Object> claims;

  @BeforeEach
  void setup() throws Exception {
    key = AdmissionTestData.keys();
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    expected = AdmissionTestData.binding("+18005550100");
    verifier = new AdmissionPermitVerifier(Map.of("test-key", key.getPublic()), clock);
    claims =
        AdmissionTestData.claims(
            expected, AdmissionTestData.id(), clock.instant().getEpochSecond());
  }

  private String signed() throws Exception {
    return AdmissionTestData.sign(key, AdmissionTestData.header(), claims);
  }

  private void rejects(String compact) {
    var failure =
        assertThrows(InvalidPermitException.class, () -> verifier.verify(compact, expected));
    assertThat(failure.getMessage()).isEqualTo("Admission permit is invalid");
    assertThat(failure.getCause()).isNull();
  }

  @Test
  void verifiesExactSignedBindingsAndOnlyVerifierCanConstructCapability() throws Exception {
    var result = verifier.verify(signed(), expected);
    assertThat(result.binding()).isEqualTo(expected);
    assertThat(result.permitId()).isEqualTo(claims.get("jti"));
    assertThat(result.expiresAt() - result.issuedAt()).isEqualTo(30);
    assertThat(AdmissionPermitVerifier.VerifiedPermit.class.getDeclaredConstructors())
        .allMatch(constructor -> Modifier.isPrivate(constructor.getModifiers()));
  }

  @Test
  void acceptsActualNodeIssuerInteroperabilityVector() throws Exception {
    try (var stream = getClass().getResourceAsStream("/admission/node-issued-permit.json")) {
      var fixture = AdmissionTestData.JSON.readTree(stream);
      var fields = fixture.get("binding");
      var publicKey =
          KeyFactory.getInstance("Ed25519")
              .generatePublic(
                  new X509EncodedKeySpec(
                      Base64.getDecoder().decode(fixture.get("publicKeySpkiBase64").textValue())));
      clock.setTimeInstant(Instant.ofEpochMilli(fixture.get("issuedAtMs").longValue()));
      var nodeVerifier =
          new AdmissionPermitVerifier(Map.of(fixture.get("kid").textValue(), publicKey), clock);
      var binding =
          new ExpectedBinding(
              UUID.fromString(fields.get("memberId").textValue()),
              fields.get("approvalEpoch").longValue(),
              UUID.fromString(fields.get("signalOperationId").textValue()),
              fields.get("registrationAttemptHash").textValue(),
              fields.get("serverVerificationSessionHash").textValue(),
              fields.get("deviceKeyCommitment").textValue(),
              fields.get("phoneBinding").textValue(),
              fields.get("serverRequestCommitment").textValue(),
              "+18005550100");
      var verified = nodeVerifier.verify(fixture.get("assertion").textValue(), binding);
      assertThat(verified.permitId()).isEqualTo(fixture.get("permitId").textValue());
      assertThat(verified.expiresAt()).isEqualTo(fixture.get("expiresAt").longValue() / 1000);
    }
  }

  @Test
  void rejectsSignatureForgeryAndPayloadTampering() throws Exception {
    rejects(AdmissionTestData.sign(AdmissionTestData.keys(), AdmissionTestData.header(), claims));
    String good = signed();
    claims.put("approvalEpoch", 2);
    String payload = AdmissionTestData.encode(AdmissionTestData.JSON.writeValueAsBytes(claims));
    rejects(good.split("\\.")[0] + "." + payload + "." + good.split("\\.")[2]);
  }

  @Test
  void rejectsEveryChangedServerOwnedBinding() throws Exception {
    for (String name :
        List.of(
            "memberId",
            "approvalEpoch",
            "signalOperationId",
            "registrationAttemptHash",
            "serverVerificationSessionHash",
            "deviceKeyCommitment",
            "phoneBinding",
            "serverRequestCommitment")) {
      var original = claims.get(name);
      claims.put(
          name,
          name.equals("approvalEpoch")
              ? 2
              : name.endsWith("Id") ? UUID.randomUUID().toString() : AdmissionTestData.hash(99));
      rejects(signed());
      claims.put(name, original);
    }
  }

  @Test
  void rejectsWrongAlgorithmKeyTypeKeyIdAndTokenType() throws Exception {
    for (var change :
        List.of(
            Map.of("alg", "none"),
            Map.of("alg", "HS256"),
            Map.of("alg", "Ed25519"),
            Map.of("kid", "unknown"),
            Map.of("typ", "JWT"))) {
      var header = AdmissionTestData.header();
      header.putAll(change);
      rejects(AdmissionTestData.sign(key, header, claims));
    }
    var ec = KeyPairGenerator.getInstance("EC").generateKeyPair();
    assertThrows(
        IllegalArgumentException.class,
        () -> new AdmissionPermitVerifier(Map.of("test-key", ec.getPublic()), clock));
    assertThrows(
        IllegalArgumentException.class, () -> new AdmissionPermitVerifier(Map.of(), clock));
  }

  @Test
  void rejectsUnknownMissingAndDuplicateHeaderOrClaimFields() throws Exception {
    var header = AdmissionTestData.header();
    header.put("jku", "https://attacker.invalid/key");
    rejects(AdmissionTestData.sign(key, header, claims));
    claims.put("role", "admin");
    rejects(signed());
    claims.remove("role");
    for (String name : List.copyOf(claims.keySet())) {
      var original = claims.remove(name);
      rejects(signed());
      claims.put(name, original);
    }
    String json = AdmissionTestData.JSON.writeValueAsString(claims);
    rejects(
        AdmissionTestData.sign(
            key,
            AdmissionTestData.JSON.writeValueAsString(AdmissionTestData.header()),
            json.substring(0, json.length() - 1) + ",\"iss\":\"bconnected-community\"}"));
    rejects(
        AdmissionTestData.sign(
            key,
            "{\"alg\":\"EdDSA\",\"alg\":\"EdDSA\",\"kid\":\"test-key\",\"typ\":\"bconnected-admission-v1\"}",
            json));
    rejects(
        AdmissionTestData.sign(
            key,
            AdmissionTestData.JSON.writeValueAsString(AdmissionTestData.header()),
            json + " {}"));
  }

  @Test
  void rejectsIssuerAudienceArraysAndNumericCoercion() throws Exception {
    for (String field : List.of("iss", "aud")) {
      var original = claims.get(field);
      claims.put(field, List.of(original));
      rejects(signed());
      claims.put(field, "wrong");
      rejects(signed());
      claims.put(field, original);
    }
    for (String field : List.of("iat", "exp", "approvalEpoch")) {
      var original = claims.get(field);
      for (Object bad : List.of(original.toString(), 1.0, -1, 9_007_199_254_740_992L)) {
        claims.put(field, bad);
        rejects(signed());
      }
      claims.put(field, original);
    }
  }

  @Test
  void requiresCanonicalBase64UuidAndHashEncodings() throws Exception {
    String valid = signed();
    for (String malformed :
        List.of(
            valid + ".extra",
            "Bearer " + valid,
            valid + "=",
            "." + valid,
            valid.replaceFirst("\\.", "=."),
            "x".repeat(8193))) rejects(malformed);
    for (String field : List.of("memberId", "signalOperationId")) {
      var original = claims.get(field);
      for (String bad :
          List.of(
              "ABCDEFAB-1234-4234-8234-ABCDEFABCDEF",
              "00000000-0000-0000-0000-000000000000",
              "1-1-1-1-1")) {
        claims.put(field, bad);
        rejects(signed());
      }
      claims.put(field, original);
    }
    claims.put("jti", AdmissionTestData.id() + "=");
    rejects(signed());
    claims.put("jti", "A".repeat(42) + "B");
    rejects(signed());
    claims.put("jti", AdmissionTestData.id());
    claims.put("deviceKeyCommitment", "F".repeat(64));
    rejects(signed());
  }

  @Test
  void enforcesStrictExpiryThirtySecondLifetimeAndFutureIssueBound() throws Exception {
    long now = clock.instant().getEpochSecond();
    for (long[] times :
        List.of(
            new long[] {now - 1, now},
            new long[] {now, now + 31},
            new long[] {now + 6, now + 30},
            new long[] {now, now},
            new long[] {now + 6, now + 36})) {
      claims.put("iat", times[0]);
      claims.put("exp", times[1]);
      rejects(signed());
    }
    claims.put("iat", now + 5);
    claims.put("exp", now + 35);
    assertThat(verifier.verify(signed(), expected).expiresAt()).isEqualTo(now + 35);
    claims.put("iat", now);
    claims.put("exp", now + 1);
    String current = signed();
    verifier.verify(current, expected);
    clock.setTimeInstant(Instant.ofEpochSecond(now + 1));
    rejects(current);
  }

  @Test
  void neverIncludesMalformedTokenOrClaimValuesInErrors() {
    rejects("private-token-do-not-log");
  }

  @Test
  void requestCommitmentIsKeyedDomainSeparatedAndLengthFramed() {
    byte[] ownedKey = new byte[32];
    ownedKey[0] = 7;
    var commitment = new RegistrationRequestCommitment(ownedKey);
    String first =
        commitment.compute(
            "request-A".getBytes(StandardCharsets.UTF_8),
            "salted-verifier".getBytes(StandardCharsets.UTF_8));
    assertThat(first).matches("[a-f0-9]{64}");
    assertThat(
            commitment.compute(
                "request-B".getBytes(StandardCharsets.UTF_8),
                "salted-verifier".getBytes(StandardCharsets.UTF_8)))
        .isNotEqualTo(first);
    assertThat(
            commitment.compute(
                "request-A".getBytes(StandardCharsets.UTF_8),
                "other-verifier".getBytes(StandardCharsets.UTF_8)))
        .isNotEqualTo(first);
    assertThat(commitment.compute(new byte[] {1}, new byte[] {2, 3}))
        .isNotEqualTo(commitment.compute(new byte[] {1, 2}, new byte[] {3}));
    ownedKey[0] = 9;
    assertThat(
            commitment.compute(
                "request-A".getBytes(StandardCharsets.UTF_8),
                "salted-verifier".getBytes(StandardCharsets.UTF_8)))
        .isEqualTo(first);
    assertThat(
            new RegistrationRequestCommitment(ownedKey)
                .compute(
                    "request-A".getBytes(StandardCharsets.UTF_8),
                    "salted-verifier".getBytes(StandardCharsets.UTF_8)))
        .isNotEqualTo(first);
    assertThrows(
        IllegalArgumentException.class, () -> new RegistrationRequestCommitment(new byte[31]));
  }
}
