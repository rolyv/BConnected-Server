// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.ExpectedBinding;

final class AdmissionTestData {
  static final ObjectMapper JSON = new ObjectMapper();

  static KeyPair keys() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  static String id() {
    return encode(
        UUID.randomUUID().toString().replace("-", "").getBytes(StandardCharsets.US_ASCII));
  }

  static String hash(int value) {
    return "%064x".formatted(value);
  }

  static ExpectedBinding binding(String number) {
    return new ExpectedBinding(
        UUID.randomUUID(),
        1,
        UUID.randomUUID(),
        hash(1),
        hash(2),
        hash(3),
        hash(4),
        hash(5),
        number);
  }

  static Map<String, Object> header() {
    return new LinkedHashMap<>(
        Map.of("alg", "EdDSA", "kid", "test-key", "typ", "bconnected-admission-v1"));
  }

  static Map<String, Object> claims(ExpectedBinding binding, String id, long now) {
    var values = new LinkedHashMap<String, Object>();
    values.put("iss", "bconnected-community");
    values.put("aud", "bconnected-signal-registration");
    values.put("jti", id);
    values.put("memberId", binding.memberId().toString());
    values.put("approvalEpoch", binding.approvalEpoch());
    values.put("signalOperationId", binding.signalOperationId().toString());
    values.put("registrationAttemptHash", binding.registrationAttemptHash());
    values.put("serverVerificationSessionHash", binding.serverVerificationSessionHash());
    values.put("deviceKeyCommitment", binding.deviceKeyCommitment());
    values.put("phoneBinding", binding.phoneBinding());
    values.put("serverRequestCommitment", binding.serverRequestCommitment());
    values.put("iat", now);
    values.put("exp", now + 30);
    return values;
  }

  static String sign(KeyPair keys, Map<String, Object> header, Map<String, Object> claims)
      throws Exception {
    return sign(keys, JSON.writeValueAsString(header), JSON.writeValueAsString(claims));
  }

  static String sign(KeyPair keys, String header, String claims) throws Exception {
    String payload =
        encode(header.getBytes(StandardCharsets.UTF_8))
            + "."
            + encode(claims.getBytes(StandardCharsets.UTF_8));
    var signature = Signature.getInstance("Ed25519");
    signature.initSign(keys.getPrivate());
    signature.update(payload.getBytes(StandardCharsets.US_ASCII));
    return payload + "." + encode(signature.sign());
  }

  static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
