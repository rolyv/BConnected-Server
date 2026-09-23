// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;

/** Explicit two-member enrollment composition. Absence leaves the existing pilot closed. */
public record DmAlphaConfiguration(Set<UUID> memberIds, Map<UUID, String> memberPhoneBindings, SecretBytes requestCommitmentKey,
    SecretBytes phoneBindingKey, Map<String, String> admissionPublicKeys) {
  public DmAlphaConfiguration {
    if (memberIds == null || memberIds.size() != 2 || memberIds.contains(new UUID(0, 0))
        || requestCommitmentKey == null || requestCommitmentKey.value().length != 32
        || phoneBindingKey == null || phoneBindingKey.value().length != 32
        || java.security.MessageDigest.isEqual(requestCommitmentKey.value(), phoneBindingKey.value()))
      throw new IllegalArgumentException("Explicit two-member alpha and independent owned keys required");
    memberIds = Set.copyOf(memberIds);
    if (memberPhoneBindings == null || !memberPhoneBindings.keySet().equals(memberIds)
        || memberPhoneBindings.values().stream().anyMatch(value -> value == null || !value.matches("[a-f0-9]{64}"))
        || Set.copyOf(memberPhoneBindings.values()).size() != 2)
      throw new IllegalArgumentException("Each alpha member requires a distinct owned phone binding");
    memberPhoneBindings = Map.copyOf(memberPhoneBindings);
    admissionPublicKeys = Map.copyOf(admissionPublicKeys);
    parseKeys(admissionPublicKeys);
  }

  public Map<String, PublicKey> permitKeys() { return parseKeys(admissionPublicKeys); }

  /** Eligibility only. Native SMS verification must still prove possession of this exact number. */
  public boolean allowsPhone(UUID memberId, String number) {
    if (memberId == null) return false;
    String expected = memberPhoneBindings.get(memberId);
    if (expected == null || number == null || !number.matches("\\+[1-9][0-9]{1,14}")) return false;
    try {
      var mac = javax.crypto.Mac.getInstance("HmacSHA256");
      mac.init(new javax.crypto.spec.SecretKeySpec(phoneBindingKey.value(), "HmacSHA256"));
      mac.update("bconnected.phone.v1\0".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return java.security.MessageDigest.isEqual(java.util.HexFormat.of().parseHex(expected),
          mac.doFinal(number.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException impossible) {
      throw new IllegalStateException("Phone eligibility unavailable");
    }
  }

  private static Map<String, PublicKey> parseKeys(Map<String, String> pins) {
    try {
      if (pins.isEmpty() || pins.size() > 2) throw new IllegalArgumentException();
      var keys = new HashMap<String, PublicKey>();
      for (var pin : pins.entrySet()) {
        if (!pin.getKey().matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException();
        var bytes = Base64.getDecoder().decode(pin.getValue());
        if (bytes.length != 44 || !Base64.getEncoder().encodeToString(bytes).equals(pin.getValue()))
          throw new IllegalArgumentException();
        var key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(bytes));
        if (!java.util.Arrays.equals(bytes, key.getEncoded())) throw new IllegalArgumentException();
        keys.put(pin.getKey(), key);
      }
      return Map.copyOf(keys);
    } catch (Exception invalid) {
      throw new IllegalArgumentException("Explicit canonical Ed25519 admission pins required");
    }
  }

  @Override public String toString() { return "DmAlphaConfiguration[redacted]"; }
}
