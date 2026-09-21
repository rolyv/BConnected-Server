// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Binds a persisted server operation to its complete request and salted authentication verifier.
 */
public final class RegistrationRequestCommitment {
  private final SecretKeySpec key;

  public RegistrationRequestCommitment(byte[] key) {
    if (key == null || key.length < 32)
      throw new IllegalArgumentException("An owned admission request key is required");
    this.key = new SecretKeySpec(key.clone(), "HmacSHA256");
  }

  public String compute(byte[] canonicalRequest, byte[] authenticationVerifierBinding) {
    if (canonicalRequest == null
        || canonicalRequest.length == 0
        || canonicalRequest.length > 1_048_576
        || authenticationVerifierBinding == null
        || authenticationVerifierBinding.length == 0
        || authenticationVerifierBinding.length > 4096)
      throw new IllegalArgumentException("Invalid server request binding");
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(key);
      mac.update("bconnected.registration-request.v1\0".getBytes(StandardCharsets.UTF_8));
      frame(mac, canonicalRequest);
      frame(mac, authenticationVerifierBinding);
      return HexFormat.of().formatHex(mac.doFinal());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Admission commitment unavailable");
    }
  }

  private static void frame(Mac mac, byte[] value) {
    mac.update(ByteBuffer.allocate(4).putInt(value.length).array());
    mac.update(value);
  }
}
