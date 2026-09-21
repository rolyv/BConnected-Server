// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.nio.charset.StandardCharsets;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;
import org.whispersystems.textsecuregcm.storage.Device;

/** The existing Signal salted token verifier, never a persisted plaintext password. */
final class RegistrationAuthentication {
  private final SaltedTokenHash verifier;

  private RegistrationAuthentication(SaltedTokenHash verifier) {
    this.verifier = verifier;
  }

  static RegistrationAuthentication create(String password) {
    validatePassword(password);
    return new RegistrationAuthentication(SaltedTokenHash.generateFor(password));
  }

  static RegistrationAuthentication restore(String hash, String salt) {
    if (hash == null
        || !hash.matches("2\\.[a-f0-9]{64}")
        || salt == null
        || !salt.matches("[a-f0-9]{32}"))
      throw new IllegalArgumentException("Invalid registration authentication verifier");
    return new RegistrationAuthentication(new SaltedTokenHash(hash, salt));
  }

  boolean verify(String password) {
    validatePassword(password);
    return verifier.verify(password);
  }

  private static void validatePassword(String password) {
    if (password == null
        || password.isBlank()
        || password.length() > 1024
        || !StandardCharsets.UTF_8.newEncoder().canEncode(password))
      throw new IllegalArgumentException("Invalid registration authentication");
  }

  String hash() {
    return verifier.hash();
  }

  String salt() {
    return verifier.salt();
  }

  byte[] binding() {
    return ("bconnected.authentication-verifier.v1\0" + hash() + "\0" + salt())
        .getBytes(StandardCharsets.US_ASCII);
  }

  void applyTo(Device device) {
    device.setAuthTokenHash(verifier);
  }

  @Override
  public String toString() {
    return "RegistrationAuthentication[redacted]";
  }
}
