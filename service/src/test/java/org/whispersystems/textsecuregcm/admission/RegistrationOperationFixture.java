// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;

final class RegistrationOperationFixture {
  AccountAttributes attributes;
  DeviceActivationRequest activation;
  IdentityKey aci, pni;
  boolean transfer = true;
  String session;
  byte[] recovery, receipt;
  Integer totp;
  String webAuthn;

  RegistrationOperationFixture() throws Exception {
    JsonNode v;
    try (var input =
        getClass().getResourceAsStream("/admission/registration-key-commitment-v1.json")) {
      v = new ObjectMapper().readTree(input);
    }
    aci = new IdentityKey(bytes(v.get("aciIdentityKey")));
    pni = new IdentityKey(bytes(v.get("pniIdentityKey")));
    attributes =
        new AccountAttributes(
                true,
                v.get("aciRegistrationId").intValue(),
                v.get("pniRegistrationId").intValue(),
                new byte[] {1, 2},
                null,
                false,
                Set.of(DeviceCapability.SPARSE_POST_QUANTUM_RATCHET, DeviceCapability.STORAGE),
                new byte[32])
            .setUnidentifiedAccessKey(new byte[16]);
    activation =
        new DeviceActivationRequest(
            ec(v.get("aciSignedPreKey")),
            Optional.of(ec(v.get("pniSignedPreKey"))),
            kem(v.get("aciPqLastResortPreKey")),
            Optional.of(kem(v.get("pniPqLastResortPreKey"))),
            Optional.empty(),
            Optional.empty());
  }

  RegistrationRequest request() {
    return new RegistrationRequest(
        session, recovery, receipt, totp, webAuthn, attributes, transfer, aci, pni, activation);
  }

  static byte[] bytes(JsonNode value) {
    return Base64.getDecoder().decode(value.textValue());
  }

  static ECSignedPreKey ec(JsonNode value) throws Exception {
    return new ECSignedPreKey(
        value.get("keyId").longValue(),
        new ECPublicKey(bytes(value.get("publicKey"))),
        bytes(value.get("signature")));
  }

  static KEMSignedPreKey kem(JsonNode value) throws Exception {
    return new KEMSignedPreKey(
        value.get("keyId").longValue(),
        new KEMPublicKey(bytes(value.get("publicKey"))),
        bytes(value.get("signature")));
  }

  void attributes(
      boolean fetch,
      int aciRegistration,
      int pniRegistration,
      byte[] name,
      String lock,
      boolean discoverable,
      Set<DeviceCapability> capabilities,
      byte[] recovery) {
    attributes =
        new AccountAttributes(
                fetch,
                aciRegistration,
                pniRegistration,
                name,
                lock,
                discoverable,
                capabilities,
                recovery)
            .setUnidentifiedAccessKey(new byte[16]);
  }

  void push(boolean apn, String token) {
    attributes(
        false,
        attributes.getRegistrationId(),
        attributes.getPhoneNumberIdentityRegistrationId().orElseThrow(),
        attributes.getName(),
        attributes.getRegistrationLock(),
        attributes.isDiscoverableByPhoneNumber(),
        attributes.getCapabilities(),
        attributes.recoveryPassword().orElse(null));
    activation =
        new DeviceActivationRequest(
            activation.aciSignedPreKey(),
            activation.pniSignedPreKey(),
            activation.aciPqLastResortPreKey(),
            activation.pniPqLastResortPreKey(),
            apn ? Optional.of(new ApnRegistrationId(token)) : Optional.empty(),
            apn ? Optional.empty() : Optional.of(new GcmRegistrationId(token)));
  }
}
