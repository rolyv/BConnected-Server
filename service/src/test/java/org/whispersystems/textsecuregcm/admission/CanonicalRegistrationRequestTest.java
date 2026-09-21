// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.entities.DeviceActivationRequest;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;

class CanonicalRegistrationRequestTest {
  private byte[] encode(RegistrationOperationFixture f) throws Exception {
    try (var canonical =
        CanonicalRegistrationRequest.beforeVerification(
            f.request(), "+13055550123", "iOS", "Signal-iOS/1")) {
      return canonical.bytes();
    }
  }

  @Test
  void deterministicTypedEncodingAndDetachedCopies() throws Exception {
    var f = new RegistrationOperationFixture();
    var canonical =
        CanonicalRegistrationRequest.beforeVerification(
            f.request(), "+13055550123", "iOS", "Signal-iOS/1");
    byte[] original = canonical.bytes();
    assertThat(original).isEqualTo(encode(new RegistrationOperationFixture()));
    f.attributes.getName()[0] = 99;
    f.attributes.getUnidentifiedAccessKey()[0] = 99;
    f.activation.aciSignedPreKey().signature()[0] ^= 1;
    assertThat(canonical.bytes()).isEqualTo(original);
    var copy = canonical.bytes();
    copy[0] ^= 1;
    assertThat(canonical.bytes()).isEqualTo(original);
    canonical.close();
    assertThrows(IllegalStateException.class, canonical::bytes);
    assertThat(canonical.toString()).isEqualTo("CanonicalRegistrationRequest[redacted]");
  }

  @Test
  void everyAccountAttributeAndTransferChoiceIsBound() throws Exception {
    byte[] baseline = encode(new RegistrationOperationFixture());
    for (Consumer<RegistrationOperationFixture> mutation :
        List.<Consumer<RegistrationOperationFixture>>of(
            f -> f.transfer = false,
            f -> f.attributes.getName()[0] = 3,
            f -> f.attributes.getUnidentifiedAccessKey()[0] = 1,
            f -> f.attributes.setUnrestrictedUnidentifiedAccess(true),
            f -> f.attributes.setDiscoverableByPhoneNumber(true),
            f -> {
              byte[] r = new byte[32];
              r[0] = 1;
              f.attributes.setRecoveryPassword(r);
            },
            f ->
                f.attributes(
                    true,
                    2,
                    3,
                    new byte[] {1, 2},
                    null,
                    false,
                    f.attributes.getCapabilities(),
                    new byte[32]),
            f ->
                f.attributes(
                    true,
                    f.attributes.getRegistrationId(),
                    2,
                    new byte[] {1, 2},
                    null,
                    false,
                    f.attributes.getCapabilities(),
                    new byte[32]),
            f ->
                f.attributes(
                    true,
                    f.attributes.getRegistrationId(),
                    f.attributes.getPhoneNumberIdentityRegistrationId().orElseThrow(),
                    new byte[] {1, 2},
                    "a".repeat(64),
                    false,
                    f.attributes.getCapabilities(),
                    new byte[32]),
            f ->
                f.attributes(
                    true,
                    f.attributes.getRegistrationId(),
                    f.attributes.getPhoneNumberIdentityRegistrationId().orElseThrow(),
                    new byte[] {1, 2},
                    null,
                    false,
                    Set.of(DeviceCapability.SPARSE_POST_QUANTUM_RATCHET),
                    new byte[32]))) {
      var f = new RegistrationOperationFixture();
      mutation.accept(f);
      assertThat(encode(f)).isNotEqualTo(baseline);
    }
  }

  @Test
  void everyPrekeyIdAndPushTypeTokenAreBound() throws Exception {
    byte[] baseline = encode(new RegistrationOperationFixture());
    for (int i = 0; i < 4; i++) {
      var f = new RegistrationOperationFixture();
      var a = f.activation;
      var ae = a.aciSignedPreKey();
      var pe = a.pniSignedPreKey().orElseThrow();
      var ak = a.aciPqLastResortPreKey();
      var pk = a.pniPqLastResortPreKey().orElseThrow();
      f.activation =
          new DeviceActivationRequest(
              i == 0 ? new ECSignedPreKey(123, ae.publicKey(), ae.signature()) : ae,
              Optional.of(i == 1 ? new ECSignedPreKey(124, pe.publicKey(), pe.signature()) : pe),
              i == 2 ? new KEMSignedPreKey(125, ak.publicKey(), ak.signature()) : ak,
              Optional.of(i == 3 ? new KEMSignedPreKey(126, pk.publicKey(), pk.signature()) : pk),
              Optional.empty(),
              Optional.empty());
      assertThat(encode(f)).isNotEqualTo(baseline);
    }
    var apn = new RegistrationOperationFixture();
    apn.push(true, "token-a");
    var apn2 = new RegistrationOperationFixture();
    apn2.push(true, "token-b");
    var gcm = new RegistrationOperationFixture();
    gcm.push(false, "token-a");
    assertThat(encode(apn))
        .isNotEqualTo(baseline)
        .isNotEqualTo(encode(apn2))
        .isNotEqualTo(encode(gcm));
  }

  @Test
  void validIdentityPublicKeysAndSignaturesRemainBound() throws Exception {
    var f = new RegistrationOperationFixture();
    var aci = ECKeyPair.generate();
    var pni = ECKeyPair.generate();
    f.aci = new IdentityKey(aci.getPublicKey());
    f.pni = new IdentityKey(pni.getPublicKey());
    var ae = KeysHelper.signedECPreKey(1, aci);
    var pe = KeysHelper.signedECPreKey(2, pni);
    var ak = KeysHelper.signedKEMPreKey(3, aci);
    var pk = KeysHelper.signedKEMPreKey(4, pni);
    f.activation =
        new DeviceActivationRequest(
            ae, Optional.of(pe), ak, Optional.of(pk), Optional.empty(), Optional.empty());
    byte[] baseline = encode(f);
    for (int index = 0; index < 4; index++) {
      f.activation =
          new DeviceActivationRequest(
              index == 0 ? KeysHelper.signedECPreKey(1, aci) : ae,
              Optional.of(index == 1 ? KeysHelper.signedECPreKey(2, pni) : pe),
              index == 2 ? KeysHelper.signedKEMPreKey(3, aci) : ak,
              Optional.of(index == 3 ? KeysHelper.signedKEMPreKey(4, pni) : pk),
              Optional.empty(),
              Optional.empty());
      assertThat(encode(f)).isNotEqualTo(baseline);
    }
    var resigned =
        new ECSignedPreKey(
            1, ae.publicKey(), aci.getPrivateKey().calculateSignature(ae.serializedPublicKey()));
    assertThat(resigned.signature()).isNotEqualTo(ae.signature());
    f.activation =
        new DeviceActivationRequest(
            resigned, Optional.of(pe), ak, Optional.of(pk), Optional.empty(), Optional.empty());
    assertThat(encode(f)).isNotEqualTo(baseline);
    var replacement = ECKeyPair.generate();
    f.aci = new IdentityKey(replacement.getPublicKey());
    f.activation =
        new DeviceActivationRequest(
            KeysHelper.signedECPreKey(1, replacement),
            Optional.of(pe),
            KeysHelper.signedKEMPreKey(3, replacement),
            Optional.of(pk),
            Optional.empty(),
            Optional.empty());
    assertThat(encode(f)).isNotEqualTo(baseline);
  }

  @Test
  void capabilityOrderDoesNotChangeEncodingAndFutureRequestFieldsRequireEncoderReview()
      throws Exception {
    var f = new RegistrationOperationFixture();
    byte[] baseline = encode(f);
    f.attributes(
        true,
        f.attributes.getRegistrationId(),
        f.attributes.getPhoneNumberIdentityRegistrationId().orElseThrow(),
        new byte[] {1, 2},
        null,
        false,
        new java.util.LinkedHashSet<>(
            List.of(DeviceCapability.STORAGE, DeviceCapability.SPARSE_POST_QUANTUM_RATCHET)),
        new byte[32]);
    assertThat(encode(f)).isEqualTo(baseline);
    assertThat(
            java.util.Arrays.stream(
                    org.whispersystems.textsecuregcm.entities.RegistrationRequest.class
                        .getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName))
        .containsExactly(
            "sessionId",
            "recoveryPassword",
            "receiptCredentialPresentation",
            "totp",
            "webAuthnResponse",
            "accountAttributes",
            "skipDeviceTransfer",
            "aciIdentityKey",
            "pniIdentityKey",
            "deviceActivationRequest");
    assertThat(
            java.util.Arrays.stream(
                    org.whispersystems.textsecuregcm.entities.AccountAttributes.class
                        .getDeclaredFields())
                .filter(field -> !java.lang.reflect.Modifier.isStatic(field.getModifiers()))
                .map(java.lang.reflect.Field::getName))
        .containsExactlyInAnyOrder(
            "deviceAttributes",
            "registrationLock",
            "unidentifiedAccessKey",
            "unrestrictedUnidentifiedAccess",
            "discoverableByPhoneNumber",
            "recoveryPassword");
    assertThat(
            java.util.Arrays.stream(
                    org.whispersystems.textsecuregcm.entities.DeviceAttributes.class
                        .getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName))
        .containsExactly(
            "fetchesMessages",
            "registrationId",
            "phoneNumberIdentityRegistrationId",
            "name",
            "capabilities");
    assertThat(
            java.util.Arrays.stream(DeviceActivationRequest.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName))
        .containsExactly(
            "aciSignedPreKey",
            "pniSignedPreKey",
            "aciPqLastResortPreKey",
            "pniPqLastResortPreKey",
            "apnToken",
            "gcmToken");
  }

  @Test
  void numberAndAgentMetadataAreBoundAndCanonicalPhoneRequired() throws Exception {
    var request = new RegistrationOperationFixture().request();
    try (var a =
            CanonicalRegistrationRequest.beforeVerification(request, "+13055550123", null, null);
        var b =
            CanonicalRegistrationRequest.beforeVerification(request, "+13055550124", null, null);
        var c =
            CanonicalRegistrationRequest.beforeVerification(request, "+13055550123", "iOS", null);
        var d =
            CanonicalRegistrationRequest.beforeVerification(
                request, "+13055550123", null, "Signal-iOS/1")) {
      assertThat(a.bytes()).isNotEqualTo(b.bytes()).isNotEqualTo(c.bytes()).isNotEqualTo(d.bytes());
    }
    for (String invalid :
        List.of(
            "3055550123",
            "+1 305 555 0123",
            "00000000-0000-4000-8000-000000000001",
            "__no_number__"))
      assertThrows(
          CanonicalRegistrationRequest.InvalidRequestException.class,
          () -> CanonicalRegistrationRequest.beforeVerification(request, invalid, null, null));
  }

  @Test
  void recoveryNumberlessMfaAndClientSessionPathsAreClosed() throws Exception {
    for (Consumer<RegistrationOperationFixture> mutation :
        List.<Consumer<RegistrationOperationFixture>>of(
            f -> f.session = "client-session",
            f -> f.session = "",
            f -> f.recovery = new byte[0],
            f -> f.receipt = new byte[32],
            f -> f.totp = 1,
            f -> f.webAuthn = "{}",
            f -> f.pni = null)) {
      var f = new RegistrationOperationFixture();
      mutation.accept(f);
      assertThrows(CanonicalRegistrationRequest.InvalidRequestException.class, () -> encode(f));
    }
  }

  @Test
  void invalidAttributesChannelsSignaturesAndUnicodeFailWithoutPayloadErrors() throws Exception {
    for (Consumer<RegistrationOperationFixture> mutation :
        List.<Consumer<RegistrationOperationFixture>>of(
            f -> f.attributes.setUnidentifiedAccessKey(new byte[15]),
            f -> f.attributes.setRecoveryPassword(new byte[31]),
            f -> f.activation.aciSignedPreKey().signature()[0] ^= 1,
            f ->
                f.attributes(
                    true, 2, 3, new byte[226], null, false, f.attributes.getCapabilities(), null),
            f ->
                f.attributes(
                    true, 2, 3, null, "short", false, f.attributes.getCapabilities(), null),
            f -> f.attributes(true, 2, 3, null, null, false, Set.of(), null),
            f -> f.push(true, ""),
            f -> f.push(true, "\ud800"))) {
      var f = new RegistrationOperationFixture();
      mutation.accept(f);
      var exception =
          assertThrows(CanonicalRegistrationRequest.InvalidRequestException.class, () -> encode(f));
      assertThat(exception.getCause()).isNull();
    }
  }

  @Test
  void originalSaltedAuthenticationSurvivesRestoreAndNeverLogsVerifier() {
    var first = RegistrationAuthentication.create("synthetic-password");
    var restored = RegistrationAuthentication.restore(first.hash(), first.salt());
    assertThat(restored.verify("synthetic-password")).isTrue();
    assertThat(restored.verify("changed")).isFalse();
    assertThat(restored.binding()).isEqualTo(first.binding());
    assertThat(RegistrationAuthentication.create("synthetic-password").binding())
        .isNotEqualTo(first.binding());
    assertThat(first.toString()).isEqualTo("RegistrationAuthentication[redacted]");
    var device = new Device();
    restored.applyTo(device);
    assertThat(device.getAuthTokenHash().verify("synthetic-password")).isTrue();
    assertThat(new String(first.binding(), StandardCharsets.US_ASCII))
        .doesNotContain("synthetic-password");
    assertThrows(IllegalArgumentException.class, () -> RegistrationAuthentication.create("\ud800"));
  }
}
