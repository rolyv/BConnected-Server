// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.DeviceActivationRequest;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.KeyIdUtil;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;

class RegistrationKeyCommitmentTest {
  private static final String VECTOR = "/admission/registration-key-commitment-v1.json";
  private static final String EXPECTED = "3b5817c63cb5ba35e0a6d1bd8b4323381de46a585b3f0ca52eb945cd831f8fd5";

  private static JsonNode vector() throws Exception {
    try (var input = RegistrationKeyCommitmentTest.class.getResourceAsStream(VECTOR)) {
      return new ObjectMapper().readTree(input);
    }
  }

  private static byte[] bytes(JsonNode field) {
    return Base64.getDecoder().decode(field.textValue());
  }

  private static final class Fixture {
    IdentityKey aciIdentity;
    IdentityKey pniIdentity;
    int aciRegistrationId;
    Integer pniRegistrationId;
    ECSignedPreKey aciEc;
    ECSignedPreKey pniEc;
    KEMSignedPreKey aciKem;
    KEMSignedPreKey pniKem;

    Fixture() throws Exception {
      JsonNode v = vector();
      aciIdentity = new IdentityKey(bytes(v.get("aciIdentityKey")));
      pniIdentity = new IdentityKey(bytes(v.get("pniIdentityKey")));
      aciRegistrationId = v.get("aciRegistrationId").intValue();
      pniRegistrationId = v.get("pniRegistrationId").intValue();
      aciEc = ec(v.get("aciSignedPreKey"));
      pniEc = ec(v.get("pniSignedPreKey"));
      aciKem = kem(v.get("aciPqLastResortPreKey"));
      pniKem = kem(v.get("pniPqLastResortPreKey"));
    }
    AccountAttributes attributes() {
      return new AccountAttributes(true, aciRegistrationId, pniRegistrationId, null, null,
          false, Set.of(), null);
    }
    DeviceActivationRequest activation() {
      return new DeviceActivationRequest(aciEc, Optional.ofNullable(pniEc), aciKem,
          Optional.ofNullable(pniKem), Optional.empty(), Optional.empty());
    }
    RegistrationRequest request() { return request(attributes(), activation()); }
    RegistrationRequest request(AccountAttributes attributes, DeviceActivationRequest activation) {
      // A claim precedes phone verification, so the key helper must not require a session/OTP.
      return new RegistrationRequest(null, null, null, null, null, attributes, true,
          aciIdentity, pniIdentity, activation);
    }
    private static ECSignedPreKey ec(JsonNode value) throws Exception {
      return new ECSignedPreKey(value.get("keyId").longValue(), new ECPublicKey(bytes(value.get("publicKey"))),
          bytes(value.get("signature")));
    }
    private static KEMSignedPreKey kem(JsonNode value) throws Exception {
      return new KEMSignedPreKey(value.get("keyId").longValue(), new KEMPublicKey(bytes(value.get("publicKey"))),
          bytes(value.get("signature")));
    }
  }

  @Test void matchesPublicOnlyCrossLanguageVectorAndIndependentRawByteFraming() throws Exception {
    JsonNode vector = vector();
    var transcript = new ByteArrayOutputStream();
    var out = new DataOutputStream(transcript);
    out.write("bconnected.registration-keys.v1\0".getBytes(StandardCharsets.UTF_8));
    for (String name : List.of("aciIdentityKey", "pniIdentityKey")) {
      byte[] field = bytes(vector.get(name)); out.writeInt(field.length); out.write(field);
    }
    for (String name : List.of("aciRegistrationId", "pniRegistrationId")) {
      out.writeInt(4); out.writeInt(vector.get(name).intValue());
    }
    for (String name : List.of("aciSignedPreKey", "pniSignedPreKey", "aciPqLastResortPreKey", "pniPqLastResortPreKey")) {
      JsonNode key = vector.get(name);
      out.writeInt(8); out.writeLong(key.get("keyId").longValue());
      for (String fieldName : List.of("publicKey", "signature")) {
        byte[] field = bytes(key.get(fieldName)); out.writeInt(field.length); out.write(field);
      }
    }
    assertThat(transcript.toByteArray()).isEqualTo(bytes(vector.get("transcriptBase64")));
    assertThat(transcript.size()).isEqualTo(3662);
    assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(transcript.toByteArray())))
        .isEqualTo(EXPECTED).isEqualTo(vector.get("sha256").textValue());
    assertThat(RegistrationKeyCommitment.compute(new Fixture().request())).isEqualTo(EXPECTED);
  }

  @Test void isDeterministicAcrossSeparateNativeKeyObjectsAndDoesNotChangeSignatures() throws Exception {
    Fixture first = new Fixture();
    byte[] original = first.aciEc.signature().clone();
    assertThat(RegistrationKeyCommitment.compute(first.request())).isEqualTo(EXPECTED);
    assertThat(RegistrationKeyCommitment.compute(first.request())).isEqualTo(EXPECTED);
    assertThat(RegistrationKeyCommitment.compute(new Fixture().request())).isEqualTo(EXPECTED);
    assertThat(first.aciEc.signature()).isEqualTo(original);
  }

  @Test void eachRegistrationAndPrekeyIdIsBoundUsingActualUpstreamBounds() throws Exception {
    // Fixture intentionally includes key ID zero and 2^31-1: use KeyIdUtil, not stale schema prose.
    for (Consumer<Fixture> change : List.<Consumer<Fixture>>of(
        f -> f.aciRegistrationId = 2, f -> f.pniRegistrationId = Device.MAX_REGISTRATION_ID - 1,
        f -> f.aciEc = new ECSignedPreKey(1, f.aciEc.publicKey(), f.aciEc.signature()),
        f -> f.pniEc = new ECSignedPreKey(KeyIdUtil.MAX_KEY_ID - 1, f.pniEc.publicKey(), f.pniEc.signature()),
        f -> f.aciKem = new KEMSignedPreKey(1, f.aciKem.publicKey(), f.aciKem.signature()),
        f -> f.pniKem = new KEMSignedPreKey(8, f.pniKem.publicKey(), f.pniKem.signature()))) {
      Fixture f = new Fixture(); change.accept(f);
      assertThat(RegistrationKeyCommitment.compute(f.request())).isNotEqualTo(EXPECTED);
    }
  }

  @Test void aciAndPniOrderCannotBeInterchangedEvenWhenBothSignaturesRemainValid() throws Exception {
    Fixture f = new Fixture();
    IdentityKey identity = f.aciIdentity; f.aciIdentity = f.pniIdentity; f.pniIdentity = identity;
    ECSignedPreKey ec = f.aciEc; f.aciEc = f.pniEc; f.pniEc = ec;
    KEMSignedPreKey kem = f.aciKem; f.aciKem = f.pniKem; f.pniKem = kem;
    assertThat(f.request().isEverySignedKeyValid(null)).isTrue();
    assertThat(RegistrationKeyCommitment.compute(f.request())).isNotEqualTo(EXPECTED);
  }

  @Test void independentlyValidReplacementKeyAndSignatureChangeCommitment() throws Exception {
    Fixture f = new Fixture();
    ECKeyPair identity = ECKeyPair.generate();
    f.aciIdentity = new IdentityKey(identity.getPublicKey());
    f.aciEc = KeysHelper.signedECPreKey(5, identity);
    f.aciKem = KeysHelper.signedKEMPreKey(6, identity);
    String original = RegistrationKeyCommitment.compute(f.request());
    ECSignedPreKey key = f.aciEc;
    f.aciEc = new ECSignedPreKey(key.keyId(), key.publicKey(),
        identity.getPrivateKey().calculateSignature(key.serializedPublicKey()));
    assertThat(f.aciEc.signature()).isNotEqualTo(key.signature());
    assertThat(RegistrationKeyCommitment.compute(f.request())).isNotEqualTo(original);
    f.aciEc = KeysHelper.signedECPreKey(key.keyId(), identity);
    assertThat(RegistrationKeyCommitment.compute(f.request())).isNotEqualTo(original);
  }

  @Test void rejectsEveryMissingPhonePilotKeyAndRequiredContainer() throws Exception {
    invalid(null);
    Fixture f = new Fixture();
    invalid(f.request(null, f.activation()));
    invalid(f.request(new AccountAttributes(), f.activation()));
    invalid(f.request(f.attributes(), null));
    for (Consumer<Fixture> remove : List.<Consumer<Fixture>>of(
        x -> x.aciIdentity = null, x -> x.pniIdentity = null, x -> x.pniRegistrationId = null,
        x -> x.aciEc = null, x -> x.pniEc = null, x -> x.aciKem = null, x -> x.pniKem = null)) {
      Fixture missing = new Fixture(); remove.accept(missing); invalid(missing.request());
    }
    invalid(f.request(f.attributes(), new DeviceActivationRequest(f.aciEc, null, f.aciKem,
        Optional.of(f.pniKem), Optional.empty(), Optional.empty())));
    invalid(f.request(f.attributes(), new DeviceActivationRequest(f.aciEc, Optional.of(f.pniEc), f.aciKem,
        null, Optional.empty(), Optional.empty())));
  }

  @Test void rejectsWrongIdentityKeyAndEachAlteredSignature() throws Exception {
    for (Consumer<Fixture> change : List.<Consumer<Fixture>>of(
        f -> f.aciIdentity = new IdentityKey(ECKeyPair.generate().getPublicKey()),
        f -> f.pniIdentity = new IdentityKey(ECKeyPair.generate().getPublicKey()),
        f -> f.aciEc.signature()[0] ^= 1, f -> f.pniEc.signature()[0] ^= 1,
        f -> f.aciKem.signature()[0] ^= 1, f -> f.pniKem.signature()[0] ^= 1)) {
      Fixture f = new Fixture(); change.accept(f); invalid(f.request());
    }
  }

  @Test void rejectsOutOfRangeRegistrationAndPrekeyIds() throws Exception {
    for (int bad : new int[] {-1, 0, Device.MAX_REGISTRATION_ID + 1, Integer.MAX_VALUE}) {
      Fixture f = new Fixture(); f.aciRegistrationId = bad; invalid(f.request());
      f = new Fixture(); f.pniRegistrationId = bad; invalid(f.request());
    }
    for (long bad : new long[] {-1, KeyIdUtil.MAX_KEY_ID + 1, Long.MAX_VALUE}) {
      for (Consumer<Fixture> change : List.<Consumer<Fixture>>of(
          f -> f.aciEc = new ECSignedPreKey(bad, f.aciEc.publicKey(), f.aciEc.signature()),
          f -> f.pniEc = new ECSignedPreKey(bad, f.pniEc.publicKey(), f.pniEc.signature()),
          f -> f.aciKem = new KEMSignedPreKey(bad, f.aciKem.publicKey(), f.aciKem.signature()),
          f -> f.pniKem = new KEMSignedPreKey(bad, f.pniKem.publicKey(), f.pniKem.signature()))) {
        Fixture f = new Fixture(); change.accept(f); invalid(f.request());
      }
    }
  }

  @Test void rejectsMissingPublicKeysAndMalformedSignatureLengths() throws Exception {
    Fixture f = new Fixture(); f.aciEc = new ECSignedPreKey(1, null, f.aciEc.signature()); invalid(f.request());
    f = new Fixture(); f.aciKem = new KEMSignedPreKey(1, null, f.aciKem.signature()); invalid(f.request());
    for (byte[] bad : new byte[][] {null, new byte[0], new byte[63], new byte[65]}) {
      f = new Fixture(); f.pniEc = new ECSignedPreKey(1, f.pniEc.publicKey(), bad); invalid(f.request());
      f = new Fixture(); f.pniKem = new KEMSignedPreKey(1, f.pniKem.publicKey(), bad); invalid(f.request());
    }
  }

  @Test void rejectsChangedPublicKeyWithOldSignatureAndIgnoresNonTranscriptFields() throws Exception {
    Fixture f = new Fixture();
    f.aciEc = new ECSignedPreKey(f.aciEc.keyId(), ECKeyPair.generate().getPublicKey(), f.aciEc.signature());
    invalid(f.request());
    f = new Fixture();
    AccountAttributes attributes = f.attributes();
    attributes.setDiscoverableByPhoneNumber(true).setRecoveryPassword(new byte[32]);
    assertThat(RegistrationKeyCommitment.compute(f.request(attributes, f.activation()))).isEqualTo(EXPECTED);
  }

  private static void invalid(RegistrationRequest request) {
    var error = assertThrows(RegistrationKeyCommitment.InvalidRegistrationKeysException.class,
        () -> RegistrationKeyCommitment.compute(request));
    assertThat(error.getMessage()).isEqualTo("Registration public-key material is invalid");
    assertThat(error.getCause()).isNull();
  }
}
