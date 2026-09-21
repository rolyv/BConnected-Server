// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.PreKeySignatureValidator;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.entities.SignedPreKey;
import org.whispersystems.textsecuregcm.storage.KeyIdUtil;
import org.whispersystems.textsecuregcm.util.RegistrationIdValidator;

/**
 * The public-key transcript defined in the community admission contract. This validates phone-pilot
 * key material, not phone possession, membership, or the complete registration request. Callers must
 * separately validate and persist the complete immutable request before authorizing any operation.
 */
public final class RegistrationKeyCommitment {
  private static final byte[] DOMAIN =
      "bconnected.registration-keys.v1\0".getBytes(StandardCharsets.UTF_8);

  private RegistrationKeyCommitment() {}

  public static final class InvalidRegistrationKeysException extends IllegalArgumentException {
    private InvalidRegistrationKeysException() {
      super("Registration public-key material is invalid");
    }
  }

  /** Returns lowercase SHA-256 hex; requires both ACI and PNI material for the phone pilot. */
  public static String compute(RegistrationRequest request) {
    final Snapshot snapshot;
    try {
      Objects.requireNonNull(request);
      var attributes = Objects.requireNonNull(request.accountAttributes());
      var activation = Objects.requireNonNull(request.deviceActivationRequest());
      int aciRegistrationId = attributes.getRegistrationId();
      int pniRegistrationId = attributes.getPhoneNumberIdentityRegistrationId().orElseThrow();
      if (!RegistrationIdValidator.validRegistrationId(aciRegistrationId)
          || !RegistrationIdValidator.validRegistrationId(pniRegistrationId)) {
        throw new InvalidRegistrationKeysException();
      }
      // Snapshot first: entity signature arrays are mutable. Verify and hash the same private copies.
      IdentityKey aciIdentity = identity(request.aciIdentityKey());
      IdentityKey pniIdentity = identity(request.pniIdentityKey());
      ECSignedPreKey aciEc = ec(activation.aciSignedPreKey());
      ECSignedPreKey pniEc = ec(activation.pniSignedPreKey().orElseThrow());
      KEMSignedPreKey aciKem = kem(activation.aciPqLastResortPreKey());
      KEMSignedPreKey pniKem = kem(activation.pniPqLastResortPreKey().orElseThrow());
      if (!PreKeySignatureValidator.validatePreKeySignatures(
              aciIdentity, List.of(aciEc, aciKem), null, "admission")
          || !PreKeySignatureValidator.validatePreKeySignatures(
              pniIdentity, List.of(pniEc, pniKem), null, "admission")) {
        throw new InvalidRegistrationKeysException();
      }
      snapshot = new Snapshot(aciIdentity, pniIdentity, aciRegistrationId, pniRegistrationId,
          aciEc, pniEc, aciKem, pniKem);
    } catch (InvalidKeyException | RuntimeException ignored) {
      // Do not retain parser errors or request/key fragments in an exception chain.
      throw new InvalidRegistrationKeysException();
    }

    final MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException impossible) {
      throw new AssertionError("SHA-256 unavailable");
    }
    digest.update(DOMAIN);
    frame(digest, snapshot.aciIdentity.serialize());
    frame(digest, snapshot.pniIdentity.serialize());
    frame(digest, ByteBuffer.allocate(4).putInt(snapshot.aciRegistrationId).array());
    frame(digest, ByteBuffer.allocate(4).putInt(snapshot.pniRegistrationId).array());
    for (SignedPreKey<?> key : List.of(snapshot.aciEc, snapshot.pniEc, snapshot.aciKem, snapshot.pniKem)) {
      frame(digest, ByteBuffer.allocate(8).putLong(key.keyId()).array());
      frame(digest, key.serializedPublicKey());
      frame(digest, key.signature());
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static IdentityKey identity(IdentityKey source) throws InvalidKeyException {
    byte[] bytes = Objects.requireNonNull(source).serialize().clone();
    IdentityKey parsed = new IdentityKey(bytes);
    canonical(bytes, parsed.serialize());
    return parsed;
  }

  private static ECSignedPreKey ec(ECSignedPreKey source) throws InvalidKeyException {
    Objects.requireNonNull(source);
    byte[] bytes = Objects.requireNonNull(source.publicKey()).serialize().clone();
    ECPublicKey parsed = new ECPublicKey(bytes);
    canonical(bytes, parsed.serialize());
    return new ECSignedPreKey(keyId(source.keyId()), parsed, signature(source.signature()));
  }

  private static KEMSignedPreKey kem(KEMSignedPreKey source) throws InvalidKeyException {
    Objects.requireNonNull(source);
    byte[] bytes = Objects.requireNonNull(source.publicKey()).serialize().clone();
    KEMPublicKey parsed = new KEMPublicKey(bytes);
    canonical(bytes, parsed.serialize());
    return new KEMSignedPreKey(keyId(source.keyId()), parsed, signature(source.signature()));
  }

  private static long keyId(long value) {
    if (!KeyIdUtil.keyIdValid(value)) throw new InvalidRegistrationKeysException();
    return value;
  }

  private static byte[] signature(byte[] source) {
    byte[] copy = Objects.requireNonNull(source).clone();
    if (copy.length != 64) throw new InvalidRegistrationKeysException();
    return copy;
  }

  private static void canonical(byte[] input, byte[] serialized) {
    if (!Arrays.equals(input, serialized)) throw new InvalidRegistrationKeysException();
  }

  private static void frame(MessageDigest digest, byte[] value) {
    digest.update(ByteBuffer.allocate(4).putInt(value.length).array());
    digest.update(value);
  }

  private record Snapshot(IdentityKey aciIdentity, IdentityKey pniIdentity,
      int aciRegistrationId, int pniRegistrationId, ECSignedPreKey aciEc, ECSignedPreKey pniEc,
      KEMSignedPreKey aciKem, KEMSignedPreKey pniKem) {}
}
