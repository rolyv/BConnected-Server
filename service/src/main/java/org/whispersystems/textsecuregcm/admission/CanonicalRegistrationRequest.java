// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.DeviceActivationRequest;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;
import org.whispersystems.textsecuregcm.util.Util;

/**
 * Explicit v1 phone-pilot encoding, independent of Jackson property order or unknown JSON fields.
 */
public final class CanonicalRegistrationRequest implements AutoCloseable {
  private byte[] bytes;
  private final String keyCommitment;
  private final String number;

  private CanonicalRegistrationRequest(byte[] bytes, String keyCommitment, String number) {
    this.bytes = bytes;
    this.keyCommitment = keyCommitment;
    this.number = number;
  }

  public static final class InvalidRequestException extends IllegalArgumentException {
    private InvalidRequestException() {
      super("Invalid phone-pilot registration request");
    }
  }

  public static CanonicalRegistrationRequest beforeVerification(
      RegistrationRequest request, String number, String signalAgent, String userAgent) {
    try {
      Util.requireNormalizedNumber(number);
      if (request.sessionId() != null
          || request.recoveryPassword() != null
          || request.receiptCredentialPresentation() != null
          || request.totp() != null
          || request.webAuthnResponse() != null) throw new InvalidRequestException();
      var source = Objects.requireNonNull(request.accountAttributes());
      var activation = Objects.requireNonNull(request.deviceActivationRequest());
      byte[] name = copy(source.getName());
      byte[] uak = copy(source.getUnidentifiedAccessKey());
      byte[] recovery = source.recoveryPassword().map(byte[]::clone).orElse(null);
      String lock = source.getRegistrationLock();
      boolean unrestricted = source.isUnrestrictedUnidentifiedAccess();
      Set<DeviceCapability> capabilities =
          Set.copyOf(Objects.requireNonNull(source.getCapabilities()));
      if (name != null && name.length > 225
          || lock != null && !lock.isEmpty() && lock.length() != 64
          || uak != null && uak.length != 0 && uak.length != 16
          || !unrestricted && (uak == null || uak.length != 16)
          || recovery != null && recovery.length != 32
          || !capabilities.containsAll(DeviceCapability.CAPABILITIES_REQUIRED_FOR_NEW_DEVICES))
        throw new InvalidRequestException();
      var attrs =
          new AccountAttributes(
                  source.getFetchesMessages(),
                  source.getRegistrationId(),
                  source.getPhoneNumberIdentityRegistrationId().orElseThrow(),
                  name,
                  lock,
                  source.isDiscoverableByPhoneNumber(),
                  capabilities,
                  recovery)
              .setUnidentifiedAccessKey(uak)
              .setUnrestrictedUnidentifiedAccess(unrestricted);
      var aciIdentity = new IdentityKey(request.aciIdentityKey().serialize().clone());
      var pniIdentity = new IdentityKey(request.pniIdentityKey().serialize().clone());
      var aciEc = ec(activation.aciSignedPreKey());
      var pniEc = ec(activation.pniSignedPreKey().orElseThrow());
      var aciKem = kem(activation.aciPqLastResortPreKey());
      var pniKem = kem(activation.pniPqLastResortPreKey().orElseThrow());
      var apn = Objects.requireNonNull(activation.apnToken());
      var gcm = Objects.requireNonNull(activation.gcmToken());
      String apnId = apn.map(value -> value.apnRegistrationId()).orElse(null);
      String gcmId = gcm.map(value -> value.gcmRegistrationId()).orElse(null);
      if (attrs.getFetchesMessages()
          ? apn.isPresent() || gcm.isPresent()
          : apn.isPresent() == gcm.isPresent()) throw new InvalidRequestException();
      if (apn.isPresent() && (apnId == null || apnId.isEmpty())
          || gcm.isPresent() && (gcmId == null || gcmId.isEmpty()))
        throw new InvalidRequestException();
      var frozen =
          new RegistrationRequest(
              null,
              null,
              null,
              null,
              null,
              attrs,
              request.skipDeviceTransfer(),
              aciIdentity,
              pniIdentity,
              new DeviceActivationRequest(
                  aciEc, Optional.of(pniEc), aciKem, Optional.of(pniKem), apn, gcm));
      String keyDigest = RegistrationKeyCommitment.compute(frozen);
      var buffer = new ByteArrayOutputStream();
      var out = new DataOutputStream(buffer);
      out.write("bconnected.registration-canonical.v1\0".getBytes(StandardCharsets.US_ASCII));
      // The session slot is server-owned and attached separately after private approval; clients
      // cannot fill it.
      text(out, "phone-with-server-assigned-session");
      text(out, number);
      text(out, signalAgent);
      text(out, userAgent);
      out.writeBoolean(request.skipDeviceTransfer());
      out.writeBoolean(attrs.getFetchesMessages());
      out.writeInt(attrs.getRegistrationId());
      out.writeInt(attrs.getPhoneNumberIdentityRegistrationId().orElseThrow());
      frame(out, name);
      text(out, lock);
      frame(out, uak);
      out.writeBoolean(attrs.isUnrestrictedUnidentifiedAccess());
      out.writeBoolean(attrs.isDiscoverableByPhoneNumber());
      frame(out, recovery);
      var names = new TreeSet<String>();
      capabilities.forEach(capability -> names.add(capability.getName()));
      out.writeInt(names.size());
      for (String capability : names) text(out, capability);
      frame(out, aciIdentity.serialize());
      frame(out, pniIdentity.serialize());
      for (var key : List.of(aciEc, pniEc, aciKem, pniKem)) {
        out.writeLong(key.keyId());
        frame(out, key.serializedPublicKey());
        frame(out, key.signature());
      }
      text(out, apnId);
      text(out, gcmId);
      byte[] encoded = buffer.toByteArray();
      if (encoded.length > 1_048_576) throw new InvalidRequestException();
      return new CanonicalRegistrationRequest(encoded, keyDigest, number);
    } catch (Exception ignored) {
      throw new InvalidRequestException();
    }
  }

  private static byte[] copy(byte[] value) {
    return value == null ? null : value.clone();
  }

  private static ECSignedPreKey ec(ECSignedPreKey value) throws Exception {
    return new ECSignedPreKey(
        value.keyId(),
        new ECPublicKey(value.serializedPublicKey().clone()),
        value.signature().clone());
  }

  private static KEMSignedPreKey kem(KEMSignedPreKey value) throws Exception {
    return new KEMSignedPreKey(
        value.keyId(),
        new KEMPublicKey(value.serializedPublicKey().clone()),
        value.signature().clone());
  }

  private static void text(DataOutputStream out, String value) throws IOException {
    if (value != null
        && (value.length() > 8192 || !StandardCharsets.UTF_8.newEncoder().canEncode(value)))
      throw new InvalidRequestException();
    frame(out, value == null ? null : value.getBytes(StandardCharsets.UTF_8));
  }

  private static void frame(DataOutputStream out, byte[] value) throws IOException {
    out.writeInt(value == null ? -1 : value.length);
    if (value != null) out.write(value);
  }

  synchronized byte[] bytes() {
    if (bytes == null) throw new IllegalStateException("Registration snapshot closed");
    return bytes.clone();
  }

  public String keyCommitment() {
    return keyCommitment;
  }

  public String number() {
    return number;
  }

  @Override
  public synchronized void close() {
    if (bytes != null) {
      Arrays.fill(bytes, (byte) 0);
      bytes = null;
    }
  }

  @Override
  public String toString() {
    return "CanonicalRegistrationRequest[redacted]";
  }
}
