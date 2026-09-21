/*
 * Copyright 2024 Signal Messenger, LLC
 * Copyright 2026 BConnected contributors.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import java.security.PublicKey;
import java.util.Objects;
import java.util.Optional;

/** The original credential/CBOR encoding retained by PostgreSQL. No attestation verification occurs here. */
final class AppleDeviceCheckCodec {
  private final ObjectConverter objectConverter;

  AppleDeviceCheckCodec(final ObjectConverter objectConverter) {
    this.objectConverter = Objects.requireNonNull(objectConverter);
  }

  record Encoded(byte[] credentialData, byte[] statement, byte[] extensions, long counter) {}

  Encoded encode(final DCAppleDevice appleDevice) {
    final AttestedCredentialDataConverter credentialConverter = new AttestedCredentialDataConverter(objectConverter);
    return new Encoded(
        credentialConverter.convert(appleDevice.getAttestedCredentialData()),
        objectConverter.getCborConverter()
            .writeValueAsBytes(new AttestationStatementEnvelope(appleDevice.getAttestationStatement())),
        objectConverter.getCborConverter().writeValueAsBytes(appleDevice.getAuthenticatorExtensions()),
        appleDevice.getCounter());
  }

  DCAppleDevice decode(final byte[] credentialData, final byte[] statementBytes, final byte[] extensionsBytes,
      final long counter) {
    final AttestedCredentialData credData = new AttestedCredentialDataConverter(objectConverter).convert(credentialData);
    final AttestationStatement statement = Optional.ofNullable(objectConverter.getCborConverter()
            .readValue(statementBytes, AttestationStatementEnvelope.class))
        .orElseThrow(() -> new IllegalStateException("Stored device check key missing attestation statement"))
        .getAttestationStatement();

    @SuppressWarnings("unchecked")
    final AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> extensions =
        objectConverter.getCborConverter().readValue(extensionsBytes, AuthenticationExtensionsAuthenticatorOutputs.class);
    return new DCAppleDeviceImpl(credData, statement, counter, extensions);
  }

  static PublicKey publicKey(final DCAppleDevice appleDevice) {
    // The upstream verifier has already bound this leaf public key to the key ID. Keep the original X.509 encoding.
    final AppleAppAttestAttestationStatement statement =
        (AppleAppAttestAttestationStatement) appleDevice.getAttestationStatement();
    Objects.requireNonNull(statement);
    return statement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
  }

  /** Preserve the upstream CBOR envelope's attStmt/fmt fields and external type information. */
  private static class AttestationStatementEnvelope {
    @JsonProperty("attStmt")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXTERNAL_PROPERTY, property = "fmt")
    private AttestationStatement attestationStatement;

    @JsonCreator
    public AttestationStatementEnvelope(@JsonProperty("attStmt") final AttestationStatement attestationStatement) {
      this.attestationStatement = attestationStatement;
    }

    @JsonProperty("fmt")
    public String getFormat() { return attestationStatement.getFormat(); }

    public AttestationStatement getAttestationStatement() { return attestationStatement; }
  }
}
