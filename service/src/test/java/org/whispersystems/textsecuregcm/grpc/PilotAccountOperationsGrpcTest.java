// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.signal.chat.account.*;
import org.whispersystems.textsecuregcm.auth.AccountOperationsPolicy;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.UsernameHashZkProofVerifier;

class PilotAccountOperationsGrpcTest extends SimpleBaseGrpcTest<AccountsGrpcService, AccountsGrpc.AccountsBlockingStub> {
  AccountsManager accounts;
  RateLimiters rates;
  ChangeNumberManager numbers;
  PhoneNumberRecoveryPasswordsManager recovery;

  @Override protected AccountsGrpcService createServiceBeforeEachTest() {
    accounts = mock(AccountsManager.class); rates = mock(RateLimiters.class);
    numbers = mock(ChangeNumberManager.class); recovery = mock(PhoneNumberRecoveryPasswordsManager.class);
    return new AccountsGrpcService(accounts, rates, mock(UsernameHashZkProofVerifier.class), recovery,
        Clock.systemUTC(), numbers, AccountOperationsPolicy.PILOT_PRIMARY_ONLY);
  }

  @Test void numberChangeRejectedBeforePhoneVerificationOrMutation() {
    var identity = org.signal.libsignal.protocol.ecc.ECKeyPair.generate();
    var ec = org.whispersystems.textsecuregcm.tests.util.KeysHelper.signedECPreKey(1, identity);
    var kem = org.whispersystems.textsecuregcm.tests.util.KeysHelper.signedKEMPreKey(2, identity);
    var request = ChangeNumberRequest.newBuilder().setSessionId(ByteString.copyFrom(new byte[32]))
        .setNumber("+12025550199").setPniIdentityKey(ByteString.copyFrom(identity.getPublicKey().serialize()))
        .putDevicePniSignedPreKeys(1, org.signal.chat.common.EcSignedPreKey.newBuilder().setKeyId(1)
            .setPublicKey(ByteString.copyFrom(ec.serializedPublicKey())).setSignature(ByteString.copyFrom(ec.signature())).build())
        .putDevicePniPqLastResortPreKeys(1, org.signal.chat.common.KemSignedPreKey.newBuilder().setKeyId(2)
            .setPublicKey(ByteString.copyFrom(kem.serializedPublicKey())).setSignature(ByteString.copyFrom(kem.signature())).build())
        .putPniRegistrationIds(1, 123).build();
    var failure = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().changeNumber(request));
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(accounts, rates, numbers, recovery);
  }

  @Test void recoveryPasswordUpdateRejectedBeforeAccountLookup() {
    var failure = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().setRegistrationRecoveryPassword(SetRegistrationRecoveryPasswordRequest.newBuilder()
            .setRegistrationRecoveryPassword(ByteString.copyFrom(new byte[32])).build()));
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(accounts, rates, numbers, recovery);
  }

  @Test void allMfaOperationsRejectedOnWireBeforeCollaboratorEffects() {
    assertMfaUnavailable(() -> authenticatedServiceStub().generateTotpKey(GenerateTotpKeyRequest.getDefaultInstance()));
    assertMfaUnavailable(() -> authenticatedServiceStub().confirmTotpKey(ConfirmTotpKeyRequest.newBuilder()
        .setOneTimePassword(123456).setMetadataCiphertext(ByteString.copyFrom(new byte[160])).build()));
    assertMfaUnavailable(() -> authenticatedServiceStub().startWebAuthnRegistration(StartWebAuthnRegistrationRequest.getDefaultInstance()));
    assertMfaUnavailable(() -> authenticatedServiceStub().finishWebAuthnRegistration(FinishWebAuthnRegistrationRequest.newBuilder()
        .setAttestationObject(ByteString.copyFrom(new byte[128])).setCollectedClientDataJson("{\"type\":\"webauthn.create\"}")
        .setMetadataCiphertext(ByteString.copyFrom(new byte[160])).build()));
    assertMfaUnavailable(() -> authenticatedServiceStub().listMfaKeys(ListMfaKeysRequest.getDefaultInstance()));
    assertMfaUnavailable(() -> authenticatedServiceStub().setMfaKeyMetadata(SetMfaKeyMetadataRequest.newBuilder()
        .setKeyId(0).setMetadataCiphertext(ByteString.copyFrom(new byte[160])).build()));
    assertMfaUnavailable(() -> authenticatedServiceStub().removeMfaKey(RemoveMfaKeyRequest.newBuilder().setKeyId(0).build()));
    assertMfaUnavailable(() -> authenticatedServiceStub().startMfaVerification(StartMfaVerificationRequest.getDefaultInstance()));
    assertMfaUnavailable(() -> authenticatedServiceStub().finishMfaVerification(FinishMfaVerificationRequest.newBuilder()
        .setTotpPassword(123456).build()));

    verifyNoInteractions(accounts, rates, numbers, recovery);
  }

  private static void assertMfaUnavailable(final Runnable operation) {
    var failure = assertThrows(StatusRuntimeException.class, operation::run);
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }
}
