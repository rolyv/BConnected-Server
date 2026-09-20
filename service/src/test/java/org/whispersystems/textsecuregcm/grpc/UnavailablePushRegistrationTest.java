// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.signal.chat.device.DevicesGrpc;
import org.signal.chat.device.SetPushTokenRequest;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.controllers.AccountController;
import org.whispersystems.textsecuregcm.entities.ApnRegistrationId;
import org.whispersystems.textsecuregcm.entities.GcmRegistrationId;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.FeatureUnavailableExceptionMapper;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;
import org.whispersystems.textsecuregcm.util.UsernameHashZkProofVerifier;

class UnavailablePushRegistrationTest extends SimpleBaseGrpcTest<DevicesGrpcService, DevicesGrpc.DevicesBlockingStub> {
  private AccountsManager accounts;

  @Override
  protected DevicesGrpcService createServiceBeforeEachTest() {
    accounts = mock(AccountsManager.class);
    return new DevicesGrpcService(accounts, Set.of());
  }

  @Test
  void grpcRejectsBothProvidersBeforeAccountReadsOrWrites() {
    for (SetPushTokenRequest request : new SetPushTokenRequest[] {
        SetPushTokenRequest.newBuilder().setApnsTokenRequest(
            SetPushTokenRequest.ApnsTokenRequest.newBuilder().setApnsToken("test-token")).build(),
        SetPushTokenRequest.newBuilder().setFcmTokenRequest(
            SetPushTokenRequest.FcmTokenRequest.newBuilder().setFcmToken("test-token")).build()}) {
      final StatusRuntimeException error = assertThrows(StatusRuntimeException.class,
          () -> authenticatedServiceStub().setPushToken(request));
      assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    }
    verifyNoInteractions(accounts);
  }

  @Test
  void restRejectsBothProvidersAndMapsFailureTo503() {
    final AccountController controller = new AccountController(accounts, mock(RateLimiters.class),
        mock(PhoneNumberRecoveryPasswordsManager.class), mock(UsernameHashZkProofVerifier.class), Set.of());
    final AuthenticatedDevice auth = new AuthenticatedDevice(AUTHENTICATED_ACI, (byte) 1, Instant.now());
    assertThatThrownBy(() -> controller.setApnRegistrationId(auth, new ApnRegistrationId("test-token")))
        .isInstanceOf(FeatureUnavailableException.class);
    assertThatThrownBy(() -> controller.setGcmRegistrationId(auth, new GcmRegistrationId("test-token")))
        .isInstanceOf(FeatureUnavailableException.class);
    assertThat(new FeatureUnavailableExceptionMapper().toResponse(new FeatureUnavailableException("test")).getStatus())
        .isEqualTo(503);
    verifyNoInteractions(accounts);
  }

  @Test
  void deviceLinkingCannotInstallUnsupportedPushTokens() {
    final var account = mock(org.whispersystems.textsecuregcm.storage.Account.class);
    when(accounts.checkDeviceLinkingToken("test-link-token")).thenReturn(java.util.Optional.of(AUTHENTICATED_ACI));
    when(accounts.getByAccountIdentifier(AUTHENTICATED_ACI)).thenReturn(java.util.Optional.of(account));
    final var controller = new org.whispersystems.textsecuregcm.controllers.DeviceController(accounts,
        mock(RateLimiters.class), mock(org.whispersystems.textsecuregcm.storage.PersistentTimer.class), Set.of());
    final var activation = mock(org.whispersystems.textsecuregcm.entities.DeviceActivationRequest.class);
    when(activation.apnToken()).thenReturn(java.util.Optional.of(new ApnRegistrationId("test-token")));
    when(activation.gcmToken()).thenReturn(java.util.Optional.empty());
    final var request = new org.whispersystems.textsecuregcm.entities.LinkDeviceRequest("test-link-token",
        mock(org.whispersystems.textsecuregcm.entities.DeviceAttributes.class), activation);
    assertThatThrownBy(() -> controller.linkDevice(null, null, request))
        .isInstanceOf(FeatureUnavailableException.class);
    verify(accounts).checkDeviceLinkingToken("test-link-token");
    verify(accounts).getByAccountIdentifier(AUTHENTICATED_ACI);
    verifyNoMoreInteractions(accounts);
    verifyNoInteractions(account);
  }
}
