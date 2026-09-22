// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.signal.chat.device.*;
import org.whispersystems.textsecuregcm.auth.AccountOperationsPolicy;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.storage.Device;

class PilotDeviceOperationsGrpcTest extends SimpleBaseGrpcTest<DevicesGrpcService, DevicesGrpc.DevicesBlockingStub> {
  AccountsManager accounts;
  @Override protected DevicesGrpcService createServiceBeforeEachTest() {
    accounts = mock(AccountsManager.class);
    return new DevicesGrpcService(accounts, Set.of(PushNotification.TokenType.APN), AccountOperationsPolicy.PILOT_PRIMARY_ONLY);
  }
  @Test void removalRejectedBeforeAccountMutation() {
    var failure = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().removeDevice(RemoveDeviceRequest.newBuilder().setId(2).build()));
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(accounts);
  }
  @Test void namingLinkedDeviceRejectedBeforeLookup() {
    var failure = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().setDeviceName(SetDeviceNameRequest.newBuilder().setId(2)
            .setName(ByteString.copyFrom(new byte[16])).build()));
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(accounts);
  }
  @Test void primaryDeviceReadAndPushSetupRemainAvailable() {
    var account = mock(Account.class); var device = new Device(); device.setId(Device.PRIMARY_ID);
    device.setCreatedAtCiphertext(new byte[16]);
    when(account.getAccountIdentifier()).thenReturn(AUTHENTICATED_ACI);
    when(account.getDevices()).thenReturn(List.of(device));
    when(account.getDevice(Device.PRIMARY_ID)).thenReturn(Optional.of(device));
    when(accounts.getByAccountIdentifier(AUTHENTICATED_ACI)).thenReturn(Optional.of(account));
    assertThat(authenticatedServiceStub().getDevices(GetDevicesRequest.getDefaultInstance()).getDevicesCount()).isEqualTo(1);
    authenticatedServiceStub().setPushToken(SetPushTokenRequest.newBuilder().setApnsTokenRequest(
        SetPushTokenRequest.ApnsTokenRequest.newBuilder().setApnsToken("synthetic-token")).build());
    verify(accounts).updateDevice(eq(AUTHENTICATED_ACI), eq(Device.PRIMARY_ID), any());
  }
}
