// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.util.*;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.auth.AccountOperationsPolicy;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.FeatureUnavailableExceptionMapper;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;
import org.whispersystems.textsecuregcm.util.UsernameHashZkProofVerifier;

/** Actual Jersey routing/validation with synthetic authentication; dependencies must remain untouched on rejection. */
@ExtendWith(DropwizardExtensionsSupport.class)
class PilotAccountOperationsTest {
  static final AccountsManager accounts = mock(AccountsManager.class);
  static final RateLimiters rates = mock(RateLimiters.class);
  static final PersistentTimer timer = mock(PersistentTimer.class);
  static final ChangeNumberManager numbers = mock(ChangeNumberManager.class);
  static final PhoneNumberRecoveryPasswordsManager recovery = mock(PhoneNumberRecoveryPasswordsManager.class);
  static final UsernameHashZkProofVerifier usernames = mock(UsernameHashZkProofVerifier.class);
  static final Set<PushNotification.TokenType> push = Set.of(PushNotification.TokenType.APN);
  static final ResourceExtension resources = ResourceExtension.builder()
      .setMapper(org.whispersystems.textsecuregcm.util.SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addProperty(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE, true)
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .addProvider(new FeatureUnavailableExceptionMapper())
      .addResource(new DeviceController(accounts, rates, timer, push, AccountOperationsPolicy.PILOT_PRIMARY_ONLY))
      .addResource(new AccountControllerV2(accounts, numbers, AccountOperationsPolicy.PILOT_PRIMARY_ONLY))
      .addResource(new AccountController(accounts, rates, recovery, usernames, push, AccountOperationsPolicy.PILOT_PRIMARY_ONLY))
      .build();

  @BeforeEach void setup() { reset(accounts, rates, timer, numbers, recovery, usernames); }
  String auth() { return AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD); }
  void rejected(Response response) {
    try (response) { assertThat(response.getStatus()).isEqualTo(503); }
    verifyNoInteractions(accounts, rates, timer, numbers, recovery, usernames);
  }

  @ParameterizedTest @ValueSource(strings = {"/v1/devices/provisioning/code",
      "/v1/devices/wait_for_linked_device/abcdefghijklmnopqrstuvwxyz123456",
      "/v1/devices/transfer_archive", "/v1/devices/restore_account/synthetic"})
  void deferredReadsCannotIssueTokensOrInstallListeners(String path) {
    rejected(resources.target(path).request().header("Authorization", auth()).get());
  }

  @Test void removeLinkedDeviceRejected() {
    rejected(resources.target("/v1/devices/2").request().header("Authorization", auth()).delete());
  }

  @Test void anonymousRestoreRejectedBeforeStore() {
    rejected(resources.target("/v1/devices/restore_account/synthetic").request().put(Entity.json(
        new RestoreAccountRequest(RestoreAccountRequest.Method.DEVICE_TRANSFER, new byte[32]))));
  }

  @Test void transferArchiveRejectedBeforeStore() {
    rejected(resources.target("/v1/devices/transfer_archive").request().header("Authorization", auth())
        .put(Entity.json(new TransferArchiveUploadedRequest((byte) 2, 123,
            new RemoteAttachment(3, Base64.getUrlEncoder().encodeToString(new byte[32]))))));
  }

  @Test void validLinkRequestCannotConsumeTokenOrInstallKeys() {
    var identity = ECKeyPair.generate();
    var request = new LinkDeviceRequest("synthetic-token",
        new DeviceAttributes(true, 123, null, null, DeviceCapability.CAPABILITIES_REQUIRED_FOR_NEW_DEVICES),
        new DeviceActivationRequest(KeysHelper.signedECPreKey(1, identity), Optional.empty(),
            KeysHelper.signedKEMPreKey(2, identity), Optional.empty(), Optional.empty(), Optional.empty()));
    rejected(resources.target("/v1/devices/link").request()
        .header("Authorization", AuthHelper.getProvisioningAuthHeader(AuthHelper.VALID_NUMBER, "synthetic-password"))
        .put(Entity.json(request)));
  }

  @Test void validNumberChangeCannotVerifyPhoneOrChangeIdentity() {
    var identity = ECKeyPair.generate();
    var request = new ChangeNumberRequest(Base64.getEncoder().encodeToString(new byte[32]), null,
        "+12025550199", null, new IdentityKey(identity.getPublicKey()), List.of(),
        Map.of((byte) 1, KeysHelper.signedECPreKey(1, identity)),
        Map.of((byte) 1, KeysHelper.signedKEMPreKey(2, identity)), Map.of((byte) 1, 123));
    rejected(resources.target("/v2/accounts/number").request().header("Authorization", auth()).put(Entity.json(request)));
  }

  @Test void mixedAttributeRequestWithRecoveryPasswordRejectsWholeMutation() {
    var attributes = new AccountAttributes(true, 123, 456, null, null, false,
        DeviceCapability.CAPABILITIES_REQUIRED_FOR_NEW_DEVICES, new byte[32]).setUnidentifiedAccessKey(new byte[16]);
    rejected(resources.target("/v1/accounts/attributes").request().header("Authorization", auth()).put(Entity.json(attributes)));
  }

  @Test void primaryNameCannotTargetLinkedDevice() {
    rejected(resources.target("/v1/accounts/name").queryParam("deviceId", 2).request()
        .header("Authorization", auth()).put(Entity.json(new DeviceName(new byte[16]))));
  }

  @Test void primaryReadAndApnsSetupRemainAvailable() {
    var account = mock(Account.class); var device = new Device(); device.setId(Device.PRIMARY_ID);
    when(account.getDevices()).thenReturn(List.of(device));
    when(accounts.getByAccountIdentifier(AuthHelper.VALID_UUID)).thenReturn(Optional.of(account));
    try (var response = resources.target("/v1/devices").request().header("Authorization", auth()).get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    try (var response = resources.target("/v1/accounts/apn").request().header("Authorization", auth())
        .put(Entity.json(new ApnRegistrationId("synthetic-token")))) {
      assertThat(response.getStatus()).isEqualTo(204);
    }
    verify(accounts).updateDevice(eq(AuthHelper.VALID_UUID), eq(Device.PRIMARY_ID), any());
  }
}
