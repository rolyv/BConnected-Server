// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.signal.chat.credentials.CredentialsGrpc;
import org.signal.chat.credentials.GetCreateCallLinkCredentialRequest;
import org.signal.chat.credentials.GetGroupCredentialsRequest;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.controllers.CertificateController;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;

class GcpCredentialsGrpcServiceTest extends SimpleBaseGrpcTest<CredentialsGrpcService, CredentialsGrpc.CredentialsBlockingStub> {
  private static final Instant NOW = Instant.parse("2026-09-20T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final ServerZkAuthOperations GROUPS = new ServerZkAuthOperations(ServerSecretParams.generate());
  private AccountsManager accounts;

  @Override
  protected CredentialsGrpcService createServiceBeforeEachTest() {
    accounts = mock(AccountsManager.class);
    final Account account = mock(Account.class);
    when(account.getAccountIdentifier()).thenReturn(AUTHENTICATED_ACI);
    when(account.getPhoneNumberIdentifier()).thenReturn(Optional.of(UUID.randomUUID()));
    when(accounts.getByAccountIdentifier(AUTHENTICATED_ACI)).thenReturn(Optional.of(account));
    return new CredentialsGrpcService(accounts, null, GROUPS, null, mock(RateLimiters.class), CLOCK, Map.of(), false);
  }

  @Test
  void groupCredentialsRemainAvailableWithoutCallingKeys() {
    final var response = authenticatedServiceStub().getGroupCredentials(GetGroupCredentialsRequest.newBuilder()
        .setRedemptionStartSeconds(NOW.getEpochSecond()).setRedemptionEndSeconds(NOW.getEpochSecond()).build());
    assertThat(response.getGroupCredentialsList()).hasSize(1);
    assertThat(response.getGroupCredentials(0).getCredential()).isNotEmpty();
    assertThat(response.getCallLinkAuthCredentialsList()).isEmpty();
  }

  @Test
  void callLinkIssuanceFailsExplicitlyWhenCallingIsDisabled() {
    final StatusRuntimeException error = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().getCreateCallLinkCredential(GetCreateCallLinkCredentialRequest.getDefaultInstance()));
    assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }

  @Test
  void restGroupCredentialsAlsoOmitCallCredentialsWithNoCallingKeys() {
    final CertificateController controller = new CertificateController(accounts, mock(org.whispersystems.textsecuregcm.auth.CertificateGenerator.class), GROUPS, null, null, CLOCK, false);
    final var result = controller.getGroupAuthenticationCredentials(
        new AuthenticatedDevice(AUTHENTICATED_ACI, (byte) 1, NOW), NOW.getEpochSecond(), NOW.getEpochSecond(), true);
    assertThat(result.credentials()).hasSize(1);
    assertThat(result.credentials().getFirst().credential()).isNotEmpty();
    assertThat(result.callLinkAuthCredentials()).isEmpty();
  }
}
