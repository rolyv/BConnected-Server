// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.chat.account.*;
import org.whispersystems.textsecuregcm.auth.AccountOperationsPolicy;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.AccountsManager;

class PilotAnonymousDiscoveryGrpcTest extends SimpleBaseGrpcTest<AccountsAnonymousGrpcService, AccountsAnonymousGrpc.AccountsAnonymousBlockingStub> {
  AccountsManager accounts; RateLimiters rates; GroupSendTokenUtil tokens;
  @Override protected AccountsAnonymousGrpcService createServiceBeforeEachTest() {
    accounts = mock(AccountsManager.class); rates = mock(RateLimiters.class); tokens = mock(GroupSendTokenUtil.class);
    return new AccountsAnonymousGrpcService(accounts, rates, tokens, AccountOperationsPolicy.PILOT_PRIMARY_ONLY);
  }
  @ParameterizedTest @ValueSource(ints={0,1,2,3})
  void allAnonymousDiscoveryRejectsBeforeLookupOrTokenValidation(int route) {
    var identifier = GrpcServiceIdentifierUtil.toGrpcServiceIdentifier(new org.whispersystems.textsecuregcm.identity.AciServiceIdentifier(java.util.UUID.randomUUID()));
    var failure = assertThrows(StatusRuntimeException.class, () -> {
      switch (route) {
        case 0 -> unauthenticatedServiceStub().checkAccountExistence(CheckAccountExistenceRequest.newBuilder().setServiceIdentifier(identifier).build());
        case 1 -> unauthenticatedServiceStub().lookupUsernameHash(LookupUsernameHashRequest.newBuilder().setUsernameHash(com.google.protobuf.ByteString.copyFrom(new byte[32])).build());
        case 2 -> unauthenticatedServiceStub().lookupUsernameLink(LookupUsernameLinkRequest.newBuilder().setUsernameLinkHandle(com.google.protobuf.ByteString.copyFrom(new byte[16])).build());
        default -> unauthenticatedServiceStub().getCapabilities(GetCapabilitiesAnonymousRequest.newBuilder().setAccountIdentifier(identifier).setUnidentifiedAccessKey(com.google.protobuf.ByteString.copyFrom(new byte[16])).build());
      }
    });
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(accounts, rates, tokens);
  }
}
