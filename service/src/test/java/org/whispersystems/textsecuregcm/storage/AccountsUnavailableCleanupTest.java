// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.whispersystems.textsecuregcm.auth.DisconnectionRequestManager;
import org.whispersystems.textsecuregcm.auth.webauthn.WebAuthnCeremonyManager;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClient;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.securestorage.SecureStorageClient;
import org.whispersystems.textsecuregcm.securevaluerecovery.SecureValueRecoveryClient;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;

class AccountsUnavailableCleanupTest {
  @ParameterizedTest
  @CsvSource({"false,false", "true,false", "false,true"})
  void deletionRejectsBeforeAnyDestructiveWork(final boolean storageEnabled, final boolean svrEnabled) throws Exception {
    final UUID aci = UUID.randomUUID();
    final AccountStore accounts = mock(AccountStore.class);
    final Account account = mock(Account.class);
    when(accounts.getByAccountIdentifier(aci)).thenReturn(Optional.of(account));
    final AccountLockManager locks = mock(AccountLockManager.class);
    doAnswer(call -> {
      final org.whispersystems.textsecuregcm.util.ThrowingSupplier<?, ?> task = call.getArgument(1);
      return task.get();
    }).when(locks).withSingleAccountLock(any(Account.class), any());
    final KeysManager keys = mock(KeysManager.class);
    final MessagesManager messages = mock(MessagesManager.class);
    final ProfilesManager profiles = mock(ProfilesManager.class);
    final SecureStorageClient storage = mock(SecureStorageClient.class);
    final SecureValueRecoveryClient svr = mock(SecureValueRecoveryClient.class);
    final PhoneNumberRecoveryPasswordsManager recovery = mock(PhoneNumberRecoveryPasswordsManager.class);
    final DisconnectionRequestManager disconnections = mock(DisconnectionRequestManager.class);
    final AccountsManager manager = new AccountsManager(accounts, mock(PhoneNumberIdentifierStore.class),
        mock(FaultTolerantRedisClusterClient.class), mock(FaultTolerantRedisClient.class), locks, keys, messages, profiles,
        mock(ChangeNumberWaitingPeriodManager.class), storageEnabled ? storage : null, svrEnabled ? svr : null,
        disconnections, recovery, mock(ScheduledExecutorService.class), mock(ScheduledExecutorService.class),
        Clock.systemUTC(), new byte[32], Duration.ofSeconds(1), mock(WebAuthnCeremonyManager.class));
    assertThatThrownBy(() -> manager.delete(aci, AccountsManager.DeletionReason.USER_REQUEST))
        .isInstanceOf(FeatureUnavailableException.class);
    verify(accounts).getByAccountIdentifier(aci);
    verifyNoMoreInteractions(accounts);
    verifyNoInteractions(keys, messages, profiles, storage, svr, recovery, disconnections, account);
  }
}
