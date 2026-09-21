/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.auth.DisconnectionRequestManager;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.DeviceAttributes;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.securestorage.SecureStorageClient;
import org.whispersystems.textsecuregcm.securevaluerecovery.SecureValueRecoveryClient;
import org.whispersystems.textsecuregcm.tests.util.AccountsHelper;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;

public class AccountsManagerMigrateRecoveryPasswordIntegrationTest {
  @RegisterExtension
  static final PostgresAccountKeyTestExtension POSTGRES = new PostgresAccountKeyTestExtension();

  @RegisterExtension
  static final RedisClusterExtension CACHE_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  private PhoneNumberRecoveryPasswordsManager phoneNumberRecoveryPasswordsManager;
  private ScheduledExecutorService executor;

  private AccountsManager accountsManager;

  @BeforeEach
  void setup() throws InterruptedException {

    {

      final KeysManager keysManager = POSTGRES.keys();

      final AccountStore accounts = POSTGRES.accounts(Clock.systemUTC());

      executor = Executors.newSingleThreadScheduledExecutor();

      final AccountLockManager accountLockManager = POSTGRES.locks();

      final SecureStorageClient secureStorageClient = mock(SecureStorageClient.class);
      when(secureStorageClient.deleteStoredData(any())).thenReturn(CompletableFuture.completedFuture(null));

      final SecureValueRecoveryClient svr2Client = mock(SecureValueRecoveryClient.class);
      when(svr2Client.removeData(any(UUID.class))).thenReturn(CompletableFuture.completedFuture(null));

      final DisconnectionRequestManager disconnectionRequestManager = mock(DisconnectionRequestManager.class);

      final PhoneNumberIdentifierStore phoneNumberIdentifiers =
          POSTGRES.phoneNumbers();

      final MessagesManager messagesManager = mock(MessagesManager.class);
      when(messagesManager.clear(any())).thenReturn(CompletableFuture.completedFuture(null));

      final ProfilesManager profilesManager = mock(ProfilesManager.class);
      when(profilesManager.deleteAll(any(), anyBoolean())).thenReturn(CompletableFuture.completedFuture(null));

      final PhoneNumberRecoveryPasswordStore phoneNumberRecoveryPasswords =
          POSTGRES.recovery(Clock.systemUTC());

      phoneNumberRecoveryPasswordsManager = new PhoneNumberRecoveryPasswordsManager(phoneNumberRecoveryPasswords);

      accountsManager = new AccountsManager(
          accounts,
          phoneNumberIdentifiers,
          CACHE_CLUSTER_EXTENSION.getRedisCluster(),
          mock(FaultTolerantRedisClient.class),
          accountLockManager,
          keysManager,
          messagesManager,
          profilesManager,
          mock(ChangeNumberWaitingPeriodManager.class),
          secureStorageClient,
          svr2Client,
          disconnectionRequestManager,
          phoneNumberRecoveryPasswordsManager,
          executor,
          executor,
          mock(Clock.class),
          "link-device-secret".getBytes(StandardCharsets.UTF_8),
          AccountsManager.TOTP.getTimeStep().dividedBy(2),
          null);
    }
  }

  @AfterEach
  void tearDown() throws InterruptedException {
    executor.shutdown();

    //noinspection ResultOfMethodCallIgnored
    executor.awaitTermination(1, TimeUnit.SECONDS);
  }

  @Test
  void migrateAccountRecoveryPassword() throws InterruptedException {
    final String phoneNumber = PhoneNumberUtil.getInstance().format(
        PhoneNumberUtil.getInstance().getExampleNumber("US"), PhoneNumberUtil.PhoneNumberFormat.E164);

    final Account account = new AccountsHelper.AccountBuilder(accountsManager)
        .e164(phoneNumber)
        .accountAttributes(new AccountAttributes()
            // No recoveryPassword
            .setDeviceAttributes(new DeviceAttributes(false, 1, 1, new byte[0], Collections.emptySet())))
        .build();

    final UUID phoneNumberIdentifier = account.getPhoneNumberIdentifier().orElseThrow();
    final byte[] recoveryPassword = TestRandomUtil.nextBytes(16);

    phoneNumberRecoveryPasswordsManager.store(phoneNumberIdentifier, recoveryPassword);

    assertFalse(accountsManager.getByAccountIdentifier(account.getAccountIdentifier())
        .orElseThrow()
        .getAccountRecoveryPassword()
        .isPresent());

    accountsManager.migrateAccountRecoveryPassword(account);

    assertTrue(accountsManager.getByAccountIdentifier(account.getAccountIdentifier())
        .orElseThrow()
        .getAccountRecoveryPassword()
        .isPresent());
  }
}
