// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.push;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;

class UnavailablePushTest {
  @ParameterizedTest
  @EnumSource(PushNotification.TokenType.class)
  void directAndBackgroundPushNeverReportSuccessOrQueueWork(final PushNotification.TokenType type) {
    final PushNotificationSender unavailable = PushNotificationSender.unavailable(type.name());
    final PushNotificationScheduler scheduler = mock(PushNotificationScheduler.class);
    final AccountsManager accounts = mock(AccountsManager.class);
    final PushNotificationManager manager = new PushNotificationManager(accounts, unavailable, unavailable, scheduler);
    for (boolean urgent : new boolean[] {true, false}) {
      final PushNotification notification = new PushNotification("test-token", type,
          PushNotification.NotificationType.NOTIFICATION, null, mock(Account.class), mock(Device.class), urgent, null);
      assertThatThrownBy(() -> manager.sendNotification(notification).join())
          .hasCauseInstanceOf(FeatureUnavailableException.class);
    }
    verifyNoInteractions(scheduler, accounts);
  }

  @ParameterizedTest
  @EnumSource(PushNotification.TokenType.class)
  void schedulerRejectsDisabledProvidersBeforeRedisWrites(final PushNotification.TokenType type) throws Exception {
    final FaultTolerantRedisClusterClient redis = mock(FaultTolerantRedisClusterClient.class);
    final PushNotificationSender unavailable = PushNotificationSender.unavailable(type.name());
    final PushNotificationScheduler scheduler = new PushNotificationScheduler(redis, unavailable, unavailable,
        mock(AccountsManager.class), 0, 0, mock(ScheduledExecutorService.class));
    final Device device = mock(Device.class);
    if (type == PushNotification.TokenType.APN) when(device.getApnId()).thenReturn("test-token");
    else when(device.getGcmId()).thenReturn("test-token");
    final Account account = mock(Account.class);
    clearInvocations(redis);
    assertThatThrownBy(() -> scheduler.scheduleBackgroundNotification(type, account, device).toCompletableFuture().join())
        .hasCauseInstanceOf(FeatureUnavailableException.class);
    assertThatThrownBy(() -> scheduler.scheduleDelayedNotification(account, device, Duration.ofSeconds(1)).join())
        .hasCauseInstanceOf(FeatureUnavailableException.class);
    assertThatThrownBy(() -> scheduler.sendBackgroundNotification(type, account, device).join())
        .hasCauseInstanceOf(FeatureUnavailableException.class);
    assertThatThrownBy(() -> scheduler.sendDelayedNotification(account, device).join())
        .hasCauseInstanceOf(FeatureUnavailableException.class);
    verifyNoInteractions(redis);
  }
}
