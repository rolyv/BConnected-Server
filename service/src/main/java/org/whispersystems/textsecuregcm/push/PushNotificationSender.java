/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.push;

import java.util.concurrent.CompletableFuture;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;

public interface PushNotificationSender {

  CompletableFuture<SendPushNotificationResult> sendNotification(PushNotification notification);

  default boolean isUnavailable() { return false; }

  static PushNotificationSender unavailable(final String provider) {
    return new PushNotificationSender() {
      @Override
      public boolean isUnavailable() { return true; }

      @Override
      public CompletableFuture<SendPushNotificationResult> sendNotification(final PushNotification notification) {
        return CompletableFuture.failedFuture(
            new FeatureUnavailableException(provider + " push notifications"));
      }
    };
  }
}
