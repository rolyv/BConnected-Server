// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.captcha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class UnavailableCaptchaClientTest {
  @ParameterizedTest
  @EnumSource(Action.class)
  void unavailableCaptchaNeverAcceptsASolution(final Action action) {
    final CaptchaClient captcha = CaptchaClient.unavailable();
    assertThat(captcha.validSiteKeys(action)).isEmpty();
    assertThrows(IOException.class, () -> captcha.verify(Optional.empty(), "noop", action, "anything", "192.0.2.1", null));
  }
}
