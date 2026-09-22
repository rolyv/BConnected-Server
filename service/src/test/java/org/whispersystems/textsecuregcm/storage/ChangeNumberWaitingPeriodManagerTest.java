/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

class ChangeNumberWaitingPeriodManagerTest {

  @RegisterExtension
  static final PostgresAccountKeyTestExtension POSTGRES = new PostgresAccountKeyTestExtension();

  private static final Duration WAITING_PERIOD = Duration.ofDays(7);

  private ChangeNumberWaitingPeriodManager changeNumberWaitingPeriodManager;

  @BeforeEach
  void setUp() {
    changeNumberWaitingPeriodManager = new ChangeNumberWaitingPeriodManager(
        new ChangeNumberWaitingPeriodsPostgres(POSTGRES.dataSource(), Clock.systemUTC()),
        WAITING_PERIOD,
        Clock.systemUTC());
  }

  @Test
  void testNewAccount() {
    final UUID aci = UUID.randomUUID();

    assertTrue(changeNumberWaitingPeriodManager.getWaitingPeriodRemaining(aci).isEmpty());

    changeNumberWaitingPeriodManager.handleAccountCreated(aci, Instant.now());

    assertTrue(changeNumberWaitingPeriodManager.getWaitingPeriodRemaining(aci).isPresent());
  }

  @Test
  void testOldAccount() {
    final UUID aci = UUID.randomUUID();

    changeNumberWaitingPeriodManager.handleAccountCreated(aci, Instant.now().minus(WAITING_PERIOD).minus(Duration.ofHours(1)));

    assertTrue(changeNumberWaitingPeriodManager.getWaitingPeriodRemaining(aci).isEmpty());
  }
}
