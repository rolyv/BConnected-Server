/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;
import org.whispersystems.textsecuregcm.util.MockUtils;
import org.whispersystems.textsecuregcm.util.MutableClock;

public class RegistrationRecoveryTest {

  private static final MutableClock CLOCK = MockUtils.mutableClock(0);
  private static final Duration EXPIRATION = Duration.ofSeconds(1000);
  private static final UUID PNI = UUID.randomUUID();

  private static final SaltedTokenHash ORIGINAL_HASH = SaltedTokenHash.generateFor("pass1");
  private static final SaltedTokenHash ANOTHER_HASH = SaltedTokenHash.generateFor("pass2");

  @RegisterExtension
  static final PostgresAccountKeyTestExtension POSTGRES = new PostgresAccountKeyTestExtension();

  private PhoneNumberRecoveryPasswordStore phoneNumberRecoveryPasswords;

  private PhoneNumberRecoveryPasswordsManager manager;

  @BeforeEach
  public void before() throws Exception {
    CLOCK.setTimeMillis(Clock.systemUTC().millis());
    phoneNumberRecoveryPasswords = new PhoneNumberRecoveryPasswordsPostgres(POSTGRES.dataSource(), EXPIRATION, CLOCK);

    manager = new PhoneNumberRecoveryPasswordsManager(phoneNumberRecoveryPasswords);
  }

  @Test
  public void testLookupAfterWrite() throws Exception {
    assertTrue(phoneNumberRecoveryPasswords.addOrReplace(PNI, ORIGINAL_HASH));
    final long initialExp = fetchTimestamp(PNI);
    final long expectedExpiration = CLOCK.instant().getEpochSecond() + EXPIRATION.getSeconds();
    assertEquals(expectedExpiration, initialExp);

    final Optional<SaltedTokenHash> saltedTokenHashByPni = phoneNumberRecoveryPasswords.lookup(PNI);
    assertTrue(saltedTokenHashByPni.isPresent());
    assertEquals(ORIGINAL_HASH.salt(), saltedTokenHashByPni.get().salt());
    assertEquals(ORIGINAL_HASH.hash(), saltedTokenHashByPni.get().hash());
  }

  @Test
  public void testLookupAfterRefresh() throws Exception {
    phoneNumberRecoveryPasswords.addOrReplace(PNI, ORIGINAL_HASH);

    CLOCK.increment(50, TimeUnit.SECONDS);
    phoneNumberRecoveryPasswords.addOrReplace(PNI, ORIGINAL_HASH);
    final long updatedExp = fetchTimestamp(PNI);
    final long expectedExp = CLOCK.instant().getEpochSecond() + EXPIRATION.getSeconds();
    assertEquals(expectedExp, updatedExp);

    final Optional<SaltedTokenHash> saltedTokenHashByPni = phoneNumberRecoveryPasswords.lookup(PNI);
    assertTrue(saltedTokenHashByPni.isPresent());
    assertEquals(ORIGINAL_HASH.salt(), saltedTokenHashByPni.get().salt());
    assertEquals(ORIGINAL_HASH.hash(), saltedTokenHashByPni.get().hash());
  }

  @Test
  public void testReplace() {
    assertTrue(phoneNumberRecoveryPasswords.addOrReplace(PNI, ORIGINAL_HASH));
    assertFalse(phoneNumberRecoveryPasswords.addOrReplace(PNI, ANOTHER_HASH));

    final Optional<SaltedTokenHash> saltedTokenHashByPni = phoneNumberRecoveryPasswords.lookup(PNI);
    assertTrue(saltedTokenHashByPni.isPresent());
    assertEquals(ANOTHER_HASH.salt(), saltedTokenHashByPni.get().salt());
    assertEquals(ANOTHER_HASH.hash(), saltedTokenHashByPni.get().hash());
  }

  @Test
  public void testRemove() {
    assertFalse(phoneNumberRecoveryPasswords.removeEntry(PNI));

    phoneNumberRecoveryPasswords.addOrReplace(PNI, ORIGINAL_HASH);
    assertTrue(phoneNumberRecoveryPasswords.lookup(PNI).isPresent());

    assertTrue(phoneNumberRecoveryPasswords.removeEntry(PNI));
    assertTrue(phoneNumberRecoveryPasswords.lookup(PNI).isEmpty());
  }

  @Test
  public void testManagerFlow() {
    final byte[] password = "password".getBytes(StandardCharsets.UTF_8);
    final byte[] updatedPassword = "udpate".getBytes(StandardCharsets.UTF_8);
    final byte[] wrongPassword = "qwerty123".getBytes(StandardCharsets.UTF_8);

    // initial store
    manager.store(PNI, password);
    assertTrue(manager.verify(PNI, password));
    assertFalse(manager.verify(PNI, wrongPassword));

    // update
    manager.store(PNI, password);
    assertTrue(manager.verify(PNI, password));
    assertFalse(manager.verify(PNI, wrongPassword));

    // replace
    manager.store(PNI, updatedPassword);
    assertTrue(manager.verify(PNI, updatedPassword));
    assertFalse(manager.verify(PNI, password));
    assertFalse(manager.verify(PNI, wrongPassword));

    manager.remove(PNI);
    assertFalse(manager.verify(PNI, updatedPassword));
    assertFalse(manager.verify(PNI, password));
    assertFalse(manager.verify(PNI, wrongPassword));
  }

  private static long fetchTimestamp(final UUID phoneNumberIdentifier) throws Exception {
    try (var connection = POSTGRES.dataSource().getConnection();
        var statement = connection.prepareStatement("SELECT expires_at FROM signal.phone_recovery_passwords WHERE pni=?")) {
      statement.setObject(1, phoneNumberIdentifier);
      try (var rows = statement.executeQuery()) {
        assertTrue(rows.next());
        return rows.getLong(1);
      }
    }
  }
}
