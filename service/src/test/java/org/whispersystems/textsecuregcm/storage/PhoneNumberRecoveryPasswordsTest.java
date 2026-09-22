/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;

class PhoneNumberRecoveryPasswordsTest {
  @RegisterExtension
  static final PostgresAccountKeyTestExtension POSTGRES = new PostgresAccountKeyTestExtension();

  private PhoneNumberRecoveryPasswordStore passwords;

  @BeforeEach
  void setUp() {
    passwords = POSTGRES.recovery(Clock.systemUTC());
  }

  @Test
  void migrationConditionRejectsChangedAndRemovedPassword() {
    UUID pni = UUID.randomUUID();
    SaltedTokenHash original = SaltedTokenHash.generateFor("synthetic-original");
    passwords.addOrReplace(pni, original);
    AccountMutation condition = passwords.buildConditionMutationForMigration(pni, original);
    assertDoesNotThrow(() -> transact(List.of(condition)));

    passwords.addOrReplace(pni, SaltedTokenHash.generateFor("synthetic-changed"));
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(condition)));
    passwords.removeEntry(pni);
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(condition)));
  }

  @Test
  void failedMigrationConditionRollsBackOtherRecoveryChanges() {
    UUID checked = UUID.randomUUID(), created = UUID.randomUUID();
    SaltedTokenHash original = SaltedTokenHash.generateFor("synthetic-original");
    SaltedTokenHash changed = SaltedTokenHash.generateFor("synthetic-changed");
    passwords.addOrReplace(checked, changed);
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(
        passwords.buildMutationForAddOrReplace(created, original),
        passwords.buildConditionMutationForMigration(checked, original))));
    assertTrue(passwords.lookup(created).isEmpty());
    assertEquals(changed, passwords.lookup(checked).orElseThrow());
  }

  private void transact(List<AccountMutation> mutations) throws SQLException {
    try (var connection = POSTGRES.dataSource().getConnection()) {
      connection.setAutoCommit(false);
      try {
        AccountMutation.executeSql(connection, mutations);
        connection.commit();
      } catch (SQLException | RuntimeException failure) {
        connection.rollback();
        throw failure;
      }
    }
  }
}
