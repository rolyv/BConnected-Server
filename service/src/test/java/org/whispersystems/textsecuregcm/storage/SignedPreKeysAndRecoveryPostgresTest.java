// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.entities.SignedPreKey;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class SignedPreKeysAndRecoveryPostgresTest {
  private static final Instant NOW = Instant.parse("2026-09-20T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final Duration EXPIRATION = Duration.ofMinutes(1);
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private SignedPreKeysPostgres<ECSignedPreKey> ec;
  private SignedPreKeysPostgres<KEMSignedPreKey> kem;
  private PhoneNumberRecoveryPasswordsPostgres recovery;
  private ECKeyPair identity;

  @BeforeEach
  void setUp() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      statement.execute("TRUNCATE signal.signed_prekeys, signal.phone_recovery_passwords");
    }
    executor = Executors.newFixedThreadPool(12);
    ec = SignedPreKeysPostgres.ec(dataSource, executor);
    kem = SignedPreKeysPostgres.kem(dataSource, executor);
    recovery = new PhoneNumberRecoveryPasswordsPostgres(dataSource, EXPIRATION, CLOCK);
    identity = ECKeyPair.generate();
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
    }
  }

  private void transact(final List<AccountMutation> mutations) throws SQLException {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        AccountMutation.executeSql(connection, mutations);
        connection.commit();
      } catch (SQLException | RuntimeException e) {
        connection.rollback();
        throw e;
      }
    }
  }

  private void assertSameKey(final SignedPreKey<?> actual, final SignedPreKey<?> expected) {
    assertThat(actual.keyId()).isEqualTo(expected.keyId());
    assertThat(actual.serializedPublicKey()).isEqualTo(expected.serializedPublicKey());
    assertThat(actual.signature()).isEqualTo(expected.signature());
  }

  @Test
  void ecAndKemPublicKeysAndSignaturesRoundTripUsingLibsignal() {
    UUID account = UUID.randomUUID();
    ECSignedPreKey ecKey = KeysHelper.signedECPreKey(KeyIdUtil.MIN_KEY_ID, identity);
    KEMSignedPreKey kemKey = KeysHelper.signedKEMPreKey(KeyIdUtil.MAX_KEY_ID, identity);
    ec.store(account, (byte) 1, ecKey).join();
    kem.store(account, (byte) 1, kemKey).join();
    assertSameKey(ec.find(account, (byte) 1).join().orElseThrow(), ecKey);
    assertSameKey(kem.find(account, (byte) 1).join().orElseThrow(), kemKey);
    // These are repeated-use keys: reads do not consume them.
    assertSameKey(ec.find(account, (byte) 1).join().orElseThrow(), ecKey);
    assertSameKey(kem.find(account, (byte) 1).join().orElseThrow(), kemKey);
    assertThat(ec.find(UUID.randomUUID(), (byte) 1).join()).isEmpty();
    assertThat(ec.find(account, (byte) 2).join()).isEmpty();
  }

  @Test
  void replacementAndDeletionAreScopedByIdentityDeviceAndKeyKind() throws Exception {
    UUID account = UUID.randomUUID();
    UUID other = UUID.randomUUID();
    ECSignedPreKey initial = KeysHelper.signedECPreKey(1, identity);
    ECSignedPreKey replacement = KeysHelper.signedECPreKey(2, identity);
    KEMSignedPreKey kemKey = KeysHelper.signedKEMPreKey(3, identity);
    ec.store(account, (byte) 1, initial).join();
    ec.store(account, (byte) 2, initial).join();
    ec.store(other, (byte) 1, initial).join();
    kem.store(account, (byte) 1, kemKey).join();
    ec.store(account, (byte) 1, replacement).join();
    assertSameKey(ec.find(account, (byte) 1).join().orElseThrow(), replacement);
    transact(List.of(ec.buildDeletion(account, (byte) 1)));
    assertThat(ec.find(account, (byte) 1).join()).isEmpty();
    assertSameKey(ec.find(account, (byte) 2).join().orElseThrow(), initial);
    assertSameKey(ec.find(other, (byte) 1).join().orElseThrow(), initial);
    assertSameKey(kem.find(account, (byte) 1).join().orElseThrow(), kemKey);
    transact(List.of(kem.buildDeletion(account, (byte) 1)));
    assertThat(kem.find(account, (byte) 1).join()).isEmpty();
  }

  @Test
  void recoveryHashesRetainUpstreamExtantRowSemanticsUntilPhysicalExpiry() throws Exception {
    UUID pni = UUID.randomUUID();
    SaltedTokenHash original = SaltedTokenHash.generateFor("original synthetic recovery token");
    SaltedTokenHash replacement = SaltedTokenHash.generateFor("replacement synthetic recovery token");
    assertThat(recovery.addOrReplace(pni, original)).isTrue();
    assertThat(recovery.lookup(pni)).contains(original);
    assertThat(recovery.addOrReplace(pni, replacement)).isFalse();
    assertThat(recovery.lookup(pni)).contains(replacement);
    assertThat(recovery.lookup(pni).orElseThrow().verify("replacement synthetic recovery token")).isTrue();
    var beforeExpiry = new PhoneNumberRecoveryPasswordsPostgres(dataSource, EXPIRATION,
        Clock.fixed(NOW.plusSeconds(59), ZoneOffset.UTC));
    assertThat(beforeExpiry.lookup(pni)).contains(replacement);
    var atExpiry = new PhoneNumberRecoveryPasswordsPostgres(dataSource, EXPIRATION,
        Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC));
    assertThat(atExpiry.lookup(pni)).contains(replacement);
    assertThat(atExpiry.deleteExpired(10)).isZero();
    var afterExpiry = new PhoneNumberRecoveryPasswordsPostgres(dataSource, EXPIRATION,
        Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC));
    assertThat(afterExpiry.lookup(pni)).contains(replacement);
    transact(List.of(afterExpiry.buildConditionMutationForMigration(pni, replacement)));
    assertThat(afterExpiry.deleteExpired(1)).isEqualTo(1);
    assertThat(afterExpiry.lookup(pni)).isEmpty();
    assertThrows(ContestedOptimisticLockException.class,
        () -> transact(List.of(afterExpiry.buildConditionMutationForMigration(pni, replacement))));
    assertThat(recovery.removeEntry(pni)).isFalse();
    assertThat(recovery.addOrReplace(pni, original)).isTrue();
    assertThat(recovery.removeEntry(pni)).isTrue();
    assertThat(recovery.removeEntry(pni)).isFalse();
    assertThat(recovery.lookup(pni)).isEmpty();
  }

  @Test
  void migrationRequiresTheSameSaltAndHashAndAnExistingPassword() throws Exception {
    UUID pni = UUID.randomUUID();
    SaltedTokenHash original = SaltedTokenHash.generateFor("synthetic recovery token");
    SaltedTokenHash changed = SaltedTokenHash.generateFor("different synthetic recovery token");
    recovery.addOrReplace(pni, original);
    transact(List.of(recovery.buildConditionMutationForMigration(pni, original)));
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(
        recovery.buildConditionMutationForMigration(pni, new SaltedTokenHash(original.hash(), changed.salt())))));
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(
        recovery.buildConditionMutationForMigration(pni, new SaltedTokenHash(changed.hash(), original.salt())))));
    AccountMutation checkBeforeRotation = recovery.buildConditionMutationForMigration(pni, original);
    recovery.addOrReplace(pni, changed);
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(checkBeforeRotation)));
    assertThrows(ContestedOptimisticLockException.class, () -> transact(List.of(
        recovery.buildConditionMutationForMigration(UUID.randomUUID(), original))));
    transact(List.of(recovery.buildConditionMutationForMigration(pni, changed), recovery.buildMutationForRemove(pni)));
    assertThat(recovery.lookup(pni)).isEmpty();
  }

  @Test
  void signedKeysAndRecoveryPasswordRollbackTogetherOnALateFailure() throws Exception {
    UUID account = UUID.randomUUID();
    UUID pni = UUID.randomUUID();
    ECSignedPreKey ecOriginal = KeysHelper.signedECPreKey(1, identity);
    KEMSignedPreKey kemOriginal = KeysHelper.signedKEMPreKey(1, identity);
    SaltedTokenHash recoveryOriginal = SaltedTokenHash.generateFor("original synthetic recovery token");
    ec.store(account, (byte) 1, ecOriginal).join();
    kem.store(account, (byte) 1, kemOriginal).join();
    recovery.addOrReplace(pni, recoveryOriginal);
    ECSignedPreKey ecReplacement = KeysHelper.signedECPreKey(2, identity);
    KEMSignedPreKey kemReplacement = KeysHelper.signedKEMPreKey(2, identity);
    SaltedTokenHash recoveryReplacement = SaltedTokenHash.generateFor("replacement synthetic recovery token");
    List<AccountMutation> replacements = List.of(ec.buildInsertion(account, (byte) 1, ecReplacement),
        kem.buildInsertion(account, (byte) 1, kemReplacement),
        recovery.buildMutationForAddOrReplace(pni, recoveryReplacement));
    var failingMutations = new ArrayList<>(replacements);
    failingMutations.add(new AccountMutation.Sql(connection -> { throw new SQLException("Synthetic late transaction failure"); }));
    assertThrows(SQLException.class, () -> transact(failingMutations));
    assertSameKey(ec.find(account, (byte) 1).join().orElseThrow(), ecOriginal);
    assertSameKey(kem.find(account, (byte) 1).join().orElseThrow(), kemOriginal);
    assertThat(recovery.lookup(pni)).contains(recoveryOriginal);
    transact(replacements);
    assertSameKey(ec.find(account, (byte) 1).join().orElseThrow(), ecReplacement);
    assertSameKey(kem.find(account, (byte) 1).join().orElseThrow(), kemReplacement);
    assertThat(recovery.lookup(pni)).contains(recoveryReplacement);
  }

  @Test
  void mixedBackendsAreRejectedBeforeAnySqlMutationExecutes() throws Exception {
    UUID pni = UUID.randomUUID();
    AtomicInteger executed = new AtomicInteger();
    AccountMutation sql = new AccountMutation.Sql(connection -> executed.incrementAndGet());
    AccountMutation dynamo = new AccountMutation.Dynamo(TransactWriteItem.builder().build());
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      assertThrows(IllegalArgumentException.class, () -> AccountMutation.executeSql(connection, List.of(sql,
          recovery.buildMutationForAddOrReplace(pni, SaltedTokenHash.generateFor("synthetic token")), dynamo)));
      // Commit deliberately: backend validation must prevent writes, not merely rely on rollback after a partial write.
      connection.commit();
    }
    assertThat(executed).hasValue(0);
    assertThat(recovery.lookup(pni)).isEmpty();
    assertThrows(IllegalArgumentException.class, () -> AccountMutation.toDynamo(List.of(dynamo, sql)));
    assertThat(AccountMutation.toDynamo(List.of(dynamo))).containsExactly(dynamo.dynamoItem());
  }

  @Test
  void sqlMutationsRejectAutoCommitConnections() throws Exception {
    AtomicInteger executed = new AtomicInteger();
    AccountMutation mutation = new AccountMutation.Sql(connection -> executed.incrementAndGet());
    try (var connection = dataSource.getConnection()) {
      assertThat(connection.getAutoCommit()).isTrue();
      assertThrows(IllegalStateException.class, () -> mutation.applySql(connection));
    }
    assertThat(executed).hasValue(0);
  }

  @Test
  void concurrentRecoveryReplacementsReportOnlyOneInitialInsertion() {
    UUID pni = UUID.randomUUID();
    var candidates = new ArrayList<SaltedTokenHash>();
    var writes = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < 30; i++) {
      SaltedTokenHash candidate = SaltedTokenHash.generateFor("synthetic token " + i);
      candidates.add(candidate);
      writes.add(CompletableFuture.supplyAsync(() -> recovery.addOrReplace(pni, candidate), executor));
    }
    assertThat(writes.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    assertThat(candidates).contains(recovery.lookup(pni).orElseThrow());
  }
}
