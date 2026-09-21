// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.ExpectedBinding;
import org.whispersystems.textsecuregcm.admission.AdmissionPermitVerifier.VerifiedPermit;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountMutation;
import org.whispersystems.textsecuregcm.storage.AccountsPostgres;
import org.whispersystems.textsecuregcm.storage.SignedPreKeysPostgres;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionLedgerPostgresTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private MutableClock clock;
  private AccountsPostgres accounts;
  private AdmissionLedger ledger;
  private AdmissionPermitVerifier verifier;
  private KeyPair key;
  private ExpectedBinding binding;

  @BeforeEach
  void setup() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require an isolated local _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var c = dataSource.getConnection();
        var statement = c.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/012-admission.sql")));
      statement.execute(
          "TRUNCATE"
              + " signal.admission_confirmation_outbox,signal.admissions,signal.accounts,signal.deleted_accounts,signal.signed_prekeys");
      statement.execute(
          "ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT IF EXISTS"
              + " test_reject_confirmation");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    executor = Executors.newFixedThreadPool(8);
    accounts = new AccountsPostgres(dataSource, clock, executor);
    ledger = new AdmissionLedger(dataSource, clock);
    key = AdmissionTestData.keys();
    verifier = new AdmissionPermitVerifier(Map.of("test-key", key.getPublic()), clock);
    binding = AdmissionTestData.binding("+18005550100");
  }

  @AfterEach
  void close() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
    }
  }

  private VerifiedPermit permit(ExpectedBinding value, String id) throws Exception {
    return verifier.verify(
        AdmissionTestData.sign(
            key,
            AdmissionTestData.header(),
            AdmissionTestData.claims(value, id, clock.instant().getEpochSecond())),
        value);
  }

  private Account account(String number) {
    var result = new Account();
    result.setAccountIdentifier(UUID.randomUUID());
    result.setNumber(number, UUID.randomUUID());
    result.addDevice(DevicesHelper.createDevice((byte) 1, clock.millis(), 100));
    result.setUnidentifiedAccessKey(new byte[16]);
    result.setAccountRecoveryPassword(new byte[16]);
    return result;
  }

  private int count(String table) throws SQLException {
    if (!List.of("admissions", "admission_confirmation_outbox", "accounts", "signed_prekeys")
        .contains(table)) throw new IllegalArgumentException();
    try (var c = dataSource.getConnection();
        var s = c.createStatement();
        var rows = s.executeQuery("SELECT count(*) FROM signal." + table)) {
      rows.next();
      return rows.getInt(1);
    }
  }

  private void assertEmpty() throws SQLException {
    for (String table :
        List.of("admissions", "admission_confirmation_outbox", "accounts", "signed_prekeys"))
      assertThat(count(table)).isZero();
  }

  @Test
  void accountRedemptionAndConfirmationWorkCommitTogetherAndRemainPending() throws Exception {
    var permit = permit(binding, AdmissionTestData.id());
    var candidate = account(binding.canonicalVerifiedNumber());
    accounts.createWithMutations(candidate, List.of(ledger.pendingMutation(permit, candidate)));
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("admissions")).isEqualTo(1);
    assertThat(count("admission_confirmation_outbox")).isEqualTo(1);
    var record = ledger.findByOperation(binding.signalOperationId()).orElseThrow();
    assertThat(record.status()).isEqualTo("PENDING");
    assertThat(record.confirmed()).isFalse();
    assertThat(record.confirmationAttempts()).isZero();
    assertThat(record.aci()).isEqualTo(candidate.getAccountIdentifier());
    assertThat(record.serverRequestCommitment()).isEqualTo(binding.serverRequestCommitment());
    assertThat(record.serverVerificationSessionHash())
        .isEqualTo(binding.serverVerificationSessionHash());
    assertThat(record.memberId()).isEqualTo(binding.memberId());
    assertThat(record.permitId()).isEqualTo(permit.permitId());
  }

  @Test
  void lateAccountMutationFailureRollsBackAccountPermitAndOutbox() throws Exception {
    var candidate = account(binding.canonicalVerifiedNumber());
    var permit = permit(binding, AdmissionTestData.id());
    var keyMutation =
        SignedPreKeysPostgres.ec(dataSource, executor)
            .buildInsertion(
                candidate.getAccountIdentifier(),
                (byte) 1,
                new ECSignedPreKey(1, ECKeyPair.generate().getPublicKey(), new byte[64]));
    var lateFailure =
        new AccountMutation.Sql(
            c -> {
              throw new SQLException("synthetic late failure");
            });
    assertThrows(
        RuntimeException.class,
        () ->
            accounts.createWithMutations(
                candidate,
                List.of(keyMutation, ledger.pendingMutation(permit, candidate), lateFailure)));
    assertEmpty();
    accounts.createWithMutations(
        candidate, List.of(keyMutation, ledger.pendingMutation(permit, candidate)));
    assertThat(count("admissions")).isEqualTo(1);
    assertThat(count("signed_prekeys")).isEqualTo(1);
  }

  @Test
  void failedOutboxInsertRollsBackItsEarlierAdmissionAndAccount() throws Exception {
    try (var c = dataSource.getConnection();
        var s = c.createStatement()) {
      s.execute(
          "ALTER TABLE signal.admission_confirmation_outbox ADD CONSTRAINT test_reject_confirmation"
              + " CHECK (false) NOT VALID");
    }
    var candidate = account(binding.canonicalVerifiedNumber());
    var permit = permit(binding, AdmissionTestData.id());
    assertThrows(
        RuntimeException.class,
        () ->
            accounts.createWithMutations(
                candidate, List.of(ledger.pendingMutation(permit, candidate))));
    assertEmpty();
  }

  @Test
  void noAutocommitOrNonexistentAccountCanRedeemAPermit() throws Exception {
    var candidate = account(binding.canonicalVerifiedNumber());
    var mutation = ledger.pendingMutation(permit(binding, AdmissionTestData.id()), candidate);
    try (var c = dataSource.getConnection()) {
      assertThrows(IllegalStateException.class, () -> mutation.operation().apply(c));
      c.setAutoCommit(false);
      assertThrows(AdmissionLedger.AdmissionConflictException.class, () -> mutation.applySql(c));
      c.rollback();
    }
    assertEmpty();
  }

  @Test
  void actualInsertedPhoneMustMatchVerifiedServerBinding() throws Exception {
    var permit = permit(binding, AdmissionTestData.id());
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () -> ledger.pendingMutation(permit, account("+18005550999")));
    var candidate = account(binding.canonicalVerifiedNumber());
    var mutation = ledger.pendingMutation(permit, candidate);
    candidate.setNumber("+18005550888", UUID.randomUUID());
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () -> accounts.createWithMutations(candidate, List.of(mutation)));
    assertEmpty();
  }

  @Test
  void expiryAfterVerificationStillPreventsAccountCreation() throws Exception {
    var permit = permit(binding, AdmissionTestData.id());
    var candidate = account(binding.canonicalVerifiedNumber());
    var mutation = ledger.pendingMutation(permit, candidate);
    clock.setTimeInstant(Instant.ofEpochSecond(permit.expiresAt()));
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () -> accounts.createWithMutations(candidate, List.of(mutation)));
    assertEmpty();
  }

  @Test
  void waitingUniqueInsertionCannotRedeemAfterExpiryWhenCompetingTransactionRollsBack()
      throws Exception {
    String id = AdmissionTestData.id();
    var first = account(binding.canonicalVerifiedNumber());
    accounts.createWithMutations(first, List.of());
    var firstPermit = permit(binding, id);
    try (var holding = dataSource.getConnection()) {
      holding.setAutoCommit(false);
      int blocker;
      try (var statement = holding.createStatement();
          var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
        rows.next();
        blocker = rows.getInt(1);
      }
      ledger.pendingMutation(firstPermit, first).applySql(holding);
      var secondBinding = AdmissionTestData.binding("+18005550800");
      var second = account(secondBinding.canonicalVerifiedNumber());
      var secondPermit = permit(secondBinding, id);
      var waiting =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  accounts.createWithMutations(
                      second, List.of(ledger.pendingMutation(secondPermit, second)));
                  return true;
                } catch (AdmissionLedger.AdmissionConflictException expectedConflict) {
                  return false;
                } catch (Exception unexpected) {
                  throw new RuntimeException(unexpected);
                }
              },
              executor);
      try {
        boolean blocked = false;
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!blocked && System.nanoTime() < until) {
          try (var inspection = dataSource.getConnection();
              var statement =
                  inspection.prepareStatement(
                      "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE ? ="
                          + " ANY(pg_blocking_pids(pid)))")) {
            statement.setInt(1, blocker);
            try (var rows = statement.executeQuery()) {
              rows.next();
              blocked = rows.getBoolean(1);
            }
          }
          if (!blocked) Thread.sleep(20);
        }
        assertThat(blocked)
            .as("second admission INSERT is waiting on the first transaction")
            .isTrue();
        clock.setTimeInstant(Instant.ofEpochSecond(secondPermit.expiresAt()));
      } finally {
        holding.rollback();
      }
      assertThat(waiting.get(5, TimeUnit.SECONDS)).isFalse();
      assertThat(accounts.getByAccountIdentifier(second.getAccountIdentifier())).isEmpty();
    }
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("admissions")).isZero();
    assertThat(count("admission_confirmation_outbox")).isZero();
  }

  @Test
  void replayAndChangedBindingCannotReclaimASpentPermit() throws Exception {
    String id = AdmissionTestData.id();
    var first = account(binding.canonicalVerifiedNumber());
    accounts.createWithMutations(
        first, List.of(ledger.pendingMutation(permit(binding, id), first)));
    var changed = AdmissionTestData.binding("+18005550200");
    var other = account(changed.canonicalVerifiedNumber());
    var replay = permit(changed, id);
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () -> accounts.createWithMutations(other, List.of(ledger.pendingMutation(replay, other))));
    assertThat(accounts.getByAccountIdentifier(other.getAccountIdentifier())).isEmpty();
    assertThat(count("admissions")).isEqualTo(1);
    assertThat(count("admission_confirmation_outbox")).isEqualTo(1);
    try (var c = dataSource.getConnection()) {
      c.setAutoCommit(false);
      var same = ledger.pendingMutation(permit(binding, id), first);
      assertThrows(AdmissionLedger.AdmissionConflictException.class, () -> same.applySql(c));
      c.rollback();
    }
  }

  @Test
  void memberOperationAndAciUniquenessCannotBeBypassedWithAFreshPermitId() throws Exception {
    var first = account(binding.canonicalVerifiedNumber());
    accounts.createWithMutations(
        first, List.of(ledger.pendingMutation(permit(binding, AdmissionTestData.id()), first)));
    for (boolean sameMember : List.of(true, false)) {
      var changed =
          new ExpectedBinding(
              sameMember ? binding.memberId() : UUID.randomUUID(),
              1,
              sameMember ? UUID.randomUUID() : binding.signalOperationId(),
              AdmissionTestData.hash(10),
              AdmissionTestData.hash(20),
              AdmissionTestData.hash(30),
              AdmissionTestData.hash(40),
              AdmissionTestData.hash(50),
              "+18005550300");
      var other = account(changed.canonicalVerifiedNumber());
      var permit = permit(changed, AdmissionTestData.id());
      assertThrows(
          AdmissionLedger.AdmissionConflictException.class,
          () ->
              accounts.createWithMutations(other, List.of(ledger.pendingMutation(permit, other))));
    }
    var changed =
        new ExpectedBinding(
            UUID.randomUUID(),
            1,
            UUID.randomUUID(),
            AdmissionTestData.hash(10),
            AdmissionTestData.hash(20),
            AdmissionTestData.hash(30),
            AdmissionTestData.hash(40),
            AdmissionTestData.hash(50),
            binding.canonicalVerifiedNumber());
    var fresh = permit(changed, AdmissionTestData.id());
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () -> accounts.updateWithMutations(first, List.of(ledger.pendingMutation(fresh, first))));
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("admissions")).isEqualTo(1);
  }

  @Test
  void concurrentTransactionsHaveOneWinnerWithoutOrphanedAccounts() throws Exception {
    String id = AdmissionTestData.id();
    var attempts = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < 8; i++) {
      String number = "+18005550%03d".formatted(200 + i);
      var expected = AdmissionTestData.binding(number);
      var candidate = account(number);
      var permit = permit(expected, id);
      var mutation = ledger.pendingMutation(permit, candidate);
      attempts.add(
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return accounts.createWithMutations(candidate, List.of(mutation));
                } catch (AdmissionLedger.AdmissionConflictException expectedConflict) {
                  return false;
                } catch (Exception e) {
                  throw new RuntimeException(e);
                }
              },
              executor));
    }
    assertThat(attempts.stream().filter(CompletableFuture::join).count()).isEqualTo(1);
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("admissions")).isEqualTo(1);
    assertThat(count("admission_confirmation_outbox")).isEqualTo(1);
  }

  @Test
  void accountDeletionRetainsSpentPermitTombstone() throws Exception {
    String id = AdmissionTestData.id();
    var candidate = account(binding.canonicalVerifiedNumber());
    accounts.createWithMutations(
        candidate, List.of(ledger.pendingMutation(permit(binding, id), candidate)));
    accounts.deleteWithMutations(candidate.getAccountIdentifier(), List.of());
    assertThat(count("accounts")).isZero();
    assertThat(count("admissions")).isEqualTo(1);
    var replacement = account(binding.canonicalVerifiedNumber());
    var replay = permit(binding, id);
    assertThrows(
        AdmissionLedger.AdmissionConflictException.class,
        () ->
            accounts.createWithMutations(
                replacement, List.of(ledger.pendingMutation(replay, replacement))));
    assertThat(count("accounts")).isZero();
  }
}
