// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
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
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.MutableClock;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import reactor.core.scheduler.Schedulers;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AccountsPostgresTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private MutableClock clock;
  private AccountsPostgres accounts;
  private SignedPreKeysPostgres<ECSignedPreKey> signedKeys;
  private final AtomicInteger nextNumber = new AtomicInteger();

  @BeforeEach
  void setUp() throws Exception {
    final String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      statement.execute("TRUNCATE signal.accounts, signal.usernames, signal.deleted_accounts, "
          + "signal.used_link_tokens, signal.signed_prekeys, signal.phone_recovery_passwords");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    executor = Executors.newFixedThreadPool(12);
    accounts = new AccountsPostgres(dataSource, clock, executor);
    signedKeys = SignedPreKeysPostgres.ec(dataSource, executor);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
    }
  }

  private Account newAccount() {
    return newAccount("+1800%07d".formatted(nextNumber.incrementAndGet()), UUID.randomUUID(), UUID.randomUUID());
  }

  private Account newAccount(final String number, final UUID aci, final UUID pni) {
    final Account account = new Account();
    account.setAccountIdentifier(aci);
    account.setNumber(number, pni);
    account.addDevice(DevicesHelper.createDevice((byte) 1, clock.millis(), 100));
    account.setUnidentifiedAccessKey(new byte[16]);
    account.setAccountRecoveryPassword(new byte[16]);
    return account;
  }

  private Account create() throws AccountAlreadyExistsException {
    final Account account = newAccount();
    assertThat(accounts.createWithMutations(account, List.of())).isTrue();
    return account;
  }

  private AccountMutation signedKey(final Account account, final byte deviceId, final long keyId) {
    return signedKeys.buildInsertion(account.getAccountIdentifier(), deviceId,
        new ECSignedPreKey(keyId, ECKeyPair.generate().getPublicKey(), new byte[64]));
  }

  private AccountMutation lateFailure() {
    return new AccountMutation.Sql(connection -> {
      throw new SQLException("Synthetic late account mutation failure", "P0001");
    });
  }

  private String snapshot(final Account account) throws Exception {
    // These authoritative columns are excluded from Account's JSON representation.
    return SystemMapper.jsonMapper().writeValueAsString(account) + "|" + account.getAccountIdentifier()
        + "|" + account.getNumber() + "|" + account.getPhoneNumberIdentifier() + "|" + account.getVersion()
        + "|" + Arrays.toString(account.getUsernameHash().orElse(null)) + "|" + account.getUsernameLinkHandle();
  }

  private int count(final String table) throws SQLException {
    if (!List.of("accounts", "signed_prekeys", "used_link_tokens", "deleted_accounts").contains(table)) {
      throw new IllegalArgumentException("Unexpected test table");
    }
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement();
         var rows = statement.executeQuery("SELECT count(*) FROM signal." + table)) {
      rows.next();
      return rows.getInt(1);
    }
  }

  private byte[] username(final int number) {
    final byte[] hash = new byte[32];
    Arrays.fill(hash, (byte) number);
    return hash;
  }

  @Test
  void competingRegistrationsProduceOneIdentityAndOneMatchingKey() throws Exception {
    final String number = "+18005551234";
    final UUID pni = UUID.randomUUID();
    final CountDownLatch start = new CountDownLatch(1);
    final List<CompletableFuture<UUID>> attempts = new ArrayList<>();
    for (int i = 0; i < 24; i++) {
      final Account candidate = newAccount(number, UUID.randomUUID(), pni);
      final AccountMutation key = signedKey(candidate, (byte) 1, i);
      attempts.add(CompletableFuture.supplyAsync(() -> {
        try {
          if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent registration did not start");
          accounts.createWithMutations(candidate, List.of(key));
          return candidate.getAccountIdentifier();
        } catch (AccountAlreadyExistsException e) {
          return e.getExistingAccount().getAccountIdentifier();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new CompletionException(e);
        }
      }, executor));
    }
    start.countDown();
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    final List<UUID> winners = attempts.stream().map(CompletableFuture::join).distinct().toList();
    assertThat(winners).hasSize(1);
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("signed_prekeys")).isEqualTo(1);
    assertThat(accounts.getByE164(number).orElseThrow().getAccountIdentifier()).isEqualTo(winners.getFirst());
    assertThat(accounts.getByPhoneNumberIdentifier(pni).orElseThrow().getAccountIdentifier()).isEqualTo(winners.getFirst());
    assertThat(signedKeys.find(winners.getFirst(), (byte) 1).join()).isPresent();
  }

  @Test
  void phoneAndPniUniquenessAreIndependentAndDoNotStealExistingAccounts() throws Exception {
    final Account original = create();
    final String before = snapshot(accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow());
    final Account sameNumber = newAccount(original.getNumber().orElseThrow(), UUID.randomUUID(), UUID.randomUUID());
    final Account samePni = newAccount("+18005550002", UUID.randomUUID(), original.getPhoneNumberIdentifier().orElseThrow());
    for (Account candidate : List.of(sameNumber, samePni)) {
      final AccountAlreadyExistsException conflict = assertThrows(AccountAlreadyExistsException.class,
          () -> accounts.createWithMutations(candidate, List.of(signedKey(candidate, (byte) 1, 7))));
      assertThat(conflict.getExistingAccount().getAccountIdentifier()).isEqualTo(original.getAccountIdentifier());
      assertThat(accounts.accountExists(candidate.getAccountIdentifier())).isFalse();
    }
    assertThat(snapshot(accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow())).isEqualTo(before);
    assertThat(count("signed_prekeys")).isZero();
  }

  @Test
  void aciCollisionFailsWithoutChangingTheOriginalIdentity() throws Exception {
    final Account original = create();
    final Account collision = newAccount("+18005550003", original.getAccountIdentifier(), UUID.randomUUID());
    assertThrows(IllegalArgumentException.class, () -> accounts.createWithMutations(collision, List.of()));
    assertThat(accounts.getByE164(collision.getNumber().orElseThrow())).isEmpty();
    assertThat(accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow().getNumber())
        .isEqualTo(original.getNumber());
  }

  @Test
  void retryingTheSameAccountIdentityReturnsTheExistingAccountForReclaim() throws Exception {
    final Account original = create();
    final Account retry = newAccount(original.getNumber().orElseThrow(), original.getAccountIdentifier(),
        original.getPhoneNumberIdentifier().orElseThrow());
    final AccountAlreadyExistsException conflict = assertThrows(AccountAlreadyExistsException.class,
        () -> accounts.createWithMutations(retry, List.of(signedKey(retry, (byte) 1, 77))));
    assertThat(conflict.getExistingAccount().getAccountIdentifier()).isEqualTo(original.getAccountIdentifier());
    assertThat(conflict.getExistingAccount().getPhoneNumberIdentifier()).isEqualTo(original.getPhoneNumberIdentifier());
    assertThat(count("accounts")).isEqualTo(1);
    assertThat(count("signed_prekeys")).isZero();
  }

  @Test
  void failedCreateRollsBackKeysAndPreservesTheDeletedIdentityTombstone() throws Exception {
    final Account deleted = create();
    accounts.deleteWithMutations(deleted.getAccountIdentifier(), List.of());
    final Account candidate = newAccount(deleted.getNumber().orElseThrow(), UUID.randomUUID(),
        deleted.getPhoneNumberIdentifier().orElseThrow());
    final String before = snapshot(candidate);
    assertThrows(RuntimeException.class, () -> accounts.createWithMutations(candidate,
        List.of(signedKey(candidate, (byte) 1, 1), lateFailure())));
    assertThat(count("accounts")).isZero();
    assertThat(count("signed_prekeys")).isZero();
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(deleted.getPhoneNumberIdentifier().orElseThrow()))
        .hasValue(deleted.getAccountIdentifier());
    assertThat(snapshot(candidate)).isEqualTo(before);
  }

  @Test
  void concurrentUpdatesEnforceTheOptimisticVersion() throws Exception {
    final Account original = create();
    final List<Account> copies = new ArrayList<>();
    for (int i = 0; i < 12; i++) copies.add(accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow());
    final CountDownLatch start = new CountDownLatch(1);
    final List<CompletableFuture<Boolean>> attempts = copies.stream().map(copy -> CompletableFuture.supplyAsync(() -> {
      try {
        if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent update did not start");
        copy.setDiscoverableByPhoneNumber(true);
        accounts.update(copy);
        return true;
      } catch (ContestedOptimisticLockException e) {
        return false;
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CompletionException(e);
      }
    }, executor)).toList();
    start.countDown();
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    assertThat(copies.stream().filter(copy -> copy.getVersion() == 1).count()).isEqualTo(1);
    final Account stored = accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow();
    assertThat(stored.getVersion()).isEqualTo(1);
    assertThat(stored.isDiscoverableByPhoneNumber()).isTrue();
  }

  @Test
  void lateUpdateFailureRollsBackTheAccountVersionAndKeyMutation() throws Exception {
    final Account account = create();
    final String storedBefore = snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow());
    account.addDevice(DevicesHelper.createDevice((byte) 2));
    final String inputBefore = snapshot(account);
    assertThrows(RuntimeException.class, () -> accounts.updateWithMutations(account,
        List.of(signedKey(account, (byte) 2, 2), lateFailure())));
    assertThat(snapshot(account)).isEqualTo(inputBefore);
    assertThat(snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow())).isEqualTo(storedBefore);
    assertThat(signedKeys.find(account.getAccountIdentifier(), (byte) 2).join()).isEmpty();
  }

  @Test
  void deviceTokenReplayRollsBackTheEntireUpdateAndLeavesTheCallerObjectUntouched() throws Exception {
    final Account account = create();
    account.addDevice(DevicesHelper.createDevice((byte) 2));
    accounts.updateWithMutations(account, List.of(signedKey(account, (byte) 2, 2),
        accounts.linkDeviceMutation("synthetic-single-use-device-token", Duration.ofMinutes(10))));
    final String storedBefore = snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow());
    account.addDevice(DevicesHelper.createDevice((byte) 3));
    final String inputBefore = snapshot(account);
    assertThrows(DeviceLinkTokenConflictException.class, () -> accounts.updateWithMutations(account,
        List.of(signedKey(account, (byte) 3, 3),
            accounts.linkDeviceMutation("synthetic-single-use-device-token", Duration.ofMinutes(10)))));
    assertThat(snapshot(account)).isEqualTo(inputBefore);
    assertThat(snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow())).isEqualTo(storedBefore);
    assertThat(signedKeys.find(account.getAccountIdentifier(), (byte) 2).join()).isPresent();
    assertThat(signedKeys.find(account.getAccountIdentifier(), (byte) 3).join()).isEmpty();
    assertThat(count("used_link_tokens")).isEqualTo(1);
  }

  @Test
  void aFailedDeviceUpdateDoesNotConsumeTheLinkToken() throws Exception {
    final Account account = create();
    account.addDevice(DevicesHelper.createDevice((byte) 2));
    final String before = snapshot(account);
    final AccountMutation link = accounts.linkDeviceMutation("synthetic-token-after-rollback", Duration.ofMinutes(10));
    assertThrows(RuntimeException.class, () -> accounts.updateWithMutations(account,
        List.of(link, signedKey(account, (byte) 2, 2), lateFailure())));
    assertThat(snapshot(account)).isEqualTo(before);
    assertThat(count("used_link_tokens")).isZero();
    assertThat(count("signed_prekeys")).isZero();
    accounts.updateWithMutations(account, List.of(link, signedKey(account, (byte) 2, 2)));
    assertThat(account.getVersion()).isEqualTo(1);
    assertThat(count("used_link_tokens")).isEqualTo(1);
    assertThat(signedKeys.find(account.getAccountIdentifier(), (byte) 2).join()).isPresent();
  }

  @Test
  void reclaimPreservesAUsernameLinkAcrossRepeatedIncompleteRegistrations() throws Exception {
    final Account original = create();
    final byte[] hash = username(1);
    final byte[] encryptedUsername = new byte[] {1, 2, 3};
    accounts.confirmUsernameHash(original, hash, encryptedUsername);
    final UUID handle = original.getUsernameLinkHandle();
    Account previous = original;
    for (int attempt = 0; attempt < 2; attempt++) {
      final Account replacement = newAccount(original.getNumber().orElseThrow(), original.getAccountIdentifier(),
          original.getPhoneNumberIdentifier().orElseThrow());
      accounts.reclaimWithMutations(previous, replacement, List.of(signedKey(replacement, (byte) 1, attempt + 10)))
          .toCompletableFuture().get(10, TimeUnit.SECONDS);
      final Account persisted = accounts.getByAccountIdentifier(original.getAccountIdentifier()).orElseThrow();
      assertThat(persisted.getUsernameHash()).isEmpty();
      assertThat(persisted.getReservedUsernameHash().orElseThrow()).isEqualTo(hash);
      assertThat(persisted.getEncryptedUsername()).isEmpty();
      assertThat(persisted.getUsernameLinkHandle()).isEqualTo(handle);
      assertThat(replacement.getUsernameLinkHandle()).isEqualTo(handle);
      assertThat(accounts.getByUsernameHash(hash).join()).isEmpty();
      previous = persisted;
    }
    accounts.confirmUsernameHash(previous, hash, encryptedUsername);
    assertThat(previous.getUsernameLinkHandle()).isEqualTo(handle);
    assertThat(accounts.getByUsernameLinkHandle(handle).join().orElseThrow().getEncryptedUsername().orElseThrow())
        .isEqualTo(encryptedUsername);
  }

  @Test
  void failedReclaimPreservesBothStoredAccountAndReplacementObject() throws Exception {
    final Account previous = create();
    accounts.confirmUsernameHash(previous, username(2), new byte[] {4, 5, 6});
    final Account replacement = newAccount(previous.getNumber().orElseThrow(), previous.getAccountIdentifier(),
        previous.getPhoneNumberIdentifier().orElseThrow());
    final String previousBefore = snapshot(accounts.getByAccountIdentifier(previous.getAccountIdentifier()).orElseThrow());
    final String replacementBefore = snapshot(replacement);
    assertThrows(CompletionException.class, () -> accounts.reclaimWithMutations(previous, replacement,
        List.of(signedKey(replacement, (byte) 1, 12), lateFailure())).toCompletableFuture().join());
    assertThat(snapshot(replacement)).isEqualTo(replacementBefore);
    assertThat(snapshot(accounts.getByAccountIdentifier(previous.getAccountIdentifier()).orElseThrow())).isEqualTo(previousBefore);
    assertThat(accounts.getByUsernameHash(username(2)).join()).isPresent();
    assertThat(count("signed_prekeys")).isZero();
  }

  @Test
  void reclaimDetectsAPersistedPhoneMismatchBeforeAnOptimisticVersionConflict() throws Exception {
    final Account stale = create();
    final Account newer = accounts.getByAccountIdentifier(stale.getAccountIdentifier()).orElseThrow();
    accounts.update(newer);
    final String storedBefore = snapshot(accounts.getByAccountIdentifier(stale.getAccountIdentifier()).orElseThrow());
    final Account wrongPrevious = newAccount("+18005553333", stale.getAccountIdentifier(),
        stale.getPhoneNumberIdentifier().orElseThrow());
    final Account wrongReplacement = newAccount("+18005553333", stale.getAccountIdentifier(),
        stale.getPhoneNumberIdentifier().orElseThrow());
    final String wrongBefore = snapshot(wrongReplacement);
    // Both the claimed previous number and version are stale. Upstream reports the identity mismatch first.
    final CompletionException wrongNumber = assertThrows(CompletionException.class,
        () -> accounts.reclaimWithMutations(wrongPrevious, wrongReplacement,
            List.of(signedKey(wrongReplacement, (byte) 1, 13))).toCompletableFuture().join());
    assertThat(wrongNumber.getCause()).isInstanceOf(UnexpectedExistingPhoneNumberException.class);
    assertThat(snapshot(wrongReplacement)).isEqualTo(wrongBefore);

    final Account correctReplacement = newAccount(stale.getNumber().orElseThrow(), stale.getAccountIdentifier(),
        stale.getPhoneNumberIdentifier().orElseThrow());
    final String correctBefore = snapshot(correctReplacement);
    final CompletionException staleVersion = assertThrows(CompletionException.class,
        () -> accounts.reclaimWithMutations(stale, correctReplacement,
            List.of(signedKey(correctReplacement, (byte) 1, 14))).toCompletableFuture().join());
    assertThat(staleVersion.getCause()).isInstanceOf(ContestedOptimisticLockException.class);
    assertThat(snapshot(correctReplacement)).isEqualTo(correctBefore);
    assertThat(snapshot(accounts.getByAccountIdentifier(stale.getAccountIdentifier()).orElseThrow())).isEqualTo(storedBefore);
    assertThat(count("signed_prekeys")).isZero();
  }

  @Test
  void changeNumberMovesEveryLookupAndDeletionLeavesTheCorrectTombstone() throws Exception {
    final Account account = create();
    final String oldNumber = account.getNumber().orElseThrow();
    final UUID oldPni = account.getPhoneNumberIdentifier().orElseThrow();
    final UUID newPni = UUID.randomUUID();
    final UUID displacedAci = UUID.randomUUID();
    accounts.changeNumberWithMutations(account, "+18005559999", newPni, Optional.of(displacedAci),
        List.of(signedKey(account, (byte) 1, 5)));
    assertThat(account.getVersion()).isEqualTo(1);
    assertThat(account.getNumber()).hasValue("+18005559999");
    assertThat(accounts.getByE164(oldNumber)).isEmpty();
    assertThat(accounts.getByPhoneNumberIdentifier(oldPni)).isEmpty();
    assertThat(accounts.getByE164("+18005559999").orElseThrow().getAccountIdentifier()).isEqualTo(account.getAccountIdentifier());
    assertThat(accounts.getByPhoneNumberIdentifier(newPni).orElseThrow().getNumber()).hasValue("+18005559999");
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(oldPni)).hasValue(displacedAci);
    accounts.deleteWithMutations(account.getAccountIdentifier(),
        List.of(signedKeys.buildDeletion(account.getAccountIdentifier(), (byte) 1)));
    assertThat(accounts.accountExists(account.getAccountIdentifier())).isFalse();
    assertThat(accounts.getByPhoneNumberIdentifier(newPni)).isEmpty();
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(newPni)).hasValue(account.getAccountIdentifier());
    assertThat(accounts.findRecentlyDeletedPhoneNumberIdentifier(account.getAccountIdentifier())).hasValue(newPni);
    assertThat(count("signed_prekeys")).isZero();
  }

  @Test
  void failedIdentityChangeAndIdentityCollisionsPreserveTheCallerAndOldLookups() throws Exception {
    final Account account = create();
    final Account occupied = create();
    final String before = snapshot(account);
    assertThrows(RuntimeException.class, () -> accounts.changeNumberWithMutations(account, "+18005558888", UUID.randomUUID(),
        Optional.of(UUID.randomUUID()), List.of(signedKey(account, (byte) 1, 6), lateFailure())));
    assertThat(snapshot(account)).isEqualTo(before);
    assertThat(accounts.getByE164("+18005558888")).isEmpty();
    assertThat(count("deleted_accounts")).isZero();
    assertThat(count("signed_prekeys")).isZero();
    assertThrows(RuntimeException.class, () -> accounts.changeNumberWithMutations(account,
        occupied.getNumber().orElseThrow(), UUID.randomUUID(), Optional.empty(), List.of()));
    assertThrows(RuntimeException.class, () -> accounts.changeNumberWithMutations(account,
        "+18005557777", occupied.getPhoneNumberIdentifier().orElseThrow(), Optional.empty(), List.of()));
    assertThat(snapshot(account)).isEqualTo(before);
    assertThat(accounts.getByE164(account.getNumber().orElseThrow()).orElseThrow().getAccountIdentifier())
        .isEqualTo(account.getAccountIdentifier());
    assertThat(accounts.getByE164(occupied.getNumber().orElseThrow()).orElseThrow().getAccountIdentifier())
        .isEqualTo(occupied.getAccountIdentifier());
  }

  @Test
  void lateDeletionFailureRestoresAccountUsernameAndSignedKeys() throws Exception {
    final Account account = newAccount();
    accounts.createWithMutations(account, List.of(signedKey(account, (byte) 1, 9)));
    accounts.confirmUsernameHash(account, username(3), new byte[] {7, 8, 9});
    final String before = snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow());
    assertThrows(RuntimeException.class, () -> accounts.deleteWithMutations(account.getAccountIdentifier(),
        List.of(signedKeys.buildDeletion(account.getAccountIdentifier(), (byte) 1), lateFailure())));
    assertThat(snapshot(accounts.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow())).isEqualTo(before);
    assertThat(accounts.getByUsernameHash(username(3)).join()).isPresent();
    assertThat(signedKeys.find(account.getAccountIdentifier(), (byte) 1).join()).isPresent();
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(account.getPhoneNumberIdentifier().orElseThrow())).isEmpty();
  }

  @Test
  void usernameReservationsArePrivateAndExpireAtTheUpstreamStrictBoundary() throws Exception {
    final Account first = create();
    final Account second = create();
    final byte[] hash = username(4);
    accounts.reserveUsernameHash(first, hash, Duration.ofSeconds(30));
    assertThat(accounts.getByUsernameHash(hash).join()).isEmpty();
    final String secondBefore = snapshot(second);
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.reserveUsernameHash(second, hash, Duration.ofMinutes(1)));
    clock.incrementSeconds(30);
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.confirmUsernameHash(second, hash, new byte[] {1}));
    assertThat(snapshot(second)).isEqualTo(secondBefore);
    clock.incrementSeconds(1);
    accounts.reserveUsernameHash(second, hash, Duration.ofMinutes(1));
    accounts.confirmUsernameHash(second, hash, new byte[] {1});
    assertThat(accounts.getByUsernameHash(hash).join().orElseThrow().getAccountIdentifier()).isEqualTo(second.getAccountIdentifier());
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.confirmUsernameHash(first, hash, new byte[] {2}));
  }

  @Test
  void clearedUsernameIsHeldForItsOwnerAndCanBeClaimedAfterTheHoldExpires() throws Exception {
    final Account owner = create();
    final Account other = create();
    final byte[] hash = username(5);
    accounts.confirmUsernameHash(owner, hash, new byte[] {2, 3});
    final UUID originalHandle = owner.getUsernameLinkHandle();
    accounts.clearUsernameHash(owner);
    assertThat(owner.getUsernameHash()).isEmpty();
    assertThat(owner.getUsernameLinkHandle()).isNull();
    assertThat(accounts.getByUsernameLinkHandle(originalHandle).join()).isEmpty();
    assertThat(accounts.getByUsernameHash(hash).join()).isEmpty();
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.reserveUsernameHash(other, hash, Duration.ofDays(1)));
    accounts.reserveUsernameHash(owner, hash, Duration.ofDays(1));
    accounts.confirmUsernameHash(owner, hash, new byte[] {3, 4});
    accounts.clearUsernameHash(owner);
    clock.incrementSeconds(Duration.ofDays(7).toSeconds() + 1);
    accounts.reserveUsernameHash(other, hash, Duration.ofMinutes(1));
    accounts.confirmUsernameHash(other, hash, new byte[] {4, 5});
    assertThat(accounts.getByUsernameHash(hash).join().orElseThrow().getAccountIdentifier()).isEqualTo(other.getAccountIdentifier());
  }

  @Test
  void clearingTheCurrentUsernamePreservesADifferentPendingReservation() throws Exception {
    final Account owner = create();
    final Account other = create();
    final byte[] current = username(30);
    final byte[] reserved = username(31);
    accounts.confirmUsernameHash(owner, current, new byte[] {8});
    accounts.reserveUsernameHash(owner, reserved, Duration.ofMinutes(5));
    accounts.clearUsernameHash(owner);
    assertThat(owner.getUsernameHash()).isEmpty();
    assertThat(owner.getReservedUsernameHash().orElseThrow()).isEqualTo(reserved);
    final Account persisted = accounts.getByAccountIdentifier(owner.getAccountIdentifier()).orElseThrow();
    assertThat(persisted.getReservedUsernameHash().orElseThrow()).isEqualTo(reserved);
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.reserveUsernameHash(other, reserved, Duration.ofMinutes(1)));
    accounts.confirmUsernameHash(persisted, reserved, new byte[] {9});
    assertThat(accounts.getByUsernameHash(reserved).join().orElseThrow().getAccountIdentifier())
        .isEqualTo(owner.getAccountIdentifier());
    assertThat(accounts.getByUsernameHash(current).join()).isEmpty();
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accounts.reserveUsernameHash(other, current, Duration.ofMinutes(1)));
  }

  @Test
  void usernameRotationKeepsOnlyTheThreeMostRecentHolds() throws Exception {
    final Account owner = create();
    final Account other = create();
    for (int i = 10; i < 15; i++) {
      accounts.reserveUsernameHash(owner, username(i), Duration.ofDays(1));
      accounts.confirmUsernameHash(owner, username(i), new byte[] {(byte) i});
    }
    assertThat(owner.getUsernameHolds()).hasSize(3);
    accounts.reserveUsernameHash(other, username(10), Duration.ofDays(1));
    for (int i = 11; i < 15; i++) {
      final byte[] unavailable = username(i);
      assertThrows(UsernameHashNotAvailableException.class,
          () -> accounts.reserveUsernameHash(other, unavailable, Duration.ofDays(1)));
    }
  }

  @Test
  void staleUsernameMutationsLeaveTheCallerAndStoredUsernameUntouched() throws Exception {
    final Account owner = create();
    accounts.confirmUsernameHash(owner, username(20), new byte[] {6});
    final Account stale = accounts.getByAccountIdentifier(owner.getAccountIdentifier()).orElseThrow();
    accounts.update(owner);
    final String staleBefore = snapshot(stale);
    assertThrows(ContestedOptimisticLockException.class,
        () -> accounts.reserveUsernameHash(stale, username(21), Duration.ofDays(1)));
    assertThrows(ContestedOptimisticLockException.class,
        () -> accounts.confirmUsernameHash(stale, username(21), new byte[] {7}));
    assertThrows(ContestedOptimisticLockException.class, () -> accounts.clearUsernameHash(stale));
    assertThat(snapshot(stale)).isEqualTo(staleBefore);
    assertThat(accounts.getByUsernameHash(username(20)).join()).isPresent();
    assertThat(accounts.getByUsernameHash(username(21)).join()).isEmpty();
  }

  @Test
  void allAccountScansTerminateWhenTheOnlyAciIsTheZeroUuid() throws Exception {
    final UUID zero = new UUID(0, 0);
    final Account account = newAccount("+18005550000", zero, UUID.randomUUID());
    accounts.createWithMutations(account, List.of());
    assertThat(accounts.getAll(1, Schedulers.fromExecutor(executor)).take(2).map(Account::getAccountIdentifier)
        .collectList().block(Duration.ofSeconds(5))).containsExactly(zero);
    assertThat(accounts.getAllAccountIdentifiers(1, Schedulers.fromExecutor(executor)).take(2)
        .collectList().block(Duration.ofSeconds(5))).containsExactly(zero);
  }

  @Test
  void keysetScansCrossPageBoundariesWithoutSkippingOrRepeatingUuidValues() throws Exception {
    final List<UUID> expected = new ArrayList<>();
    for (int i = 0; i < 300; i++) expected.add(new UUID(0, i));
    expected.add(new UUID(1, 0));
    expected.add(new UUID(Long.MIN_VALUE, 0));
    expected.add(new UUID(-1, -1));
    expected.sort(Comparator.comparing(UUID::toString));
    // Batch only the fixture setup: this test targets the native scan cursor and its 256-row page boundary.
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
        "INSERT INTO signal.accounts(aci,number,pni,version,data) VALUES(?,?,?,0,?::jsonb)")) {
      connection.setAutoCommit(false);
      for (UUID aci : expected) {
        final Account account = newAccount("+1800%07d".formatted(nextNumber.incrementAndGet()), aci, UUID.randomUUID());
        statement.setObject(1, aci);
        statement.setString(2, account.getNumber().orElseThrow());
        statement.setObject(3, account.getPhoneNumberIdentifier().orElseThrow());
        statement.setString(4, SystemMapper.jsonMapper().writeValueAsString(account));
        statement.addBatch();
      }
      statement.executeBatch();
      connection.commit();
    }
    // The extra item bound also makes duplicate/restarting cursor failures terminate safely.
    final List<UUID> fullRows = accounts.getAll(1, Schedulers.fromExecutor(executor))
        .take(expected.size() + 1L).map(Account::getAccountIdentifier).collectList().block(Duration.ofSeconds(10));
    assertThat(fullRows).containsExactlyElementsOf(expected).doesNotHaveDuplicates();
    final List<UUID> identifiers = accounts.getAllAccountIdentifiers(4, Schedulers.fromExecutor(executor))
        .take(expected.size() + 1L).collectList().block(Duration.ofSeconds(10));
    assertThat(identifiers).containsExactlyElementsOf(expected).doesNotHaveDuplicates();
  }
}
