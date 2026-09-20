// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class PushChallengePostgresTest {
  private PGSimpleDataSource dataSource;
  private MutableClock clock;
  private PushChallengePostgres store;
  private ExecutorService executor;

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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/008-push-challenges.sql")));
      statement.execute("TRUNCATE signal.push_challenges");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    store = new PushChallengePostgres(dataSource, clock);
    executor = Executors.newFixedThreadPool(12);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
    }
  }

  private static void await(final CountDownLatch latch) {
    try {
      if (!latch.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent challenge operation did not start");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted while starting concurrent challenge operation", e);
    }
  }

  private static byte[] token(final int id) {
    final byte[] token = new byte[16];
    Arrays.fill(token, (byte) id);
    return token;
  }

  private int count() throws Exception {
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement();
         var rows = statement.executeQuery("SELECT count(*) FROM signal.push_challenges")) {
      rows.next();
      return rows.getInt(1);
    }
  }

  @Test
  void concurrentInsertsHaveExactlyOneWinnerAndCannotReplaceItsToken() throws Exception {
    final UUID account = UUID.randomUUID();
    final CountDownLatch start = new CountDownLatch(1);
    final PushChallengePostgres secondStore = new PushChallengePostgres(dataSource, clock);
    final List<CompletableFuture<Boolean>> attempts = new ArrayList<>();
    for (int i = 0; i < 24; i++) {
      final int id = i;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        await(start);
        return (id % 2 == 0 ? store : secondStore).add(account, token(id), Duration.ofMinutes(1));
      }, executor));
    }
    start.countDown();
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    final List<Integer> winners = IntStream.range(0, attempts.size()).filter(i -> attempts.get(i).join()).boxed().toList();
    assertThat(winners).hasSize(1);
    assertThat(count()).isEqualTo(1);
    for (int i = 0; i < attempts.size(); i++) {
      if (i != winners.getFirst()) assertThat(store.remove(account, token(i))).isFalse();
    }
    assertThat(store.remove(account, token(winners.getFirst()))).isTrue();
    assertThat(count()).isZero();
  }

  @Test
  void concurrentCorrectResponsesConsumeTheChallengeExactlyOnce() throws Exception {
    final UUID account = UUID.randomUUID();
    final byte[] response = token(25);
    assertThat(store.add(account, response, Duration.ofMinutes(1))).isTrue();
    final CountDownLatch start = new CountDownLatch(1);
    final PushChallengePostgres secondStore = new PushChallengePostgres(dataSource, clock);
    final List<CompletableFuture<Boolean>> attempts = new ArrayList<>();
    for (int i = 0; i < 24; i++) {
      final PushChallengePostgres consumer = i % 2 == 0 ? store : secondStore;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        await(start);
        return consumer.remove(account, response);
      }, executor));
    }
    start.countDown();
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    assertThat(store.remove(account, response)).isFalse();
    assertThat(count()).isZero();
  }

  @Test
  void wrongResponsesAndOtherAccountsCannotConsumeOrReplaceAValidChallenge() throws Exception {
    final UUID first = UUID.randomUUID();
    final UUID second = UUID.randomUUID();
    final byte[] firstToken = new byte[] {0, (byte) 0xff, 0, 42, (byte) 0x80};
    final byte[] secondToken = token(26);
    assertThat(store.remove(first, firstToken)).isFalse();
    assertThat(store.add(first, firstToken, Duration.ofMinutes(1))).isTrue();
    assertThat(store.add(second, secondToken, Duration.ofMinutes(1))).isTrue();
    assertThat(store.remove(first, secondToken)).isFalse();
    assertThat(store.remove(second, firstToken)).isFalse();
    assertThat(store.remove(UUID.randomUUID(), firstToken)).isFalse();
    assertThat(store.remove(first, Arrays.copyOf(firstToken, firstToken.length - 1))).isFalse();
    assertThat(store.remove(first, Arrays.copyOf(firstToken, firstToken.length + 1))).isFalse();
    assertThat(store.add(first, secondToken, Duration.ofHours(1))).isFalse();
    assertThat(count()).isEqualTo(2);
    assertThat(store.remove(first, firstToken)).isTrue();
    assertThat(store.remove(second, secondToken)).isTrue();
  }

  @Test
  void expirationEqualityRemainsConsumableAndCleanupUsesTheSameStrictBoundary() {
    final UUID account = UUID.randomUUID();
    final byte[] response = token(27);
    assertThat(store.add(account, response, Duration.ofSeconds(10))).isTrue();
    clock.incrementSeconds(10);
    assertThat(store.deleteExpired(10)).isZero();
    assertThat(store.remove(account, response)).isTrue();
    // Upstream compares integral epoch seconds; fractions inside the same expiry second remain valid.
    assertThat(store.add(account, response, Duration.ZERO)).isTrue();
    clock.incrementMillis(999);
    assertThat(store.deleteExpired(10)).isZero();
    assertThat(store.remove(account, response)).isTrue();
  }

  @Test
  void expiredChallengesRejectResponsesAndBlockInsertionUntilCleanup() throws Exception {
    final UUID account = UUID.randomUUID();
    final byte[] oldToken = token(28);
    final byte[] replacement = token(29);
    assertThat(store.add(account, oldToken, Duration.ofSeconds(1))).isTrue();
    clock.incrementSeconds(2);
    assertThat(store.remove(account, oldToken)).isFalse();
    assertThat(store.add(account, replacement, Duration.ofMinutes(1))).isFalse();
    assertThat(count()).isEqualTo(1);
    assertThat(store.deleteExpired(1)).isEqualTo(1);
    assertThat(store.add(account, replacement, Duration.ofMinutes(1))).isTrue();
    assertThat(store.remove(account, oldToken)).isFalse();
    assertThat(store.remove(account, replacement)).isTrue();
  }

  @Test
  void cleanupIsBoundedAndPreservesBothLiveAndExactlyExpiringChallenges() throws Exception {
    final List<UUID> expired = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    for (UUID account : expired) assertThat(store.add(account, token(30), Duration.ofSeconds(-1))).isTrue();
    final UUID live = UUID.randomUUID();
    final UUID equality = UUID.randomUUID();
    assertThat(store.add(live, token(31), Duration.ofMinutes(1))).isTrue();
    assertThat(store.add(equality, token(32), Duration.ZERO)).isTrue();
    assertThrows(IllegalArgumentException.class, () -> store.deleteExpired(0));
    assertThrows(IllegalArgumentException.class, () -> store.deleteExpired(10001));
    assertThat(count()).isEqualTo(5);
    assertThat(store.deleteExpired(2)).isEqualTo(2);
    assertThat(count()).isEqualTo(3);
    assertThat(store.deleteExpired(2)).isEqualTo(1);
    assertThat(store.deleteExpired(2)).isZero();
    assertThat(store.remove(live, token(31))).isTrue();
    assertThat(store.remove(equality, token(32))).isTrue();
    for (UUID account : expired) assertThat(store.add(account, token(33), Duration.ofMinutes(1))).isTrue();
  }

  @Test
  void cleanupSkipsLockedExpiredRowsAndRemovesThemAfterTheLockIsReleased() throws Exception {
    final UUID locked = UUID.randomUUID();
    final UUID other = UUID.randomUUID();
    assertThat(store.add(locked, token(34), Duration.ofSeconds(-1))).isTrue();
    assertThat(store.add(other, token(35), Duration.ofSeconds(-1))).isTrue();
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
        "SELECT aci FROM signal.push_challenges WHERE aci=? FOR UPDATE")) {
      connection.setAutoCommit(false);
      statement.setObject(1, locked);
      try (var rows = statement.executeQuery()) { assertThat(rows.next()).isTrue(); }
      assertThat(CompletableFuture.supplyAsync(() -> store.deleteExpired(10), executor).get(5, TimeUnit.SECONDS))
          .isEqualTo(1);
      assertThat(count()).isEqualTo(1);
      connection.rollback();
    }
    assertThat(store.deleteExpired(10)).isEqualTo(1);
    assertThat(count()).isZero();
  }
}
