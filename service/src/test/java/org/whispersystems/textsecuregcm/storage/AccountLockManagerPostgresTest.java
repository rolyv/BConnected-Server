// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AccountLockManagerPostgresTest {
  private HikariDataSource lockPool;
  private ExecutorService executor;
  private AccountLockManager manager;

  @BeforeEach
  void setUp() {
    final String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    lockPool = pool(4);
    manager = new AccountLockManager(lockPool);
    executor = Executors.newFixedThreadPool(8);
  }

  private HikariDataSource pool(final int maximumSize) {
    final HikariConfig configuration = new HikariConfig();
    configuration.setJdbcUrl(System.getenv("BCONNECTED_TEST_JDBC_URL"));
    configuration.setUsername("postgres");
    configuration.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    configuration.setMaximumPoolSize(maximumSize);
    configuration.setMinimumIdle(0);
    configuration.setConnectionTimeout(3000);
    configuration.addDataSourceProperty("options", "-c statement_timeout=5000 -c lock_timeout=3000");
    return new HikariDataSource(configuration);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdownNow();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }
    if (lockPool != null) lockPool.close();
  }

  private static void await(final CountDownLatch latch) {
    try {
      if (!latch.await(10, TimeUnit.SECONDS)) throw new AssertionError("Timed out waiting for concurrent lock scope");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted while waiting for concurrent lock scope", e);
    }
  }

  @Test
  void overlappingScopesHoldLocksUntilTheirCallbacksReturn() throws Exception {
    final UUID identity = UUID.randomUUID();
    final CountDownLatch firstEntered = new CountDownLatch(1);
    final CountDownLatch releaseFirst = new CountDownLatch(1);
    final CountDownLatch secondEntered = new CountDownLatch(1);
    final AtomicInteger completedCallbacks = new AtomicInteger();
    final AccountLockManager otherManager = new AccountLockManager(lockPool);
    final CompletableFuture<Integer> first = CompletableFuture.supplyAsync(() -> manager.withLock(Set.of(identity), () -> {
      firstEntered.countDown();
      await(releaseFirst);
      return completedCallbacks.incrementAndGet();
    }), executor);
    await(firstEntered);
    final CompletableFuture<Integer> second = CompletableFuture.supplyAsync(() -> otherManager.withLock(Set.of(identity), () -> {
      secondEntered.countDown();
      return completedCallbacks.incrementAndGet();
    }), executor);
    try {
      assertThat(secondEntered.await(150, TimeUnit.MILLISECONDS)).isFalse();
    } finally {
      releaseFirst.countDown();
    }
    assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo(1);
    assertThat(second.get(10, TimeUnit.SECONDS)).isEqualTo(2);
  }

  @Test
  void disjointIdentitiesCanRunTheirCallbacksConcurrently() throws Exception {
    final CountDownLatch entered = new CountDownLatch(2);
    final CountDownLatch release = new CountDownLatch(1);
    final List<CompletableFuture<Void>> tasks = new ArrayList<>();
    for (int i = 0; i < 2; i++) {
      final UUID identity = UUID.randomUUID();
      tasks.add(CompletableFuture.runAsync(() -> manager.withLock(Set.of(identity), () -> {
        entered.countDown();
        await(release);
        return null;
      }), executor));
    }
    try {
      await(entered);
    } finally {
      release.countDown();
    }
    CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).get(10, TimeUnit.SECONDS);
  }

  @Test
  void reversedMultiIdentityRequestsDoNotDeadlockOrOverlap() throws Exception {
    final UUID first = UUID.randomUUID();
    final UUID second = UUID.randomUUID();
    final CountDownLatch start = new CountDownLatch(1);
    final AtomicInteger active = new AtomicInteger();
    final AtomicInteger maximumActive = new AtomicInteger();
    final AtomicInteger completed = new AtomicInteger();
    final List<CompletableFuture<Void>> tasks = new ArrayList<>();
    for (int i = 0; i < 24; i++) {
      final Set<UUID> identifiers = new LinkedHashSet<>(i % 2 == 0 ? List.of(first, second) : List.of(second, first));
      tasks.add(CompletableFuture.runAsync(() -> {
        await(start);
        manager.withLock(identifiers, () -> {
          maximumActive.accumulateAndGet(active.incrementAndGet(), Math::max);
          try {
            completed.incrementAndGet();
          } finally {
            active.decrementAndGet();
          }
          return null;
        });
      }, executor));
    }
    start.countDown();
    CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).get(10, TimeUnit.SECONDS);
    assertThat(completed).hasValue(24);
    assertThat(maximumActive).hasValue(1);
  }

  @Test
  void checkedCallbackExceptionIsPreservedAndReleasesEveryLock() throws Exception {
    final Set<UUID> identities = Set.of(UUID.randomUUID(), UUID.randomUUID());
    final IOException expected = new IOException("Callback failure");
    assertThat(assertThrows(IOException.class, () -> manager.withLock(identities, () -> {
      throw expected;
    }))).isSameAs(expected);
    final AccountLockManager otherManager = new AccountLockManager(lockPool);
    assertThat(CompletableFuture.supplyAsync(() -> otherManager.withLock(identities, () -> "released"), executor)
        .get(10, TimeUnit.SECONDS)).isEqualTo("released");
  }

  @Test
  void nestedCallsReuseTheDedicatedPoolWhileCallbacksUseTheDataPool() throws Exception {
    final UUID pni = UUID.randomUUID();
    final UUID aci = UUID.randomUUID();
    try (final HikariDataSource oneConnectionLockPool = pool(1);
         final HikariDataSource dataPool = pool(1)) {
      final AccountLockManager nestedManager = new AccountLockManager(oneConnectionLockPool);
      final int result = nestedManager.withLock(Set.of(pni), () -> nestedManager.withLock(Set.of(pni, aci), () -> {
        assertThat(oneConnectionLockPool.getHikariPoolMXBean().getActiveConnections()).isEqualTo(1);
        try (var connection = dataPool.getConnection(); var statement = connection.createStatement();
             var rows = statement.executeQuery("SELECT 42")) {
          rows.next();
          return rows.getInt(1);
        }
      }));
      assertThat(result).isEqualTo(42);
      final AccountLockManager otherManager = new AccountLockManager(oneConnectionLockPool);
      assertThat(otherManager.withLock(Set.of(pni, aci), () -> "released")).isEqualTo("released");
    }
  }

  @Test
  void failedNestedCallbackReleasesBothOuterAndInnerLocks() throws Exception {
    final UUID outer = UUID.randomUUID();
    final UUID inner = UUID.randomUUID();
    final IOException expected = new IOException("Nested callback failure");
    assertThat(assertThrows(IOException.class, () -> manager.withLock(Set.of(outer), () ->
        manager.withLock(Set.of(inner), () -> { throw expected; })))).isSameAs(expected);
    final AccountLockManager otherManager = new AccountLockManager(lockPool);
    assertThat(CompletableFuture.supplyAsync(() -> otherManager.withLock(Set.of(outer, inner), () -> true), executor)
        .get(10, TimeUnit.SECONDS)).isTrue();
  }

  @Test
  void contendedNestedAdditionsFailWithoutDeadlockOrCallbackReplay() throws Exception {
    final UUID first = UUID.randomUUID();
    final UUID second = UUID.randomUUID();
    final CountDownLatch bothOuterScopesEntered = new CountDownLatch(2);
    final AtomicInteger outerCallbacks = new AtomicInteger();
    final AtomicInteger failedNestedAcquisitions = new AtomicInteger();
    final List<CompletableFuture<Void>> tasks = new ArrayList<>();
    for (int i = 0; i < 2; i++) {
      final UUID outer = i == 0 ? first : second;
      final UUID inner = i == 0 ? second : first;
      tasks.add(CompletableFuture.runAsync(() -> {
        try {
          manager.withLock(Set.of(outer), () -> {
            outerCallbacks.incrementAndGet();
            bothOuterScopesEntered.countDown();
            await(bothOuterScopesEntered);
            return manager.withLock(Set.of(inner), () -> null);
          });
        } catch (IllegalStateException e) {
          assertThat(e).hasMessage("Nested PostgreSQL account lifecycle lock is already held");
          failedNestedAcquisitions.incrementAndGet();
        }
      }, executor));
    }
    CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).get(10, TimeUnit.SECONDS);
    assertThat(outerCallbacks).hasValue(2);
    assertThat(failedNestedAcquisitions.get()).isBetween(1, 2);
    assertThat(manager.withLock(Set.of(first, second), () -> true)).isTrue();
  }

  @Test
  void emptyScopeRejectsTheRequestWithoutRunningTheCallback() {
    final AtomicInteger callbacks = new AtomicInteger();
    assertThrows(IllegalArgumentException.class, () -> manager.withLock(Set.of(), callbacks::incrementAndGet));
    assertThat(callbacks).hasValue(0);
  }
}
