// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Optional;
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
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.util.UUIDUtil;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class ReportMessagePostgresTest {
  private static final Instant NOW = Instant.parse("2026-09-20T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final Duration TTL = Duration.ofSeconds(60);
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private ReportMessagePostgres store;

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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/007-report-message.sql")));
      statement.execute("TRUNCATE signal.report_messages");
    }
    executor = Executors.newFixedThreadPool(12);
    store = new ReportMessagePostgres(dataSource, TTL, CLOCK, executor);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
    }
  }

  private byte[] hash() { return UUIDUtil.toBytes(UUID.randomUUID()); }

  private ReportMessagePostgres at(final long secondsAfterStart) {
    return new ReportMessagePostgres(dataSource, TTL, Clock.fixed(NOW.plusSeconds(secondsAfterStart), ZoneOffset.UTC), executor);
  }

  @Test
  void storesDeduplicateAndEachStoredHashCanBeConsumedOnce() {
    byte[] first = hash();
    byte[] second = hash();
    assertThat(store.remove(first)).isFalse();
    var writes = new ArrayList<CompletableFuture<Void>>();
    for (int i = 0; i < 30; i++) writes.add(store.store(first));
    writes.add(store.store(second));
    CompletableFuture.allOf(writes.toArray(CompletableFuture[]::new)).join();
    assertThat(store.remove(hash())).isFalse();
    assertThat(store.remove(first)).isTrue();
    assertThat(store.remove(first)).isFalse();
    assertThat(store.remove(second)).isTrue();
    assertThat(store.remove(second)).isFalse();
    // A new upstream store of an already-consumed hash makes it reportable again.
    store.store(first).join();
    assertThat(store.remove(first)).isTrue();
  }

  @Test
  void concurrentConsumersAcrossInstancesHaveExactlyOneWinner() {
    byte[] hash = hash();
    store.store(hash).join();
    ReportMessagePostgres second = at(0);
    var attempts = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < 60; i++) {
      ReportMessagePostgres selected = i % 2 == 0 ? store : second;
      attempts.add(CompletableFuture.supplyAsync(() -> selected.remove(hash), executor));
    }
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
  }

  @Test
  void extantExpiredHashesRemainReportableUntilBoundedCleanup() {
    byte[] expiredButPresent = hash();
    store.store(expiredButPresent).join();
    assertThat(at(61).remove(expiredButPresent)).isTrue();
    for (int i = 0; i < 4; i++) store.store(hash()).join();
    assertThat(at(60).deleteExpired(10)).isZero();
    byte[] future = hash();
    at(30).store(future).join();
    assertThat(at(61).deleteExpired(2)).isEqualTo(2);
    assertThat(at(61).deleteExpired(2)).isEqualTo(2);
    assertThat(at(61).deleteExpired(2)).isZero();
    assertThat(at(61).remove(future)).isTrue();
  }

  @Test
  void storingADuplicateRefreshesItsExpiry() {
    byte[] hash = hash();
    store.store(hash).join();
    at(30).store(hash).join();
    assertThat(at(61).deleteExpired(10)).isZero();
    assertThat(at(90).deleteExpired(10)).isZero();
    assertThat(at(91).deleteExpired(10)).isEqualTo(1);
    assertThat(at(91).remove(hash)).isFalse();
  }

  @Test
  void asynchronousStoreCapturesTheHashAtInvocationTime() {
    var pendingTasks = new ArrayList<Runnable>();
    ReportMessagePostgres deferred = new ReportMessagePostgres(dataSource, TTL, CLOCK, pendingTasks::add);
    byte[] mutable = hash();
    byte[] original = mutable.clone();
    CompletableFuture<Void> pending = deferred.store(mutable);
    mutable[0] ^= (byte) 0xff;
    pendingTasks.getFirst().run();
    pending.join();
    assertThat(store.remove(mutable)).isFalse();
    assertThat(store.remove(original)).isTrue();
  }

  @Test
  void managerReportsOnlyTheMatchingHashAndNotifiesOnceUnderConcurrency() {
    FaultTolerantRedisClusterClient rateLimits = mock(FaultTolerantRedisClusterClient.class);
    // Use a direct executor for manager.store(), whose upstream API intentionally does not return the write future.
    var synchronousStore = new ReportMessagePostgres(dataSource, TTL, CLOCK, Runnable::run);
    var manager = new ReportMessageManager(synchronousStore, rateLimits, Duration.ofDays(1));
    UUID sender = UUID.randomUUID();
    UUID message = UUID.randomUUID();
    UUID reporter = UUID.randomUUID();
    AtomicInteger notifications = new AtomicInteger();
    manager.addListener((number, messageGuid, reporterUuid, token, deleted) -> {
      assertThat(messageGuid).isEqualTo(message);
      assertThat(reporterUuid).isEqualTo(reporter);
      notifications.incrementAndGet();
    });
    manager.store(sender.toString(), message);
    manager.report(Optional.empty(), UUID.randomUUID(), Optional.empty(), message, reporter,
        Optional.empty(), null, false);
    manager.report(Optional.empty(), sender, Optional.empty(), UUID.randomUUID(), reporter,
        Optional.empty(), null, false);
    assertThat(notifications).hasValue(0);
    var attempts = new ArrayList<CompletableFuture<Void>>();
    for (int i = 0; i < 40; i++) attempts.add(CompletableFuture.runAsync(() ->
        manager.report(Optional.empty(), sender, Optional.empty(), message, reporter, Optional.empty(), null, false), executor));
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).join();
    assertThat(notifications).hasValue(1);
    verify(rateLimits, times(1)).useCluster(any());
  }
}
