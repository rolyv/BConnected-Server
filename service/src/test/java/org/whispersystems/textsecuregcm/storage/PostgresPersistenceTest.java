// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.ByteString;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
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
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.core.publisher.Flux;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class PostgresPersistenceTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private MessagesPostgres messages;
  private RemoteConfigsPostgres configs;

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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/001-postgres.sql")));
      statement.execute("TRUNCATE signal.messages, signal.remote_configs");
    }
    executor = Executors.newFixedThreadPool(8);
    messages = new MessagesPostgres(dataSource, Duration.ofDays(30), executor);
    configs = new RemoteConfigsPostgres(dataSource);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }
  }

  private Envelope envelope(long timestamp, long id) {
    return Envelope.newBuilder().setType(Envelope.Type.CIPHERTEXT)
        .setServerGuid(UUIDUtil.toByteString(new UUID(0, id)))
        .setServerTimestamp(timestamp).setUrgent(id == 105)
        .setContent(ByteString.copyFrom(new byte[] {(byte) 0xff, 0, 42})).build();
  }

  @Test
  void encryptedBytesOrderingPaginationAndDuplicateDelivery() {
    UUID account = UUID.randomUUID();
    Device device = DevicesHelper.createDevice((byte) 1);
    long timestamp = System.currentTimeMillis();
    List<Envelope> batch = new ArrayList<>();
    for (int i = 0; i < 205; i++) batch.add(envelope(timestamp, i));
    messages.store(batch, account, device);
    messages.store(batch, account, device);
    assertThat(Flux.from(messages.load(account, device, 7)).collectList().block(Duration.ofSeconds(10))).isEqualTo(batch);
    assertThat(messages.mayHaveMessages(account, device).join()).isTrue();
    assertThat(messages.mayHaveUrgentMessages(account, device).join()).isTrue();
  }

  @Test
  void accountsAndDeviceGenerationsAreIsolated() {
    UUID account = UUID.randomUUID();
    Device first = DevicesHelper.createDevice((byte) 1);
    first.setCreated(128);
    messages.store(List.of(envelope(System.currentTimeMillis(), 1)), account, first);
    Device replacement = DevicesHelper.createDevice((byte) 1);
    replacement.setCreated(256);
    assertThat(messages.mayHaveMessages(account, replacement).join()).isFalse();
    assertThat(messages.mayHaveMessages(UUID.randomUUID(), first).join()).isFalse();
    assertThat(messages.mayHaveMessages(account, DevicesHelper.createDevice((byte) 2)).join()).isFalse();
  }

  @Test
  void concurrentAcknowledgementsReturnTheEnvelopeExactlyOnce() {
    UUID account = UUID.randomUUID();
    Device device = DevicesHelper.createDevice((byte) 1);
    long timestamp = System.currentTimeMillis();
    messages.store(List.of(envelope(timestamp, 1)), account, device);
    var attempts = new ArrayList<CompletableFuture<java.util.Optional<Envelope>>>();
    for (int i = 0; i < 20; i++) attempts.add(messages.deleteMessage(account, device, new UUID(0, 1), timestamp));
    assertThat(attempts.stream().map(CompletableFuture::join).filter(java.util.Optional::isPresent).count()).isEqualTo(1);
    assertThat(messages.mayHaveMessages(account, device).join()).isFalse();
  }

  @Test
  void invalidLateBatchEntryRollsBackEarlierSqlBatches() {
    UUID account = UUID.randomUUID();
    Device device = DevicesHelper.createDevice((byte) 1);
    long timestamp = System.currentTimeMillis();
    List<Envelope> batch = new ArrayList<>();
    for (int i = 0; i < 150; i++) batch.add(envelope(timestamp, i));
    batch.add(Envelope.newBuilder().setServerGuid(ByteString.EMPTY).build());
    assertThrows(RuntimeException.class, () -> messages.store(batch, account, device));
    assertThat(messages.mayHaveMessages(account, device).join()).isFalse();
  }

  @Test
  void expiredEnvelopesAreHiddenAndPhysicallyRemoved() {
    UUID account = UUID.randomUUID();
    Device device = DevicesHelper.createDevice((byte) 1);
    long now = System.currentTimeMillis();
    Envelope live = envelope(now, 1);
    messages.store(List.of(envelope(now - Duration.ofDays(40).toMillis(), 2), live), account, device);
    assertThat(Flux.from(messages.load(account, device, null)).collectList().block(Duration.ofSeconds(5))).containsExactly(live);
    assertThat(messages.deleteExpired(100)).isEqualTo(1);
    assertThat(messages.deleteExpired(100)).isZero();
  }

  @Test
  void remoteConfigRetainsEnrollmentAndNullSemantics() {
    UUID account = UUID.randomUUID();
    configs.set(new RemoteConfig("global.groupsv2.groupSizeHardLimit", 100, Set.of(account), null, "10000", "test"));
    RemoteConfig saved = configs.getAll().getFirst();
    assertThat(saved.getUuids()).containsExactly(account);
    assertThat(saved.getDefaultValue()).isNull();
    assertThat(saved.getValue()).isEqualTo("10000");
    configs.set(new RemoteConfig(saved.getName(), 0, Set.of(), "1000", null, null));
    assertThat(configs.getAll()).hasSize(1);
    assertThat(configs.getAll().getFirst().getUuids()).isEmpty();
    assertThat(configs.getAll().getFirst().getValue()).isNull();
    configs.delete(saved.getName());
    assertThat(configs.getAll()).isEmpty();
  }
}
