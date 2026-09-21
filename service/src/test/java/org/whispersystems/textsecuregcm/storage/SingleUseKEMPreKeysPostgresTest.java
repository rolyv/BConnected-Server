// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class SingleUseKEMPreKeysPostgresTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private SingleUseKEMPreKeysPostgres store;

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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/005-kem-prekeys.sql")));
      statement.execute("TRUNCATE signal.single_use_kem_prekeys");
    }
    executor = Executors.newFixedThreadPool(16);
    store = new SingleUseKEMPreKeysPostgres(dataSource, executor);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(20, TimeUnit.SECONDS)).isTrue();
    }
  }

  private KEMSignedPreKey key(final long id) {
    return KeysHelper.signedKEMPreKey(id, ECKeyPair.generate());
  }

  private List<KEMSignedPreKey> keys(final int start, final int count) {
    return IntStream.range(start, start + count).mapToObj(this::key).toList();
  }

  @Test
  void libsignalEncodingAndKeyIdBoundariesRoundTripInOrder() {
    UUID account = UUID.randomUUID();
    KEMSignedPreKey min = key(KeyIdUtil.MIN_KEY_ID);
    KEMSignedPreKey max = key(KeyIdUtil.MAX_KEY_ID);
    store.store(account, (byte) 1, List.of(max, min)).join();
    assertThat(store.getCount(account, (byte) 1).join()).isEqualTo(2);
    KEMSignedPreKey first = store.take(account, (byte) 1).join().orElseThrow();
    assertThat(first.keyId()).isEqualTo(min.keyId());
    assertThat(first.serializedPublicKey()).isEqualTo(min.serializedPublicKey());
    assertThat(first.signature()).isEqualTo(min.signature());
    KEMSignedPreKey second = store.take(account, (byte) 1).join().orElseThrow();
    assertThat(second.keyId()).isEqualTo(max.keyId());
    assertThat(second.serializedPublicKey()).isEqualTo(max.serializedPublicKey());
    assertThat(second.signature()).isEqualTo(max.signature());
    assertThat(store.take(account, (byte) 1).join()).isEmpty();
    assertThat(store.getCount(account, (byte) 1).join()).isZero();
  }

  @Test
  void devicesAndAccountsAreIsolatedAndDeletionCoversTheRequestedScope() {
    UUID account = UUID.randomUUID();
    UUID other = UUID.randomUUID();
    store.store(account, (byte) 1, keys(0, 3)).join();
    store.store(account, (byte) 2, keys(0, 4)).join();
    store.store(other, (byte) 1, keys(0, 5)).join();
    store.delete(account, (byte) 1).join();
    assertThat(store.getCount(account, (byte) 1).join()).isZero();
    assertThat(store.getCount(account, (byte) 2).join()).isEqualTo(4);
    store.delete(account).join();
    assertThat(store.getCount(account, (byte) 2).join()).isZero();
    assertThat(store.getCount(other, (byte) 1).join()).isEqualTo(5);
    store.store(other, (byte) 1, List.of()).join();
    assertThat(store.getCount(other, (byte) 1).join()).isZero();
  }

  @Test
  void concurrentConsumersAcrossStoreInstancesReceiveEveryKeyAtMostOnce() {
    UUID account = UUID.randomUUID();
    store.store(account, (byte) 1, keys(0, 100)).join();
    var secondStore = new SingleUseKEMPreKeysPostgres(dataSource, executor);
    var attempts = new ArrayList<CompletableFuture<Optional<KEMSignedPreKey>>>();
    for (int i = 0; i < 140; i++) {
      attempts.add((i % 2 == 0 ? store : secondStore).take(account, (byte) 1));
    }
    List<Long> consumed = attempts.stream().map(CompletableFuture::join).flatMap(Optional::stream)
        .map(KEMSignedPreKey::keyId).toList();
    assertThat(consumed).hasSize(100).doesNotHaveDuplicates();
    assertThat(consumed).containsExactlyInAnyOrderElementsOf(IntStream.range(0, 100).mapToObj(i -> (long) i).toList());
    assertThat(store.getCount(account, (byte) 1).join()).isZero();
  }

  @Test
  void failedReplacementRollsBackDeletionAndAlreadyWrittenBatches() {
    UUID account = UUID.randomUUID();
    KEMSignedPreKey original = key(1000);
    store.store(account, (byte) 1, List.of(original)).join();
    var replacement = new ArrayList<>(keys(0, 150));
    replacement.add(key(KeyIdUtil.MAX_KEY_ID + 1));
    assertThrows(CompletionException.class, () -> store.store(account, (byte) 1, replacement).join());
    assertThat(store.getCount(account, (byte) 1).join()).isEqualTo(1);
    KEMSignedPreKey retained = store.take(account, (byte) 1).join().orElseThrow();
    assertThat(retained.keyId()).isEqualTo(original.keyId());
    assertThat(retained.serializedPublicKey()).isEqualTo(original.serializedPublicKey());
  }

  @Test
  void competingReplacementsCannotLeaveMixedBatches() {
    UUID account = UUID.randomUUID();
    var replacements = new ArrayList<CompletableFuture<Void>>();
    for (int i = 0; i < 10; i++) {
      replacements.add(store.store(account, (byte) 1, keys(i * 1000, 150)));
    }
    CompletableFuture.allOf(replacements.toArray(CompletableFuture[]::new)).join();
    assertThat(store.getCount(account, (byte) 1).join()).isEqualTo(150);
    var consumed = new ArrayList<Long>();
    for (int i = 0; i < 150; i++) consumed.add(store.take(account, (byte) 1).join().orElseThrow().keyId());
    assertThat(consumed.stream().map(id -> id / 1000).distinct().toList()).hasSize(1);
    assertThat(consumed).containsExactlyElementsOf(
        IntStream.range(0, 150).mapToObj(i -> consumed.getFirst() + i).toList());
  }

  @Test
  void accountDeletionAndReplacementHaveOnlySerializableOutcomes() {
    UUID account = UUID.randomUUID();
    for (int trial = 0; trial < 20; trial++) {
      store.store(account, (byte) 1, keys(0, 3)).join();
      store.store(account, (byte) 2, keys(0, 4)).join();
      var replacement = store.store(account, (byte) 1, keys(100, 150));
      var deletion = store.delete(account);
      CompletableFuture.allOf(replacement, deletion).join();
      // If replacement committed first, the deletion removed it. If deletion committed first, its successor
      // contains the entire new batch. The second device must be gone in either ordering.
      assertThat(store.getCount(account, (byte) 1).join()).isIn(0, 150);
      assertThat(store.getCount(account, (byte) 2).join()).isZero();
    }
  }

  @Test
  void malformedStoredEncodingDoesNotConsumeTheKey() throws Exception {
    UUID account = UUID.randomUUID();
    store.store(account, (byte) 1, List.of(key(5))).join();
    try (var connection = dataSource.getConnection();
        var statement = connection.prepareStatement("UPDATE signal.single_use_kem_prekeys SET public_key = ? WHERE account_id = ?")) {
      statement.setBytes(1, new byte[0]);
      statement.setObject(2, account);
      statement.executeUpdate();
    }
    assertThrows(CompletionException.class, () -> store.take(account, (byte) 1).join());
    assertThat(store.getCount(account, (byte) 1).join()).isEqualTo(1);
  }
  @Test
  void exhaustionUsesLastResort() {
    UUID account = UUID.randomUUID();
    KEMSignedPreKey single = key(1);
    KEMSignedPreKey fallback = key(2);
    @SuppressWarnings("unchecked")
    SignedPreKeyStore<KEMSignedPreKey> lastResort = mock(SignedPreKeyStore.class);
    when(lastResort.find(account, (byte) 1)).thenReturn(CompletableFuture.completedFuture(Optional.of(fallback)));
    var manager = new KeysManager(mock(SingleUseECPreKeyStorage.class), store,
        mock(SignedPreKeyStore.class), lastResort);
    store.store(account, (byte) 1, List.of(single)).join();
    assertThat(manager.takePQ(account, (byte) 1).join()).contains(single);
    verifyNoInteractions(lastResort);
    assertThat(manager.takePQ(account, (byte) 1).join()).contains(fallback);
    verify(lastResort).find(account, (byte) 1);
  }

  @Test
  void duplicateKeyIdsCannotBeDistributedTwice() {
    UUID account = UUID.randomUUID();
    KEMSignedPreKey replacement = key(1);
    store.store(account, (byte) 1, List.of(key(1), replacement)).join();
    assertThat(store.getCount(account, (byte) 1).join()).isEqualTo(1);
    assertThat(store.take(account, (byte) 1).join()).contains(replacement);
    assertThat(store.take(account, (byte) 1).join()).isEmpty();
  }
}
