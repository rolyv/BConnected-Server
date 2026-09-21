// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class ProfilesPostgresTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private ProfilesPostgres profiles;
  private final UUID account = UUID.randomUUID();
  private final byte[] version = {1, 2, 3};
  private final byte[] commitment = new byte[97];
  private static final Instant NOW = Instant.parse("2026-09-20T00:00:00Z");

  @BeforeEach void setUp() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var c = dataSource.getConnection(); var s = c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/006-profiles.sql")));
      s.execute("TRUNCATE signal.profiles_v1, signal.profiles_v2, signal.profile_avatars");
    }
    executor = Executors.newFixedThreadPool(8);
    profiles = new ProfilesPostgres(dataSource, executor);
  }

  @AfterEach void tearDown() throws Exception {
    if (executor != null) { executor.shutdown(); assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue(); }
  }

  private VersionedProfileV1 v1(String name) {
    return new VersionedProfileV1("010203", name.getBytes(), "avatars/test", new byte[] {7}, new byte[] {8},
        new byte[] {9}, new byte[] {10}, commitment);
  }
  private VersionedProfile v2(int value) {
    return new VersionedProfile(version, new byte[] {(byte) 0xff, 0, (byte) value}, new byte[] {99}, commitment);
  }

  @Test void dualWritePreservesCiphertextAndAccountIsolation() throws Exception {
    profiles.setBoth(account, v1("encrypted"), v2(1), null);
    assertThat(profiles.getV1(account, "010203")).contains(v1("encrypted"));
    assertThat(profiles.getV2(account, version)).contains(v2(1));
    assertThat(profiles.getV1(UUID.randomUUID(), "010203")).isEmpty();
    assertThat(profiles.getV2(account, new byte[] {4})).isEmpty();
  }

  @Test void initialAndConditionalWritesRequireTheCorrectPriorState() throws Exception {
    var noCommitment = new VersionedProfile(version, new byte[] {2}, VersionedProfile.hash(new byte[] {2}),
        null, null, null);
    assertThrows(IllegalArgumentException.class, () -> profiles.setBoth(account, v1("bad"), noCommitment, null));
    assertThrows(WriteConflictException.class, () -> profiles.setBoth(account, v1("bad"), v2(1), new byte[] {1}));
    assertThat(profiles.getV1(account, "010203")).isEmpty();
    assertThat(profiles.getV2(account, version)).isEmpty();
  }

  @Test void versionsAreIndependentAndDeleteRemovesAllVersions() throws Exception {
    var otherV1 = new VersionedProfileV1("040506", new byte[] {3}, null, null, null, null, null, commitment);
    var otherV2 = new VersionedProfile(new byte[] {4, 5, 6}, new byte[] {4}, null, commitment);
    profiles.setBoth(account, v1("first"), v2(1), null);
    profiles.setBoth(account, otherV1, otherV2, null);
    profiles.setBoth(account, v1("updated"), v2(2), v2(1).dataHash());
    assertThat(profiles.getV1(account, "010203")).contains(v1("updated"));
    assertThat(profiles.getV1(account, "040506")).contains(otherV1);
    assertThat(profiles.getV2(account, otherV2.version())).contains(otherV2);
    assertThat(profiles.deleteV1(account).join()).containsExactly("avatars/test");
    profiles.deleteV2(account).join();
    assertThat(profiles.getV1(account, "010203")).isEmpty();
    assertThat(profiles.getV1(account, "040506")).isEmpty();
    assertThat(profiles.getV2(account, version)).isEmpty();
    assertThat(profiles.getV2(account, otherV2.version())).isEmpty();
    assertThat(profiles.deleteV1(account).join()).isEmpty();
  }

  @Test void avatarOnlyInsertAndUpdatePreserveEncryptedFieldsAndCommitment() {
    var inserted = profiles.setV1Avatar(account, "new-version", "first", commitment);
    assertThat(inserted.avatar()).isEqualTo("first");
    assertThat(inserted.name()).isNull();
    assertThat(inserted.commitment()).isEqualTo(commitment);
    profiles.setV1(account, v1("encrypted"));
    var updated = profiles.setV1Avatar(account, "010203", "replacement", new byte[] {1});
    assertThat(updated.avatar()).isEqualTo("replacement");
    assertThat(updated.name()).isEqualTo(v1("encrypted").name());
    assertThat(updated.about()).isEqualTo(v1("encrypted").about());
    assertThat(updated.aboutEmoji()).isEqualTo(v1("encrypted").aboutEmoji());
    assertThat(updated.paymentAddress()).isEqualTo(v1("encrypted").paymentAddress());
    assertThat(updated.phoneNumberSharing()).isEqualTo(v1("encrypted").phoneNumberSharing());
    assertThat(updated.commitment()).isEqualTo(commitment);
  }

  @Test void paymentAddressCanBeAddedReplacedAndRemovedWithItsHash() throws Exception {
    var original = new VersionedProfile(version, new byte[] {1}, null, commitment);
    profiles.setBoth(account, v1("first"), original, null);
    assertThat(profiles.getV2(account, version).orElseThrow().paymentAddress()).isNull();
    var added = new VersionedProfile(version, new byte[] {2}, new byte[] {3}, commitment);
    profiles.setBoth(account, v1("added"), added, original.dataHash());
    assertThat(profiles.getV2(account, version)).contains(added);
    var replaced = new VersionedProfile(version, new byte[] {4}, new byte[] {5}, commitment);
    profiles.setBoth(account, v1("replaced"), replaced, added.dataHash());
    assertThat(profiles.getV2(account, version)).contains(replaced);
    var removed = new VersionedProfile(version, new byte[] {6}, null, commitment);
    profiles.setBoth(account, v1("removed"), removed, replaced.dataHash());
    var saved = profiles.getV2(account, version).orElseThrow();
    assertThat(saved.paymentAddress()).isNull();
    assertThat(saved.paymentAddressHash()).isNull();
  }

  @Test void deletionAllowsAReplacementCommitmentForTheSameVersion() throws Exception {
    profiles.setBoth(account, v1("first"), v2(1), null);
    profiles.deleteV1(account).join();
    profiles.deleteV2(account).join();
    byte[] replacement = commitment.clone();
    replacement[0] = 1;
    var freshV1 = new VersionedProfileV1("010203", null, null, null, null, null, null, replacement);
    var freshV2 = new VersionedProfile(version, new byte[] {2}, null, replacement);
    profiles.setBoth(account, freshV1, freshV2, null);
    assertThat(profiles.getV1(account, "010203")).contains(freshV1);
    assertThat(profiles.getV2(account, version)).contains(freshV2);
  }

  @Test void v1UpdatesKeepOriginalCommitmentAndRemoveNullFields() throws Exception {
    profiles.setV1(account, v1("first"));
    var update = new VersionedProfileV1("010203", null, "  ", null, null, null, null, new byte[] {123});
    profiles.setV1(account, update);
    var saved = profiles.getV1(account, "010203").orElseThrow();
    assertThat(saved.commitment()).isEqualTo(commitment);
    assertThat(saved.name()).isNull();
    assertThat(saved.avatar()).isNull();
    assertThat(saved.paymentAddress()).isNull();
    assertThat(profiles.setV1Avatar(account, "010203", "avatars/new", new byte[] {1}).commitment()).isEqualTo(commitment);
  }

  @Test void lateV1FailureRollsBackV2AndExistingV1() throws Exception {
    profiles.setBoth(account, v1("original"), v2(1), null);
    var invalid = new VersionedProfileV1(null, new byte[] {1}, null, null, null, null, null, commitment);
    assertThrows(IllegalStateException.class, () -> profiles.setBoth(account, invalid, v2(2), v2(1).dataHash()));
    assertThat(profiles.getV1(account, "010203")).contains(v1("original"));
    assertThat(profiles.getV2(account, version)).contains(v2(1));
  }

  @Test void staleHashAndChangedCommitmentCannotUpdateEitherGeneration() throws Exception {
    profiles.setBoth(account, v1("original"), v2(1), null);
    assertThrows(WriteConflictException.class, () -> profiles.setBoth(account, v1("bad"), v2(2), null));
    assertThrows(WriteConflictException.class, () -> profiles.setBoth(account, v1("bad"), v2(2), new byte[] {1}));
    var wrong = new VersionedProfile(version, new byte[] {2}, null, new byte[96]);
    assertThrows(IllegalArgumentException.class, () -> profiles.setBoth(account, v1("bad"), wrong, v2(1).dataHash()));
    assertThat(profiles.getV1(account, "010203")).contains(v1("original"));
    assertThat(profiles.getV2(account, version)).contains(v2(1));
  }

  @Test void omittedCommitmentUpdatePreservesCommitmentAndClearsPayment() throws Exception {
    profiles.setBoth(account, v1("original"), v2(1), null);
    byte[] data = {2, 3, 4};
    var update = new VersionedProfile(version, data, VersionedProfile.hash(data), null, null, null);
    profiles.setBoth(account, v1("new"), update, v2(1).dataHash());
    var saved = profiles.getV2(account, version).orElseThrow();
    assertThat(saved.data()).isEqualTo(data);
    assertThat(saved.commitment()).isEqualTo(commitment);
    assertThat(saved.paymentAddress()).isNull();
  }

  @Test void concurrentInitialAndConditionalWritesHaveOneWinnerAcrossInstances() throws Exception {
    ProfilesPostgres second = new ProfilesPostgres(dataSource, executor);
    var attempts = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < 20; i++) {
      final int value = i;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        try { (value % 2 == 0 ? profiles : second).setBoth(account, v1("first"), v2(0), null); return true; }
        catch (WriteConflictException expected) { return false; }
      }, executor));
    }
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    attempts.clear();
    for (int i = 1; i <= 20; i++) {
      final int value = i;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        try { (value % 2 == 0 ? profiles : second).setBoth(account, v1("winner" + value), v2(value), v2(0).dataHash()); return true; }
        catch (WriteConflictException expected) { return false; }
      }, executor));
    }
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    int winner = profiles.getV2(account, version).orElseThrow().data()[2];
    assertThat(profiles.getV1(account, "010203")).contains(v1("winner" + winner));
  }

  @Test void deletingProfilesIsScopedAndReturnsAvatars() throws Exception {
    UUID other = UUID.randomUUID();
    profiles.setBoth(account, v1("a"), v2(1), null);
    profiles.setBoth(other, v1("b"), v2(2), null);
    assertThat(profiles.deleteV1(account).join()).containsExactly("avatars/test");
    profiles.deleteV2(account).join();
    assertThat(profiles.getV1(account, "010203")).isEmpty();
    assertThat(profiles.getV2(account, version)).isEmpty();
    assertThat(profiles.getV1(other, "010203")).contains(v1("b"));
    assertThat(profiles.getV2(other, version)).contains(v2(2));
  }

  @Test void avatarReplacementIsAtomicAndFailedWriteRetainsPreviousValue() throws Exception {
    var avatars = profiles.avatarStore(Duration.ofDays(1), Clock.fixed(NOW, ZoneOffset.UTC));
    byte[] identity = {11, 12};
    assertThat(avatars.setAvatarUrl(identity, "first")).isEmpty();
    var attempts = new ArrayList<CompletableFuture<String>>();
    for (int i = 0; i < 20; i++) {
      final String value = "avatar-" + i;
      attempts.add(CompletableFuture.supplyAsync(() -> avatars.setAvatarUrl(identity, value).orElseThrow(), executor));
    }
    var previous = attempts.stream().map(CompletableFuture::join).toList();
    assertThat(previous).hasSize(20).doesNotHaveDuplicates().contains("first");
    String current = avatars.updateAvatarTtl(identity).orElseThrow();
    assertThat(previous).doesNotContain(current);
    assertThrows(IllegalStateException.class, () -> avatars.setAvatarUrl(identity, null));
    assertThat(avatars.deleteAvatarUrl(identity)).contains(current);
    assertThat(avatars.deleteAvatarUrl(identity)).isEmpty();
  }

  @Test void avatarExpiryIsBoundedAndRefreshKeepsTheRow() throws Exception {
    var avatars = profiles.avatarStore(Duration.ofDays(1), Clock.fixed(NOW, ZoneOffset.UTC));
    var later = profiles.avatarStore(Duration.ofDays(1), Clock.fixed(NOW.plus(Duration.ofDays(2)), ZoneOffset.UTC));
    avatars.setAvatarUrl(new byte[] {1}, "expired");
    avatars.setAvatarUrl(new byte[] {2}, "refreshed");
    assertThat(later.updateAvatarTtl(new byte[] {2})).contains("refreshed");
    assertThat(later.updateAvatarTtl(new byte[] {3})).isEmpty();
    assertThat(later.deleteExpired(1)).isEqualTo(1);
    assertThat(later.deleteExpired(1)).isZero();
    assertThat(later.updateAvatarTtl(new byte[] {1})).isEmpty();
    assertThat(later.deleteAvatarUrl(new byte[] {2})).contains("refreshed");
  }
}
