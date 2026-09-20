// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vdurmont.semver4j.Semver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class ClientReleasesPostgresTest {
  private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");

  private PGSimpleDataSource dataSource;
  private ClientReleasesPostgres store;

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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/010-client-releases.sql")));
      statement.execute("TRUNCATE signal.client_releases");
    }
    store = new ClientReleasesPostgres(dataSource);
  }

  @Test
  void emptyTableReturnsAnImmutableEmptySnapshot() {
    final Map<ClientPlatform, Map<Semver, ClientRelease>> result = store.getClientReleases();
    assertThat(result).isEmpty();
    assertThrows(UnsupportedOperationException.class, () -> result.put(ClientPlatform.IOS, Map.of()));
  }

  @Test
  void readsAllPlatformsAndPreservesEpochSecondsWithoutFilteringExpiration() throws Exception {
    insert("IOS", "1.2.3", -1, NOW.minusSeconds(1).getEpochSecond());
    insert("IOS", "2.0.0-beta.1+build.42", NOW.getEpochSecond(), NOW.getEpochSecond());
    insert("ANDROID", "1.2.3", NOW.getEpochSecond(), NOW.plusSeconds(90).getEpochSecond());
    insert("DESKTOP", "4.5.6", NOW.plusSeconds(60).getEpochSecond(), NOW.plusSeconds(120).getEpochSecond());

    assertThat(store.getClientReleases()).isEqualTo(Map.of(
        ClientPlatform.IOS, Map.of(
            new Semver("1.2.3"), release(ClientPlatform.IOS, "1.2.3", Instant.ofEpochSecond(-1), NOW.minusSeconds(1)),
            new Semver("2.0.0-beta.1+build.42"), release(ClientPlatform.IOS, "2.0.0-beta.1+build.42", NOW, NOW)),
        ClientPlatform.ANDROID, Map.of(
            new Semver("1.2.3"), release(ClientPlatform.ANDROID, "1.2.3", NOW, NOW.plusSeconds(90))),
        ClientPlatform.DESKTOP, Map.of(
            new Semver("4.5.6"), release(ClientPlatform.DESKTOP, "4.5.6", NOW.plusSeconds(60), NOW.plusSeconds(120)))));
  }

  @Test
  void malformedRowsAreIgnoredWithoutDiscardingValidReleases() throws Exception {
    insert("ANDROID", "1.0.0", NOW.getEpochSecond(), NOW.plusSeconds(60).getEpochSecond());
    insert("DESKTOP", "2.0.0", NOW.getEpochSecond(), NOW.plusSeconds(60).getEpochSecond());
    insert("IOS", "3.0.0", NOW.getEpochSecond(), NOW.plusSeconds(60).getEpochSecond());
    insert("UNRECOGNIZED_PLATFORM", "4.0.0", 0, 1);
    insert("ios", "5.0.0", 0, 1);
    insert("IOS", "not-a-valid-version", 0, 1);
    insert("IOS", "6.0.0", Long.MAX_VALUE, 1);
    insert("IOS", "7.0.0", 0, Long.MIN_VALUE);

    final Map<ClientPlatform, Map<Semver, ClientRelease>> result = store.getClientReleases();
    assertThat(result).hasSize(3);
    assertThat(result.get(ClientPlatform.ANDROID)).containsOnlyKeys(new Semver("1.0.0"));
    assertThat(result.get(ClientPlatform.DESKTOP)).containsOnlyKeys(new Semver("2.0.0"));
    assertThat(result.get(ClientPlatform.IOS)).containsOnlyKeys(new Semver("3.0.0"));
  }

  @Test
  void allInvalidRowsProduceNoPlatformEntries() throws Exception {
    insert("IOS", "not-a-version", 0, 1);
    insert("ANDROID", "1.2.3", Long.MIN_VALUE, Long.MAX_VALUE);
    insert("UNKNOWN", "1.2.3", 0, 1);
    assertThat(store.getClientReleases()).isEmpty();
  }

  @Test
  void snapshotsAreImmutableAndOperatorUpdatesDoNotMutatePriorReads() throws Exception {
    final Semver version = new Semver("1.2.3");
    insert("IOS", version.getValue(), NOW.getEpochSecond(), NOW.plusSeconds(1).getEpochSecond());
    final Map<ClientPlatform, Map<Semver, ClientRelease>> first = store.getClientReleases();
    assertThrows(UnsupportedOperationException.class, () -> first.remove(ClientPlatform.IOS));
    assertThrows(UnsupportedOperationException.class, () -> first.get(ClientPlatform.IOS).remove(version));

    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        INSERT INTO signal.client_releases (platform, version, released_at, expires_at)
        VALUES ('IOS', '1.2.3', ?, ?)
        ON CONFLICT (platform, version) DO UPDATE SET released_at = EXCLUDED.released_at,
          expires_at = EXCLUDED.expires_at
        """)) {
      statement.setLong(1, NOW.plusSeconds(10).getEpochSecond());
      statement.setLong(2, NOW.plusSeconds(20).getEpochSecond());
      assertThat(statement.executeUpdate()).isEqualTo(1);
    }
    assertThat(first.get(ClientPlatform.IOS).get(version).expiration()).isEqualTo(NOW.plusSeconds(1));
    assertThat(store.getClientReleases().get(ClientPlatform.IOS)).containsExactly(Map.entry(version,
        release(ClientPlatform.IOS, "1.2.3", NOW.plusSeconds(10), NOW.plusSeconds(20))));
  }

  @Test
  void primaryKeySeparatesPlatformsAndRejectsDuplicatePlatformVersion() throws Exception {
    insert("IOS", "1.2.3", 0, 1);
    insert("ANDROID", "1.2.3", 2, 3);
    final SQLException duplicate = assertThrows(SQLException.class, () -> insert("IOS", "1.2.3", 4, 5));
    assertThat(duplicate.getSQLState()).isEqualTo("23505");
    assertThat(store.getClientReleases().get(ClientPlatform.IOS).get(new Semver("1.2.3")).release())
        .isEqualTo(Instant.EPOCH);
    assertThat(store.getClientReleases().get(ClientPlatform.ANDROID).get(new Semver("1.2.3")).release())
        .isEqualTo(Instant.ofEpochSecond(2));
  }

  @Test
  void managerAloneAppliesStrictExpirationBoundary() throws Exception {
    insert("IOS", "1.0.0", NOW.minusSeconds(60).getEpochSecond(), NOW.minusSeconds(1).getEpochSecond());
    insert("IOS", "2.0.0", NOW.minusSeconds(60).getEpochSecond(), NOW.getEpochSecond());
    insert("IOS", "3.0.0", NOW.plusSeconds(60).getEpochSecond(), NOW.plusSeconds(120).getEpochSecond());
    final ClientReleaseManager manager = manager(store);
    manager.refreshClientVersions();
    assertThat(store.getClientReleases().get(ClientPlatform.IOS)).hasSize(3);
    assertThat(manager.isVersionActive(ClientPlatform.IOS, new Semver("1.0.0"))).isFalse();
    assertThat(manager.isVersionActive(ClientPlatform.IOS, new Semver("2.0.0"))).isFalse();
    // Upstream checks expiration alone, even when an operator has entered a future release timestamp.
    assertThat(manager.isVersionActive(ClientPlatform.IOS, new Semver("3.0.0"))).isTrue();
    assertThat(manager.isVersionActive(ClientPlatform.ANDROID, new Semver("3.0.0"))).isFalse();
  }

  @Test
  void databaseFailurePropagatesAndManagerRetainsItsLastSuccessfulSnapshot() throws Exception {
    insert("IOS", "1.2.3", NOW.getEpochSecond(), NOW.plusSeconds(60).getEpochSecond());
    final AtomicBoolean unavailable = new AtomicBoolean();
    final DataSource failingDataSource = mock(DataSource.class);
    when(failingDataSource.getConnection()).thenAnswer(_ -> {
      if (unavailable.get()) throw new SQLException("Injected connection failure");
      return dataSource.getConnection();
    });
    final ClientReleasesPostgres failingStore = new ClientReleasesPostgres(failingDataSource);
    final ClientReleaseManager manager = manager(failingStore);
    manager.refreshClientVersions();
    unavailable.set(true);

    final IllegalStateException failure = assertThrows(IllegalStateException.class, failingStore::getClientReleases);
    assertThat(failure).hasCauseInstanceOf(SQLException.class);
    manager.refreshClientVersions();
    assertThat(manager.isVersionActive(ClientPlatform.IOS, new Semver("1.2.3"))).isTrue();
  }

  private static ClientReleaseManager manager(final ClientReleaseStore releases) {
    return new ClientReleaseManager(releases, mock(ScheduledExecutorService.class), Duration.ofHours(1),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static ClientRelease release(final ClientPlatform platform, final String version,
      final Instant releasedAt, final Instant expiresAt) {
    return new ClientRelease(platform, new Semver(version), releasedAt, expiresAt);
  }

  private void insert(final String platform, final String version, final long releasedAt, final long expiresAt)
      throws SQLException {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        INSERT INTO signal.client_releases (platform, version, released_at, expires_at) VALUES (?, ?, ?, ?)
        """)) {
      statement.setString(1, platform);
      statement.setString(2, version);
      statement.setLong(3, releasedAt);
      statement.setLong(4, expiresAt);
      statement.executeUpdate();
    }
  }
}
