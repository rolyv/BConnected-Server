// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import com.vdurmont.semver4j.Semver;
import java.sql.SQLException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

/** Release metadata is maintained by operators; clients only read it for metrics version labels. */
public final class ClientReleasesPostgres implements ClientReleaseStore {
  private static final Logger logger = LoggerFactory.getLogger(ClientReleasesPostgres.class);

  private final DataSource dataSource;

  public ClientReleasesPostgres(final DataSource dataSource) {
    this.dataSource = Objects.requireNonNull(dataSource);
  }

  @Override
  public Map<ClientPlatform, Map<Semver, ClientRelease>> getClientReleases() {
    final Map<ClientPlatform, Map<Semver, ClientRelease>> releases = new EnumMap<>(ClientPlatform.class);

    try (var connection = dataSource.getConnection();
         var statement = connection.prepareStatement("""
             SELECT platform, version, released_at, expires_at
             FROM signal.client_releases ORDER BY platform, version
             """);
         var rows = statement.executeQuery()) {
      while (rows.next()) {
        final String platformName = rows.getString("platform");
        final String versionString = rows.getString("version");
        final long releaseSeconds = rows.getLong("released_at");
        final long expirationSeconds = rows.getLong("expires_at");

        // Match the Dynamo reader: one malformed operator-written item must not discard other releases.
        // JDBC errors propagate instead, so the manager retains its last successful snapshot.
        try {
          final ClientPlatform platform = ClientPlatform.valueOf(platformName);
          final Semver version = new Semver(versionString);
          final ClientRelease release = new ClientRelease(platform, version,
              Instant.ofEpochSecond(releaseSeconds), Instant.ofEpochSecond(expirationSeconds));
          releases.computeIfAbsent(platform, _ -> new HashMap<>()).put(version, release);
        } catch (final RuntimeException e) {
          logger.warn("Failed to parse client release item", e);
        }
      }
    } catch (final SQLException e) {
      throw new IllegalStateException("Cannot read client releases", e);
    }

    releases.replaceAll((_, versions) -> Map.copyOf(versions));
    return Map.copyOf(releases);
  }
}
