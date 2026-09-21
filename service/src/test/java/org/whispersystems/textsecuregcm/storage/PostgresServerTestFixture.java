// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.List;
import java.util.UUID;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/** Isolated, ephemeral native storage for the full local server, independent of operator databases. */
public final class PostgresServerTestFixture {
  private static String jdbcUrl;
  private static GenericContainer<?> container;

  private PostgresServerTestFixture() {}

  public static synchronized String jdbcUrl() {
    if (jdbcUrl != null) return jdbcUrl;
    final String password = UUID.randomUUID().toString();
    container = new GenericContainer<>(DockerImageName.parse("postgres:17"))
        .withEnv("POSTGRES_DB", "signal_server_test")
        .withEnv("POSTGRES_USER", "postgres")
        .withEnv("POSTGRES_PASSWORD", password)
        .withExposedPorts(5432)
        .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\n", 2));
    try {
      container.start();
      // The URL contains only this disposable container's random test password, never operator credentials.
      final String url = "jdbc:postgresql://%s:%d/signal_server_test?password=%s".formatted(
          container.getHost(), container.getMappedPort(5432), password);
      try (var connection = DriverManager.getConnection(url, "postgres", password);
          var statement = connection.createStatement()) {
        for (String migration : List.of("001-postgres.sql", "002-ec-prekeys.sql", "003-accounts.sql",
            "004-registration.sql", "005-kem-prekeys.sql", "006-profiles.sql", "007-report-message.sql",
            "008-push-challenges.sql", "009-apple-device-checks.sql", "010-client-releases.sql")) {
          statement.execute(Files.readString(Path.of("../bconnected/migrations", migration)));
        }
      }
      Runtime.getRuntime().addShutdownHook(new Thread(container::stop, "postgres-server-test-stop"));
      jdbcUrl = url;
      return jdbcUrl;
    } catch (Exception e) {
      container.stop();
      throw new IllegalStateException("Cannot start isolated PostgreSQL server fixture", e);
    }
  }
}
