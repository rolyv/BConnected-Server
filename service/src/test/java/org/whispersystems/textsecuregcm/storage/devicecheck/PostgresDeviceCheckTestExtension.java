// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.webauthn4j.appattest.DeviceCheckManager;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.storage.PostgresServerTestFixture;

/** Fresh App Attest database per test, using only the shared disposable PostgreSQL container. */
final class PostgresDeviceCheckTestExtension implements BeforeEachCallback, AfterEachCallback {
  private PGSimpleDataSource admin;
  private PGSimpleDataSource data;
  private String database;

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    final String template = PostgresServerTestFixture.jdbcUrl();
    admin = dataSource(template);
    database = "signal_devicecheck_" + UUID.randomUUID().toString().replace("-", "");
    try (var connection = admin.getConnection();
        var statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + database);
    }
    data = dataSource(template.replace("/signal_server_test?", "/" + database + "?"));
    try (var connection = data.getConnection();
        var statement = connection.createStatement()) {
      statement.execute(
          Files.readString(Path.of("../bconnected/migrations/009-apple-device-checks.sql")));
    } catch (Exception e) {
      afterEach(context);
      throw e;
    }
  }

  private static PGSimpleDataSource dataSource(String url) {
    var source = new PGSimpleDataSource();
    source.setURL(url);
    source.setUser("postgres");
    return source;
  }

  DataSource dataSource() {
    return data;
  }

  AppleDeviceChecksPostgres store() {
    return new AppleDeviceChecksPostgres(data, DeviceCheckManager.createObjectConverter());
  }

  @Override
  public void afterEach(ExtensionContext context) throws SQLException {
    if (database == null) return;
    if (!database.matches("signal_devicecheck_[0-9a-f]{32}")) {
      throw new IllegalStateException("Invalid owned test database");
    }
    try (var connection = admin.getConnection();
        var statement = connection.createStatement()) {
      statement.execute("DROP DATABASE " + database + " WITH (FORCE)");
    }
    database = null;
  }
}
