// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.postgresql.ds.PGSimpleDataSource;

/**
 * Native account/key transactions in a fresh owned database for each test, never an operator DB.
 */
final class PostgresAccountKeyTestExtension implements BeforeEachCallback, AfterEachCallback {
  private PGSimpleDataSource admin;
  private PGSimpleDataSource data;
  private String database;

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    final String template = PostgresServerTestFixture.jdbcUrl();
    admin = dataSource(template);
    database = "signal_keys_" + UUID.randomUUID().toString().replace("-", "");
    try (var connection = admin.getConnection();
        var statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + database);
    }
    data = dataSource(template.replace("/signal_server_test?", "/" + database + "?"));
    try (var connection = data.getConnection();
        var statement = connection.createStatement()) {
      for (String migration :
          List.of(
              "002-ec-prekeys.sql",
              "003-accounts.sql",
              "004-registration.sql",
              "005-kem-prekeys.sql")) {
        statement.execute(Files.readString(Path.of("../bconnected/migrations", migration)));
      }
    } catch (Exception e) {
      afterEach(context);
      throw e;
    }
  }

  private static PGSimpleDataSource dataSource(String url) {
    var result = new PGSimpleDataSource();
    result.setURL(url);
    result.setUser("postgres");
    return result;
  }

  DataSource dataSource() {
    return data;
  }

  KeysManager keys() {
    return new KeysManager(
        new SingleUseECPreKeysPostgres(data, Runnable::run),
        kemKeys(),
        SignedPreKeysPostgres.ec(data, Runnable::run),
        SignedPreKeysPostgres.kem(data, Runnable::run));
  }

  SingleUseKEMPreKeysPostgres kemKeys() {
    return new SingleUseKEMPreKeysPostgres(data, Runnable::run);
  }

  AccountsPostgres accounts(Clock clock) {
    return new AccountsPostgres(data, clock, Runnable::run);
  }

  PhoneNumberIdentifiersPostgres phoneNumbers() {
    return new PhoneNumberIdentifiersPostgres(data, Runnable::run);
  }

  PhoneNumberRecoveryPasswordsPostgres recovery(Clock clock) {
    return new PhoneNumberRecoveryPasswordsPostgres(data, Duration.ofDays(1), clock);
  }

  AccountLockManager locks() {
    // Unpooled, distinct data source: callbacks always obtain independent data connections.
    final PGSimpleDataSource lockDataSource = dataSource(data.getURL());
    lockDataSource.setPassword(data.getPassword());
    return new AccountLockManager(lockDataSource);
  }

  void username(byte[] hash, UUID account, Long expiry) throws SQLException {
    try (var connection = data.getConnection();
        var statement =
            connection.prepareStatement(
                "INSERT INTO signal.usernames(hash,aci,confirmed,expires_at) VALUES (?,?,?,?)")) {
      statement.setBytes(1, hash);
      statement.setObject(2, account);
      statement.setBoolean(3, expiry == null);
      statement.setObject(4, expiry);
      statement.executeUpdate();
    }
  }

  void expireUsername(byte[] hash, long expiry) throws SQLException {
    try (var connection = data.getConnection();
        var statement =
            connection.prepareStatement(
                "UPDATE signal.usernames SET expires_at=?, confirmed=false WHERE hash=?")) {
      statement.setLong(1, expiry);
      statement.setBytes(2, hash);
      statement.executeUpdate();
    }
  }

  long accountAndKeyCount() throws SQLException {
    try (var connection = data.getConnection();
        var statement = connection.createStatement();
        var rows =
            statement.executeQuery(
                "SELECT (SELECT count(*) FROM signal.accounts) + (SELECT count(*) FROM"
                    + " signal.signed_prekeys) + (SELECT count(*) FROM"
                    + " signal.phone_recovery_passwords) + (SELECT count(*) FROM"
                    + " signal.single_use_ec_prekeys) + (SELECT count(*) FROM"
                    + " signal.single_use_kem_prekeys)")) {
      rows.next();
      return rows.getLong(1);
    }
  }

  @Override
  public void afterEach(ExtensionContext context) throws SQLException {
    if (database == null) return;
    if (!database.matches("signal_keys_[0-9a-f]{32}"))
      throw new IllegalStateException("Invalid owned test database");
    try (var connection = admin.getConnection();
        var statement = connection.createStatement()) {
      statement.execute("DROP DATABASE " + database + " WITH (FORCE)");
    }
    database = null;
  }
}
