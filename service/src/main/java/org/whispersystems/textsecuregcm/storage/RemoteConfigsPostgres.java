// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;

public final class RemoteConfigsPostgres implements RemoteConfigStore {
  private final DataSource dataSource;

  public RemoteConfigsPostgres(final DataSource dataSource) { this.dataSource = dataSource; }

  @Override
  public void set(final RemoteConfig config) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        INSERT INTO signal.remote_configs (name, percentage, enrolled_accounts, default_value, value, hash_key)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (name) DO UPDATE SET percentage = EXCLUDED.percentage,
          enrolled_accounts = EXCLUDED.enrolled_accounts, default_value = EXCLUDED.default_value,
          value = EXCLUDED.value, hash_key = EXCLUDED.hash_key
        """)) {
      statement.setString(1, config.getName());
      statement.setInt(2, config.getPercentage());
      var accounts = connection.createArrayOf("uuid", config.getUuids() == null ? new UUID[0] : config.getUuids().toArray(UUID[]::new));
      try {
        statement.setArray(3, accounts);
        statement.setString(4, config.getDefaultValue());
        statement.setString(5, config.getValue());
        statement.setString(6, config.getHashKey());
        statement.executeUpdate();
      } finally { accounts.free(); }
    } catch (SQLException e) { throw new IllegalStateException("Cannot persist remote configuration", e); }
  }

  @Override
  public List<RemoteConfig> getAll() {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
        "SELECT name, percentage, enrolled_accounts, default_value, value, hash_key FROM signal.remote_configs ORDER BY name");
        var results = statement.executeQuery()) {
      var configs = new ArrayList<RemoteConfig>();
      while (results.next()) {
        var accounts = results.getArray("enrolled_accounts");
        try {
          configs.add(new RemoteConfig(results.getString("name"), results.getInt("percentage"),
              new HashSet<>(Arrays.asList((UUID[]) accounts.getArray())), results.getString("default_value"),
              results.getString("value"), results.getString("hash_key")));
        } finally { accounts.free(); }
      }
      return configs;
    } catch (SQLException e) { throw new IllegalStateException("Cannot read remote configuration", e); }
  }

  @Override
  public void delete(final String name) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
        "DELETE FROM signal.remote_configs WHERE name = ?")) {
      statement.setString(1, name);
      statement.executeUpdate();
    } catch (SQLException e) { throw new IllegalStateException("Cannot delete remote configuration", e); }
  }
}
