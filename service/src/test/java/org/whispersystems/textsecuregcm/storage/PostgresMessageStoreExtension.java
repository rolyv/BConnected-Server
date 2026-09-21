// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.postgresql.ds.PGSimpleDataSource;
import org.reactivestreams.Publisher;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;

/** Real native message storage; cleans only account queues written by the current test. */
public final class PostgresMessageStoreExtension implements BeforeAllCallback, AfterEachCallback {
  private final Set<UUID> ownedAccounts = ConcurrentHashMap.newKeySet();
  private PGSimpleDataSource dataSource;

  @Override
  public void beforeAll(ExtensionContext context) {
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(PostgresServerTestFixture.jdbcUrl());
    dataSource.setUser("postgres");
  }

  public DataSource dataSource() { return dataSource; }

  public PersistentMessageStore store(Duration retention, Executor executor) {
    return track(new MessagesPostgres(dataSource, retention, executor));
  }

  public PersistentMessageStore track(PersistentMessageStore store) {
    return new PersistentMessageStore() {
      @Override
      public void store(List<Envelope> messages, UUID account, Device device) {
        ownedAccounts.add(account);
        store.store(messages, account, device);
      }

      @Override
      public CompletableFuture<Boolean> mayHaveMessages(UUID account, Device device) {
        return store.mayHaveMessages(account, device);
      }

      @Override
      public CompletableFuture<Boolean> mayHaveUrgentMessages(UUID account, Device device) {
        return store.mayHaveUrgentMessages(account, device);
      }

      @Override
      public Publisher<Envelope> load(UUID account, Device device, Integer pageSize) {
        return store.load(account, device, pageSize);
      }

      @Override
      public CompletableFuture<Optional<Envelope>> deleteMessage(UUID account, Device device,
          UUID message, long timestamp) {
        return store.deleteMessage(account, device, message, timestamp);
      }
    };
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    if (ownedAccounts.isEmpty()) return;
    // JUnit invokes this after each test's own teardown has stopped delivery/persister work.
    try (var connection = dataSource.getConnection();
        var statement = connection.prepareStatement("DELETE FROM signal.messages WHERE account_id = ANY(?)")) {
      var accounts = connection.createArrayOf("uuid", ownedAccounts.toArray(UUID[]::new));
      try {
        statement.setArray(1, accounts);
        statement.executeUpdate();
      } finally { accounts.free(); }
    }
    ownedAccounts.clear();
  }
}
