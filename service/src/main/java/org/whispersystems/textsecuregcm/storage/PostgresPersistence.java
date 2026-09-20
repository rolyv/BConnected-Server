// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.lifecycle.Managed;
import java.time.Duration;
import java.time.Clock;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.PostgresConfiguration;

public record PostgresPersistence(MessagesPostgres messages, RemoteConfigsPostgres remoteConfigs,
                                  SingleUseECPreKeysPostgres ecPreKeys, SingleUseKEMPreKeysPostgres kemPreKeys, ProfilesPostgres profiles, ProfileAvatarsPostgres profileAvatars,
                                  PhoneNumberIdentifiersPostgres phoneNumbers, VerificationSessionsPostgres verificationSessions,
                                  ChangeNumberWaitingPeriodsPostgres waitingPeriods) {
  public static PostgresPersistence build(final Environment environment, final PostgresConfiguration configuration,
      final Duration messageRetention, final Duration avatarRetention, final Clock clock, final Executor executor) {
    final HikariConfig pool = new HikariConfig();
    pool.setJdbcUrl(configuration.jdbcUrl());
    pool.setUsername(configuration.username());
    if (configuration.passwordEnvironmentVariable() != null) {
      final String password = System.getenv(configuration.passwordEnvironmentVariable());
      if (password == null || password.isBlank()) throw new IllegalStateException("PostgreSQL password environment variable is missing");
      pool.setPassword(password);
    }
    pool.setMaximumPoolSize(configuration.maximumPoolSize());
    pool.setMinimumIdle(0);
    pool.setConnectionTimeout(15000);
    pool.setInitializationFailTimeout(15000);
    pool.addDataSourceProperty("tcpKeepAlive", "true");
    pool.addDataSourceProperty("socketTimeout", "30");
    pool.addDataSourceProperty("options", "-c statement_timeout=15000 -c lock_timeout=5000");
    final HikariDataSource dataSource = new HikariDataSource(pool);
    environment.lifecycle().manage(new Managed() {
      @Override public void stop() { dataSource.close(); }
    });
    final MessagesPostgres messages = new MessagesPostgres(dataSource, messageRetention, executor);
    final ProfilesPostgres profiles = new ProfilesPostgres(dataSource, executor);
    final ProfileAvatarsPostgres avatars = profiles.avatarStore(avatarRetention, clock);
    final VerificationSessionsPostgres sessions = new VerificationSessionsPostgres(dataSource, clock);
    final ChangeNumberWaitingPeriodsPostgres waiting = new ChangeNumberWaitingPeriodsPostgres(dataSource, clock);
    environment.lifecycle().scheduledExecutorService("postgres-message-expiry-%d").build().scheduleWithFixedDelay(() -> {
      try { messages.deleteExpired(5000); avatars.deleteExpired(5000); sessions.deleteExpired(5000); waiting.deleteExpired(5000); }
      catch (RuntimeException e) { LoggerFactory.getLogger(PostgresPersistence.class).error("PostgreSQL expiry cleanup failed", e); }
    }, 60, 60, TimeUnit.SECONDS);
    return new PostgresPersistence(messages, new RemoteConfigsPostgres(dataSource),
        new SingleUseECPreKeysPostgres(dataSource, executor), new SingleUseKEMPreKeysPostgres(dataSource, executor), profiles, avatars, new PhoneNumberIdentifiersPostgres(dataSource, executor), sessions, waiting);
  }
}
