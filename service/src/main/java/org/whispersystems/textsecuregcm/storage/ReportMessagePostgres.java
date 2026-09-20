// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import javax.sql.DataSource;

/** Native report eligibility hash storage. Hash construction and report side effects remain in the manager. */
public final class ReportMessagePostgres implements ReportMessageStore {
  private static final String REMOVED_MESSAGE_COUNTER_NAME = name(ReportMessagePostgres.class, "removed");
  private static final Timer REMOVED_MESSAGE_AGE_TIMER = Timer
      .builder(name(ReportMessagePostgres.class, "removedMessageAge"))
      .distributionStatisticExpiry(Duration.ofDays(1))
      .register(Metrics.globalRegistry);

  private final DataSource dataSource;
  private final Duration ttl;
  private final Clock clock;
  private final Executor executor;

  public ReportMessagePostgres(final DataSource dataSource, final Duration ttl, final Clock clock,
      final Executor executor) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.ttl = Objects.requireNonNull(ttl);
    this.clock = Objects.requireNonNull(clock);
    this.executor = Objects.requireNonNull(executor);
  }

  @Override
  public CompletableFuture<Void> store(final byte[] hash) {
    final byte[] immutableHash = hash.clone();
    final long expiresAt = clock.instant().plus(ttl).getEpochSecond();
    return CompletableFuture.runAsync(() -> {
      try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
          INSERT INTO signal.report_messages (hash, expires_at) VALUES (?, ?)
          ON CONFLICT (hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
          """)) {
        statement.setBytes(1, immutableHash);
        statement.setLong(2, expiresAt);
        statement.executeUpdate();
      } catch (SQLException e) {
        throw new CompletionException("PostgreSQL message report storage failed", e);
      }
    }, executor);
  }

  @Override
  public boolean remove(final byte[] hash) {
    final boolean found;
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        DELETE FROM signal.report_messages WHERE hash = ? RETURNING expires_at
        """)) {
      statement.setBytes(1, hash);
      try (var result = statement.executeQuery()) {
        found = result.next();
        if (found) {
          final Instant expiration = Instant.ofEpochSecond(result.getLong("expires_at"));
          REMOVED_MESSAGE_AGE_TIMER.record(ttl.minus(Duration.between(clock.instant(), expiration)));
        }
      }
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL message report consumption failed", e);
    }
    Metrics.counter(REMOVED_MESSAGE_COUNTER_NAME, "found", String.valueOf(found)).increment();
    return found;
  }

  /** Upstream accepts an extant hash regardless of TTL; expiration removes rows asynchronously. */
  public int deleteExpired(final int batchSize) {
    if (batchSize < 1 || batchSize > 10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        WITH expired AS (
          SELECT hash FROM signal.report_messages WHERE expires_at < ?
          ORDER BY expires_at, hash LIMIT ? FOR UPDATE SKIP LOCKED
        )
        DELETE FROM signal.report_messages message USING expired WHERE message.hash = expired.hash
        """)) {
      statement.setLong(1, clock.instant().getEpochSecond());
      statement.setInt(2, batchSize);
      return statement.executeUpdate();
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL message report expiry failed", e);
    }
  }
}
