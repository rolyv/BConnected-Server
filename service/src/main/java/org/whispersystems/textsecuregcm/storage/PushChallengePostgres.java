// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** One outstanding challenge per account; checking and consuming a response is atomic. */
public final class PushChallengePostgres implements PushChallengeStore {
  private final DataSource dataSource;
  private final Clock clock;

  public PushChallengePostgres(DataSource dataSource, Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
  }

  @Override
  public boolean add(UUID account, byte[] token, Duration ttl) {
    try (var c = dataSource.getConnection();
        var s =
            c.prepareStatement(
                """
                INSERT INTO signal.push_challenges(aci,token,expires_at) VALUES(?,?,?) ON CONFLICT DO NOTHING
                """)) {
      s.setObject(1, account);
      s.setBytes(2, token);
      s.setLong(3, clock.instant().plus(ttl).getEpochSecond());
      return s.executeUpdate() == 1;
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL push challenge insertion failed", e);
    }
  }

  @Override
  public boolean remove(UUID account, byte[] token) {
    try (var c = dataSource.getConnection();
        var s =
            c.prepareStatement(
                """
                DELETE FROM signal.push_challenges WHERE aci=? AND token=? AND expires_at>=?
                """)) {
      s.setObject(1, account);
      s.setBytes(2, token);
      s.setLong(3, clock.instant().getEpochSecond());
      return s.executeUpdate() == 1;
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL push challenge consumption failed", e);
    }
  }

  public int deleteExpired(int limit) {
    if (limit < 1 || limit > 10000)
      throw new IllegalArgumentException("Cleanup batch must be 1..10000");
    try (var c = dataSource.getConnection();
        var s =
            c.prepareStatement(
                """
                DELETE FROM signal.push_challenges WHERE aci IN
                  (SELECT aci FROM signal.push_challenges WHERE expires_at < ? LIMIT ? FOR UPDATE SKIP LOCKED)
                """)) {
      s.setLong(1, clock.instant().getEpochSecond());
      s.setInt(2, limit);
      return s.executeUpdate();
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL push challenge cleanup failed", e);
    }
  }
}
