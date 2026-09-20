// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

public final class ChangeNumberWaitingPeriodsPostgres implements ChangeNumberWaitingPeriodStore {
  private final DataSource dataSource;
  private final Clock clock;
  public ChangeNumberWaitingPeriodsPostgres(DataSource dataSource, Clock clock) { this.dataSource=dataSource; this.clock=clock; }
  @Override public void setExpiration(UUID account, Instant expiration) {
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement("""
        INSERT INTO signal.change_number_waiting_periods(account_id,expires_epoch) VALUES (?,?)
        ON CONFLICT(account_id) DO UPDATE SET expires_epoch=EXCLUDED.expires_epoch
        """)) {
      statement.setObject(1,account); statement.setLong(2,expiration.getEpochSecond()); statement.executeUpdate();
    } catch(SQLException e) { throw new IllegalStateException("Cannot write registration waiting period",e); }
  }
  @Override public Optional<Instant> getExpiration(UUID account) {
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement(
        "SELECT expires_epoch FROM signal.change_number_waiting_periods WHERE account_id=? AND expires_epoch>?")) {
      statement.setObject(1,account); statement.setLong(2,clock.instant().getEpochSecond());
      try (var rows=statement.executeQuery()) { return rows.next()?Optional.of(Instant.ofEpochSecond(rows.getLong(1))):Optional.empty(); }
    } catch(SQLException e) { throw new IllegalStateException("Cannot read registration waiting period",e); }
  }
  @Override public void delete(UUID account) {
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement(
        "DELETE FROM signal.change_number_waiting_periods WHERE account_id=?")) {
      statement.setObject(1,account); statement.executeUpdate();
    } catch(SQLException e) { throw new IllegalStateException("Cannot remove registration waiting period",e); }
  }
  public int deleteExpired(int limit) {
    if(limit<1 || limit>10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement("""
        WITH expired AS (SELECT account_id FROM signal.change_number_waiting_periods WHERE expires_epoch<=?
          ORDER BY expires_epoch LIMIT ? FOR UPDATE SKIP LOCKED)
        DELETE FROM signal.change_number_waiting_periods s USING expired e WHERE s.account_id=e.account_id
        """)) {
      statement.setLong(1,clock.instant().getEpochSecond()); statement.setInt(2,limit); return statement.executeUpdate();
    } catch(SQLException e) { throw new IllegalStateException("Cannot expire registration waiting periods",e); }
  }
}
