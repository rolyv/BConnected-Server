// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.sql.SQLException;
import java.time.Clock;
import java.util.Optional;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.util.SystemMapper;

public final class VerificationSessionsPostgres implements VerificationSessionStore {
  private final DataSource dataSource;
  private final Clock clock;
  public VerificationSessionsPostgres(DataSource dataSource, Clock clock) { this.dataSource=dataSource; this.clock=clock; }
  @Override public void insert(String key, VerificationSession session) { write(key, session, false); }
  // Upstream update is an upsert. Retain that contract during the database migration.
  @Override public void update(String key, VerificationSession session) { write(key, session, true); }
  private void write(String key, VerificationSession session, boolean upsert) {
    String conflict = upsert ? "DO UPDATE SET data=EXCLUDED.data, expires_epoch=EXCLUDED.expires_epoch" : "DO NOTHING";
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement(
        "INSERT INTO signal.verification_sessions (id,data,expires_epoch) VALUES (?,?::jsonb,?) ON CONFLICT(id) " + conflict)) {
      statement.setString(1,key);
      statement.setString(2,SystemMapper.jsonMapper().writeValueAsString(session));
      statement.setLong(3,session.getExpirationEpochSeconds());
      if (statement.executeUpdate()==0) throw new IllegalStateException("Verification session already exists");
    } catch (SQLException | JsonProcessingException e) { throw new IllegalStateException("Cannot write verification session",e); }
  }
  @Override public Optional<VerificationSession> findForKey(String key) {
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement(
        "SELECT data FROM signal.verification_sessions WHERE id=? AND expires_epoch>=?")) {
      statement.setString(1,key);
      statement.setLong(2,clock.instant().getEpochSecond());
      try (var rows=statement.executeQuery()) {
        if (!rows.next()) return Optional.empty();
        try {
          var session=SystemMapper.jsonMapper().readValue(rows.getString(1),VerificationSession.class);
          return session.getExpirationEpochSeconds() < clock.instant().getEpochSecond() ? Optional.empty() : Optional.of(session);
        }
        catch (JsonProcessingException e) { return Optional.empty(); }
      }
    } catch (SQLException e) { throw new IllegalStateException("Cannot read verification session",e); }
  }
  @Override public void remove(String key) {
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement(
        "DELETE FROM signal.verification_sessions WHERE id=?")) {
      statement.setString(1,key); statement.executeUpdate();
    } catch (SQLException e) { throw new IllegalStateException("Cannot remove verification session",e); }
  }
  public int deleteExpired(int limit) {
    if(limit<1 || limit>10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection=dataSource.getConnection(); var statement=connection.prepareStatement("""
        WITH expired AS (SELECT id FROM signal.verification_sessions WHERE expires_epoch<?
          ORDER BY expires_epoch LIMIT ? FOR UPDATE SKIP LOCKED)
        DELETE FROM signal.verification_sessions s USING expired e WHERE s.id=e.id
        """)) {
      statement.setLong(1,clock.instant().getEpochSecond()); statement.setInt(2,limit); return statement.executeUpdate();
    } catch(SQLException e) { throw new IllegalStateException("Cannot expire verification sessions",e); }
  }
}
