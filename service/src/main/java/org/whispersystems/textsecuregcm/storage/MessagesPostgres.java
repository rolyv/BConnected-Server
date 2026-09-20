// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.reactivestreams.Publisher;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

/** Native SQL queue. Payloads are the upstream serialized encrypted envelopes. */
public final class MessagesPostgres implements PersistentMessageStore {
  private final DataSource dataSource;
  private final Duration timeToLive;
  private final Executor executor;

  public MessagesPostgres(final DataSource dataSource, final Duration timeToLive, final Executor executor) {
    if (timeToLive.isNegative() || timeToLive.isZero()) throw new IllegalArgumentException("Positive retention required");
    this.dataSource = dataSource;
    this.timeToLive = timeToLive;
    this.executor = executor;
  }

  // Preserve upstream's device generation encoding so a relinked device cannot
  // read envelopes belonging to the previous device with the same numeric ID.
  private static long generation(final Device device) { return (device.getCreated() & ~0x7fL) + device.getId(); }
  private static void bindQueue(final PreparedStatement statement, final UUID account, final Device device) throws SQLException {
    statement.setObject(1, account);
    statement.setLong(2, generation(device));
  }

  @Override
  public void store(final List<Envelope> messages, final UUID account, final Device device) {
    if (messages.isEmpty()) return;
    try (Connection connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try (var statement = connection.prepareStatement("""
          INSERT INTO signal.messages (account_id, device_generation, server_timestamp, message_id, envelope, expires_at)
          VALUES (?, ?, ?, ?, ?, to_timestamp(?))
          ON CONFLICT (account_id, device_generation, server_timestamp, message_id)
          DO UPDATE SET envelope = EXCLUDED.envelope, expires_at = EXCLUDED.expires_at
          """)) {
        int batch = 0;
        for (Envelope message : messages) {
          bindQueue(statement, account, device);
          statement.setLong(3, message.getServerTimestamp());
          statement.setObject(4, UUIDUtil.fromByteString(message.getServerGuid()));
          statement.setBytes(5, message.toByteArray());
          statement.setLong(6, Math.addExact(message.getServerTimestamp() / 1000, timeToLive.getSeconds()));
          statement.addBatch();
          if (++batch % 100 == 0) statement.executeBatch();
        }
        if (batch % 100 != 0) statement.executeBatch();
        connection.commit();
      } catch (Exception e) { connection.rollback(); throw e; }
    } catch (SQLException e) { throw new IllegalStateException("Cannot persist encrypted envelopes", e); }
  }

  @Override
  public CompletableFuture<Boolean> mayHaveMessages(final UUID account, final Device device) {
    return CompletableFuture.supplyAsync(() -> {
      try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
          SELECT 1 FROM signal.messages WHERE account_id = ? AND device_generation = ? AND expires_at > now() LIMIT 1
          """)) {
        bindQueue(statement, account, device);
        try (var rows = statement.executeQuery()) { return rows.next(); }
      } catch (SQLException e) { throw new IllegalStateException("Cannot inspect message queue", e); }
    }, executor);
  }

  @Override
  public CompletableFuture<Boolean> mayHaveUrgentMessages(final UUID account, final Device device) {
    return Flux.from(load(account, device, 20)).any(Envelope::getUrgent).toFuture();
  }

  private record Cursor(Long timestamp, UUID messageId) {}

  @Override
  public Publisher<Envelope> load(final UUID account, final Device device, final Integer requestedPageSize) {
    if (requestedPageSize != null && requestedPageSize <= 0) throw new IllegalArgumentException("Positive page size required");
    final int pageSize = requestedPageSize == null ? 100 : Math.min(requestedPageSize, 100);
    return Flux.<List<Envelope>, Cursor>generate(() -> new Cursor(null, null), (cursor, sink) -> {
      final String after = cursor.timestamp == null ? "" : " AND (server_timestamp, message_id) > (?, ?)";
      try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
          "SELECT server_timestamp, message_id, envelope FROM signal.messages WHERE account_id = ? AND device_generation = ?"
              + " AND expires_at > now()" + after + " ORDER BY server_timestamp, message_id LIMIT ?")) {
        bindQueue(statement, account, device);
        int index = 3;
        if (cursor.timestamp != null) {
          statement.setLong(index++, cursor.timestamp);
          statement.setObject(index++, cursor.messageId);
        }
        statement.setInt(index, pageSize);
        var page = new ArrayList<Envelope>(pageSize);
        Cursor next = cursor;
        try (var rows = statement.executeQuery()) {
          while (rows.next()) {
            page.add(Envelope.parseFrom(rows.getBytes("envelope")));
            next = new Cursor(rows.getLong("server_timestamp"), rows.getObject("message_id", UUID.class));
          }
        }
        if (page.isEmpty()) sink.complete(); else sink.next(page);
        return next;
      } catch (Exception e) { sink.error(new IllegalStateException("Cannot read encrypted envelopes", e)); return cursor; }
    }).concatMapIterable(page -> page).subscribeOn(Schedulers.fromExecutor(executor));
  }

  @Override
  public CompletableFuture<Optional<Envelope>> deleteMessage(final UUID account, final Device device,
      final UUID messageId, final long serverTimestamp) {
    return CompletableFuture.supplyAsync(() -> {
      try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
          DELETE FROM signal.messages WHERE account_id = ? AND device_generation = ?
          AND server_timestamp = ? AND message_id = ? RETURNING envelope
          """)) {
        bindQueue(statement, account, device);
        statement.setLong(3, serverTimestamp);
        statement.setObject(4, messageId);
        try (var rows = statement.executeQuery()) {
          return rows.next() ? Optional.of(Envelope.parseFrom(rows.getBytes("envelope"))) : Optional.empty();
        }
      } catch (Exception e) { throw new IllegalStateException("Cannot acknowledge encrypted envelope", e); }
    }, executor);
  }

  public int deleteExpired(final int batchSize) {
    if (batchSize < 1 || batchSize > 10000) throw new IllegalArgumentException("Invalid expiry batch size");
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        WITH expired AS (
          SELECT account_id, device_generation, server_timestamp, message_id FROM signal.messages
          WHERE expires_at <= now() ORDER BY expires_at LIMIT ? FOR UPDATE SKIP LOCKED
        ) DELETE FROM signal.messages m USING expired e WHERE m.account_id = e.account_id
          AND m.device_generation = e.device_generation AND m.server_timestamp = e.server_timestamp AND m.message_id = e.message_id
        """)) {
      statement.setInt(1, batchSize);
      return statement.executeUpdate();
    } catch (SQLException e) { throw new IllegalStateException("Cannot expire encrypted envelopes", e); }
  }
}
