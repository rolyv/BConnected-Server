// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.sql.DataSource;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.limits.MessageDeliveryLoopMonitor;
import org.whispersystems.textsecuregcm.metrics.MessageMetrics;
import org.whispersystems.textsecuregcm.push.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import org.whispersystems.textsecuregcm.websocket.*;
import org.whispersystems.websocket.messages.WebSocketResponseMessage;
import reactor.adapter.JdkFlowAdapter;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

/** Synthetic socket/issuer/provider, actual account/admission/message transactions on isolated PostgreSQL. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionDeliveryPostgresTest {
  AdmissionWebSocketPostgresTest ws;
  final Queue<Runnable> deliveries = new ConcurrentLinkedQueue<>();
  final Queue<Runnable> deletions = new ConcurrentLinkedQueue<>();
  Account account;
  Device device;
  MessageStream stream;
  MessagesManager manager;
  ReceiptSender receipts;
  PushNotificationScheduler pushes;
  WebSocketConnection connection;
  Envelope envelope;
  CompletableFuture<WebSocketResponseMessage> response;

  @BeforeEach void setup() throws Exception {
    ws = new AdmissionWebSocketPostgresTest();
    ws.setup();
    ws.sessions = new AdmissionWebSocketSessionManager(ws.scheduler, ws.workers::add, deliveries::add);
    ws.connect();
    account = new AccountsPostgres(ws.fixture.flow.ds, ws.fixture.flow.http.clock, Runnable::run)
        .getByAccountIdentifier(ws.fixture.aci).orElseThrow();
    device = account.getDevice(Device.PRIMARY_ID).orElseThrow();
    manager = mock(MessagesManager.class);
    stream = mock(MessageStream.class);
    receipts = mock(ReceiptSender.class);
    pushes = mock(PushNotificationScheduler.class);
    when(manager.getMessages(account.getAccountIdentifier(), device)).thenReturn(stream);
    when(stream.acknowledgeMessage(any(), anyLong(), any())).thenReturn(CompletableFuture.completedFuture(null));
    response = new CompletableFuture<>();
    when(ws.socket.sendRequest(eq("PUT"), eq("/api/v1/message"), any(), any())).thenReturn(response);
    var queueEmptyResponse = CompletableFuture.completedFuture(success());
    when(ws.socket.sendRequest(eq("PUT"), eq("/api/v1/queue/empty"), any(), any()))
        .thenReturn(queueEmptyResponse);
    when(ws.socket.shouldDeliverStories()).thenReturn(true);
    envelope = Envelope.newBuilder().setType(Envelope.Type.UNIDENTIFIED_SENDER)
        .setDestinationServiceId(UUIDUtil.toByteString(ws.fixture.aci))
        .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID())).setServerTimestamp(System.currentTimeMillis())
        .setContent(com.google.protobuf.ByteString.copyFromUtf8("synthetic opaque envelope")).build();
    try (var c = ws.fixture.flow.ds.getConnection(); var s = c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/001-postgres.sql")));
      s.execute("TRUNCATE signal.messages");
    }
  }

  @AfterEach void cleanup() throws Exception {
    if (connection != null) connection.stop();
    if (ws != null) ws.cleanup();
  }

  static WebSocketResponseMessage success() {
    var result = mock(WebSocketResponseMessage.class);
    when(result.getStatus()).thenReturn(200);
    return result;
  }

  void start(MessageStreamEntry... entries) {
    when(stream.getMessages()).thenReturn(JdkFlowAdapter.publisherToFlowPublisher(Flux.fromArray(entries)));
    connection = new WebSocketConnection(receipts, manager, new MessageMetrics(), mock(PushNotificationManager.class),
        pushes, account, device, ws.socket, Schedulers.immediate(), mock(ClientReleaseManager.class),
        mock(MessageDeliveryLoopMonitor.class), mock(ExperimentEnrollmentManager.class),
        ws.sessions.deliveryAuthorization(ws.context));
    connection.start();
  }

  void runDelivery() { Objects.requireNonNull(deliveries.poll(), "Expected queued delivery work").run(); }
  void drainDelivery() { while (!deliveries.isEmpty()) runDelivery(); }
  void noWireOrAcknowledgment() {
    verify(ws.socket, never()).sendRequest(any(), any(), any(), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong(), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong());
  }

  @Test void delayedStartNeverSubstitutesRenewedProof() {
    start(new MessageStreamEntry.Envelope(envelope));
    ws.advance(2000); ws.runRenewal(); ws.fixture.flow.http.advance(2100);
    drainDelivery();
    noWireOrAcknowledgment();
    verify(manager, never()).mayHaveMessages(any(), any());
  }

  @Test void deliveryQueuedBeforeSuspensionDoesNotSend() {
    start(new MessageStreamEntry.Envelope(envelope)); runDelivery();
    ws.fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    drainDelivery();
    noWireOrAcknowledgment();
  }

  @Test void expiredQueueEmptyIsNotSent() {
    start(new MessageStreamEntry.QueueEmpty()); runDelivery();
    ws.fixture.flow.http.advance(4000); drainDelivery();
    noWireOrAcknowledgment();
  }

  @Test void lateAckOnExpiredSessionRetainsMessageAndDoesNotSendReceipt() {
    start(new MessageStreamEntry.Envelope(envelope)); drainDelivery();
    verify(ws.socket).sendRequest(eq("PUT"), eq("/api/v1/message"), any(), any());
    ws.advance(4000);
    response.complete(success()); drainDelivery();
    verify(stream, never()).acknowledgeMessage(any(), anyLong(), any());
    verifyNoInteractions(receipts);
  }

  @Test void freshRenewedSessionCanAcknowledgeEarlierDelivery() {
    start(new MessageStreamEntry.Envelope(envelope), new MessageStreamEntry.QueueEmpty()); drainDelivery();
    verify(ws.socket, never()).sendRequest(eq("PUT"), eq("/api/v1/queue/empty"), any(), any());
    ws.advance(2000); ws.runRenewal(); ws.fixture.flow.http.advance(2100);
    response.complete(success()); drainDelivery();
    verify(stream).acknowledgeMessage(eq(UUIDUtil.fromByteString(envelope.getServerGuid())),
        eq(envelope.getServerTimestamp()), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong());
    verify(ws.socket).sendRequest(eq("PUT"), eq("/api/v1/queue/empty"), any(), any());
    assertThat(ws.fixture.requests.get()).isEqualTo(2);
  }

  @Test void queuedAckCannotBorrowLaterRenewal() {
    start(new MessageStreamEntry.Envelope(envelope)); drainDelivery();
    response.complete(success()); // Captures the old proof, before its worker runs.
    ws.advance(2000); ws.runRenewal(); ws.fixture.flow.http.advance(2100);
    drainDelivery();
    verify(stream, never()).acknowledgeMessage(any(), anyLong(), any());
  }

  @Test void droppedStoryUsesGuardedAcknowledgment() {
    when(ws.socket.shouldDeliverStories()).thenReturn(false);
    start(new MessageStreamEntry.Envelope(envelope.toBuilder().setStory(true).build())); drainDelivery();
    verify(stream).acknowledgeMessage(any(), anyLong(), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong());
    verify(ws.socket, never()).sendRequest(any(), any(), any(), any());
  }

  @Test void expiredDroppedStoryRemainsQueued() {
    when(ws.socket.shouldDeliverStories()).thenReturn(false);
    start(new MessageStreamEntry.Envelope(envelope.toBuilder().setStory(true).build())); runDelivery();
    ws.fixture.flow.http.advance(4000); drainDelivery();
    noWireOrAcknowledgment();
  }

  @Test void deliveryExecutorRejectionClosesWithoutEffects() {
    ws.sessions.stop();
    ws.sessions = new AdmissionWebSocketSessionManager(ws.scheduler, ws.workers::add,
        _ -> { throw new RejectedExecutionException(); });
    ws.context.setAuthenticated(ws.initial); ws.connect();
    start(new MessageStreamEntry.Envelope(envelope));
    noWireOrAcknowledgment();
    verify(ws.socket, atLeastOnce()).close(eq(1013), any());
  }

  @Test void closedSessionCannotScheduleCachedIdentityPush() {
    start(new MessageStreamEntry.Envelope(envelope)); drainDelivery();
    ws.sessions.stop(); connection.stop();
    verify(manager, never()).mayHaveMessages(any(), any());
    verifyNoInteractions(pushes);
  }

  @Test void stopBeforeQueuedStartupNeverBeginsMessageStream() {
    start(new MessageStreamEntry.Envelope(envelope));
    connection.stop(); drainDelivery();
    noWireOrAcknowledgment();
    verify(stream, never()).getMessages();
    verifyNoInteractions(pushes);
  }

  @Test void transportClosedBeforeDispatchDoesNotDeliver() {
    start(new MessageStreamEntry.Envelope(envelope)); runDelivery();
    when(ws.socket.isOpen()).thenReturn(false);
    drainDelivery(); noWireOrAcknowledgment();
  }

  @Test void queueEmptyWaitAlsoRejectsClosedTransport() {
    start(new MessageStreamEntry.QueueEmpty()); runDelivery();
    when(ws.socket.isOpen()).thenReturn(false);
    drainDelivery(); noWireOrAcknowledgment();
  }

  @Test void receiptExecutorWaitCannotOutliveAckProof() {
    var accounts = mock(AccountsManager.class);
    var sender = mock(MessageSender.class);
    var actual = new ReceiptSender(accounts, sender, mock(ExecutorService.class));
    actual.sendReceipt(new org.whispersystems.textsecuregcm.identity.AciServiceIdentifier(ws.fixture.aci),
        Device.PRIMARY_ID, new org.whispersystems.textsecuregcm.identity.AciServiceIdentifier(UUID.randomUUID()),
        123L, ws.sessions.authorizeRequest(ws.context));
    ws.fixture.flow.http.advance(4000); drainDelivery();
    verifyNoInteractions(accounts, sender);
  }

  @Test void receiptAccountLookupWaitCannotExtendAckProof() {
    var accounts = mock(AccountsManager.class);
    var sender = mock(MessageSender.class);
    var actual = new ReceiptSender(accounts, sender, mock(ExecutorService.class));
    when(accounts.getByAccountIdentifier(any())).thenAnswer(_ -> {
      ws.fixture.flow.http.advance(4000); return Optional.of(account);
    });
    actual.sendReceipt(new org.whispersystems.textsecuregcm.identity.AciServiceIdentifier(ws.fixture.aci),
        Device.PRIMARY_ID, new org.whispersystems.textsecuregcm.identity.AciServiceIdentifier(UUID.randomUUID()),
        123L, ws.sessions.authorizeRequest(ws.context));
    drainDelivery(); verify(accounts).getByAccountIdentifier(any());
    verifyNoInteractions(sender);
  }

  MessagesPostgres store(DataSource ds, Executor executor) {
    return new MessagesPostgres(ds, Duration.ofDays(14), executor);
  }
  MessagesPostgres seed() {
    var store = store(ws.fixture.flow.ds, deletions::add);
    store.store(List.of(envelope), account.getAccountIdentifier(), device);
    return store;
  }
  CompletableFuture<?> delete(MessagesPostgres store, MessageDeliveryGuard guard) {
    return store.deleteMessage(account.getAccountIdentifier(), device,
        UUIDUtil.fromByteString(envelope.getServerGuid()), envelope.getServerTimestamp(), guard);
  }
  void retained() throws Exception { assertThat(ws.fixture.flow.count("SELECT count(*) FROM signal.messages")).isEqualTo(1); }

  @Test void nativeDeleteCommitsWithOriginalProof() throws Exception {
    var future = delete(seed(), ws.sessions.authorizeRequest(ws.context));
    deletions.remove().run(); future.join();
    assertThat(ws.fixture.flow.count("SELECT count(*) FROM signal.messages")).isZero();
  }

  @Test void nativeExecutorWaitExpiryRollsBackWithoutDeleting() throws Exception {
    var future = delete(seed(), ws.sessions.authorizeRequest(ws.context));
    ws.fixture.flow.http.advance(4000); deletions.remove().run();
    assertThrows(CompletionException.class, future::join); retained();
  }

  @Test void nativePoolWaitExpiryDoesNotDelete() throws Exception {
    seed(); var ds = mock(DataSource.class);
    when(ds.getConnection()).thenAnswer(_ -> {
      ws.fixture.flow.http.advance(4000); return ws.fixture.flow.ds.getConnection();
    });
    var future = delete(store(ds, Runnable::run), ws.sessions.authorizeRequest(ws.context));
    assertThrows(CompletionException.class, future::join); retained();
    verify(ds, times(1)).getConnection();
  }

  @Test void messageRowWaitExpiryRollsBackDeletion() throws Exception {
    seed(); var guard = ws.sessions.authorizeRequest(ws.context);
    try (var holding = ws.fixture.flow.ds.getConnection(); var s = holding.createStatement()) {
      holding.setAutoCommit(false); s.execute("SELECT * FROM signal.messages FOR UPDATE");
      var future = delete(store(ws.fixture.flow.ds, ws.fixture.flow.executor), guard);
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      while (ws.fixture.flow.count("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()"
          + " AND wait_event_type='Lock' AND query LIKE 'DELETE FROM signal.messages%'") == 0) {
        if (System.nanoTime() > deadline) throw new AssertionError("Deletion did not reach row lock");
        Thread.sleep(10);
      }
      ws.fixture.flow.http.advance(4000); holding.rollback();
      assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
    }
    retained();
  }

  @Test void nativeAckAfterCredentialMutationRetainsEnvelope() throws Exception {
    var store = seed(); var guard = ws.sessions.authorizeRequest(ws.context);
    ws.fixture.sql("UPDATE signal.accounts SET version=version+1");
    var future = delete(store, guard); deletions.remove().run();
    assertThrows(CompletionException.class, future::join); retained();
  }

  @Test void differentAccountOrDeviceGenerationCannotConsumeQueue() throws Exception {
    var store = seed(); var guard = ws.sessions.authorizeRequest(ws.context);
    var other = store.deleteMessage(UUID.randomUUID(), device, UUIDUtil.fromByteString(envelope.getServerGuid()),
        envelope.getServerTimestamp(), guard);
    deletions.remove().run(); assertThrows(CompletionException.class, other::join); retained();
    var stale = new Device(); stale.setId(device.getId()); stale.setCreated(device.getCreated() - 128);
    var wrong = store.deleteMessage(account.getAccountIdentifier(), stale,
        UUIDUtil.fromByteString(envelope.getServerGuid()), envelope.getServerTimestamp(), guard);
    deletions.remove().run(); assertThrows(CompletionException.class, wrong::join); retained();
  }

  @Test void redisMissCannotDispatchSqlAfterOriginalAckExpiry() throws Exception {
    var store = seed(); var cache = mock(MessagesCache.class);
    var removed = new CompletableFuture<Optional<RemovedMessage>>();
    when(cache.remove(any(), anyByte(), any(UUID.class))).thenReturn(removed);
    var stream = new RedisDynamoDbMessageStream(store, cache, mock(RedisMessageAvailabilityManager.class),
        account.getAccountIdentifier(), device, false);
    var future = stream.acknowledgeMessage(UUIDUtil.fromByteString(envelope.getServerGuid()),
        envelope.getServerTimestamp(), ws.sessions.authorizeRequest(ws.context));
    removed.complete(Optional.empty());
    assertThat(deliveries).hasSize(1); // Redis completion only queues, does not run blocking SQL.
    ws.fixture.flow.http.advance(4000); drainDelivery();
    assertThrows(CompletionException.class, future::join);
    assertThat(deletions).isEmpty(); retained();
  }
}
