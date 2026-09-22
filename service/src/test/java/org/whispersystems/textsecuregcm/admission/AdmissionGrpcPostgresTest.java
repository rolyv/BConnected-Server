// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.reactivestreams.Subscription;
import org.signal.chat.messages.GetMessagesResponse;
import org.signal.grpc.simple.ServerCalls;
import org.whispersystems.textsecuregcm.auth.DisconnectionRequestManager;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.limits.MessageDeliveryLoopMonitor;
import org.whispersystems.textsecuregcm.metrics.MessageMetrics;
import org.whispersystems.textsecuregcm.push.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.adapter.JdkFlowAdapter;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Flux;
import reactor.test.publisher.TestPublisher;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionGrpcPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  AdmissionGrpcSessionManager sessions;
  final Queue<Runnable> workers = new ConcurrentLinkedQueue<>(), renewals = new ConcurrentLinkedQueue<>();
  final List<Scheduled> timers = new ArrayList<>();
  ScheduledExecutorService scheduler;
  AuthenticatedDevice principal;
  Account account;
  Device device;
  MessagesManager messages;
  MessageStream stream;
  ReceiptSender receipts;
  PushNotificationScheduler push;
  MessageDispatcher dispatcher;
  TestPublisher<MessageStreamEntry> entries;
  TestPublisher<UUID> acks;
  Envelope envelope;
  Probe probe;
  AdmissionGrpcSessionManager.Session session;
  record Scheduled(long due, FutureTask<Void> task) {}

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    scheduler = mock(ScheduledExecutorService.class);
    when(scheduler.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class))).thenAnswer(call -> {
      Runnable command = call.getArgument(0);
      long delay = call.getArgument(1);
      TimeUnit unit = call.getArgument(2);
      var task = new FutureTask<Void>(command, null);
      timers.add(new Scheduled(fixture.flow.http.nanos.get() + unit.toNanos(delay), task));
      var handle = mock(ScheduledFuture.class);
      when(handle.cancel(anyBoolean())).thenAnswer(_ -> task.cancel(false));
      return handle;
    });
    sessions = new AdmissionGrpcSessionManager(scheduler, renewals::add, workers::add);
    principal = new AuthenticatedDevice(fixture.aci, Device.PRIMARY_ID,
        fixture.gate.authorizeDevice(fixture.aci, Device.PRIMARY_ID, fixture.flow.input.password()));
    account = new AccountsPostgres(fixture.flow.ds, fixture.flow.http.clock, Runnable::run)
        .getByAccountIdentifier(fixture.aci).orElseThrow();
    device = account.getDevice(Device.PRIMARY_ID).orElseThrow();
    messages = mock(MessagesManager.class); stream = mock(MessageStream.class);
    receipts = mock(ReceiptSender.class); push = mock(PushNotificationScheduler.class);
    when(messages.getMessages(fixture.aci, device)).thenReturn(stream);
    when(stream.acknowledgeMessage(any(), anyLong(), any())).thenReturn(CompletableFuture.completedFuture(null));
    entries = TestPublisher.create(); acks = TestPublisher.create();
    when(stream.getMessages()).thenReturn(JdkFlowAdapter.publisherToFlowPublisher(entries.flux()));
    dispatcher = new MessageDispatcher(receipts, messages, new MessageMetrics(), mock(PushNotificationManager.class),
        push, mock(MessageDeliveryLoopMonitor.class), mock(DisconnectionRequestManager.class), mock(ClientReleaseManager.class));
    envelope = Envelope.newBuilder().setType(Envelope.Type.UNIDENTIFIED_SENDER)
        .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID())).setServerTimestamp(System.currentTimeMillis())
        .setDestinationServiceId(UUIDUtil.toByteString(fixture.aci))
        .setContent(com.google.protobuf.ByteString.copyFromUtf8("synthetic opaque envelope")).build();
  }

  @AfterEach void cleanup() throws Exception {
    if (probe != null) probe.cancel();
    if (sessions != null) sessions.stop();
    if (fixture != null) fixture.close();
  }

  static final class Probe extends BaseSubscriber<GetMessagesResponse> {
    final List<GetMessagesResponse> received = new ArrayList<>();
    Throwable error;
    @Override protected void hookOnSubscribe(Subscription s) {} // Test real downstream demand.
    @Override protected void hookOnNext(GetMessagesResponse response) { received.add(response); }
    @Override protected void hookOnError(Throwable failure) { error = failure; }
  }

  Flux<GetMessagesResponse> responses(boolean dropStories) {
    return sessions.withSession(principal, current -> {
      session = current;
      return dispatcher.getMessages(dropStories, "synthetic grpc", account, device, acks.flux(), current);
    });
  }
  void start(boolean dropStories, long demand) {
    probe = new Probe(); responses(dropStories).subscribe(probe);
    if (demand > 0) probe.request(demand);
    drain();
  }
  void drain() {
    int count = 0;
    while (!workers.isEmpty()) {
      if (++count > 1000) throw new AssertionError("Unbounded worker dispatch");
      workers.remove().run();
    }
  }
  void advance(long millis) { fixture.flow.http.advance(millis); runTimers(); }
  void runTimers() {
    while (true) {
      var next = timers.stream().filter(t -> !t.task().isDone() && t.due() <= fixture.flow.http.nanos.get())
          .min(Comparator.comparingLong(Scheduled::due));
      if (next.isEmpty()) return;
      next.get().task().run();
    }
  }
  void renew() { Objects.requireNonNull(renewals.poll()).run(); }
  void unavailable() { assertThat(Status.fromThrowable(probe.error).getCode()).isEqualTo(Status.Code.UNAVAILABLE); }

  @Test void prooflessPrincipalNeverInitializesQueue() {
    principal = new AuthenticatedDevice(fixture.aci, Device.PRIMARY_ID);
    start(false, 1);
    assertThat(Status.fromThrowable(probe.error).getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    verifyNoInteractions(messages);
  }

  @Test void nonPrimaryPrincipalNeverInitializesQueue() {
    principal = new AuthenticatedDevice(fixture.aci, (byte) 2, principal.admissionAuthorization());
    start(false, 1);
    assertThat(Status.fromThrowable(probe.error).getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    verifyNoInteractions(messages);
  }

  @Test void initializationWorkerWaitDoesNotRefreshProof() {
    probe = new Probe(); responses(false).subscribe(probe); probe.request(1);
    fixture.flow.http.advance(4000); drain(); unavailable(); verifyNoInteractions(messages);
  }

  @Test void queuedEmissionRejectsLocalSuspensionBeforeOnNext() {
    start(false, 1); entries.next(new MessageStreamEntry.Envelope(envelope));
    fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    drain(); assertThat(probe.received).isEmpty();
    assertThat(Status.fromThrowable(probe.error).getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
  }

  @Test void stalledDeadlineSchedulerStillCannotEmitAfterExpiry() {
    start(false, 1); entries.next(new MessageStreamEntry.Envelope(envelope));
    fixture.flow.http.advance(4000); drain();
    assertThat(probe.received).isEmpty(); unavailable();
  }

  @Test void deadlineClosesWithZeroDemandAndBlockedWorkers() {
    start(false, 0); entries.next(new MessageStreamEntry.Envelope(envelope));
    entries.assertSubscribers(1);
    acks.assertSubscribers(1);
    advance(4000); // Do not run either renewal or delivery work.
    assertThat(probe.received).isEmpty(); unavailable();
    entries.assertCancelled();
    acks.assertCancelled();
    drain(); assertThat(probe.received).isEmpty();
  }

  @Test void healthyRenewalAllowsLaterDemandWithoutExpiringBufferedPayload() {
    start(false, 0); entries.next(new MessageStreamEntry.Envelope(envelope)); drain();
    advance(2000); renew(); advance(2000); renew();
    probe.request(1); drain();
    assertThat(probe.received).hasSize(1); assertThat(probe.error).isNull();
    assertThat(fixture.requests.get()).isEqualTo(3);
  }

  @Test void renewalIssuerFailureClosesStreamWithoutDemand() {
    start(false, 0); fixture.httpStatus = 503;
    entries.assertSubscribers(1);
    advance(2000); renew(); unavailable();
    entries.assertCancelled();
  }

  @Test void cancelledStreamCannotBeReopenedByPendingRenewal() {
    start(false, 1); advance(2000); probe.cancel(); renew(); drain();
    entries.assertCancelled(); acks.assertCancelled();
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThat(probe.received).isEmpty();
  }

  @Test void cancellationBeforeInitializationDiscardsTheOpenedLease() {
    probe = new Probe(); responses(false).subscribe(probe); probe.request(1); probe.cancel();
    drain(); advance(10000);
    verifyNoInteractions(messages);
    assertThat(renewals).isEmpty();
    assertThat(probe.received).isEmpty();
  }

  @Test void lateRenewalSuccessCannotReopenCancelledStream() throws Exception {
    start(false, 1);
    var entered = new CountDownLatch(1); var release = new CompletableFuture<Void>();
    fixture.duringHttp = () -> { entered.countDown(); release.join(); };
    advance(2000);
    var task = fixture.flow.executor.submit(renewals.remove());
    assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
    probe.cancel(); release.complete(null); task.get(5, TimeUnit.SECONDS); drain();
    entries.assertCancelled(); acks.assertCancelled();
    assertThat(probe.received).isEmpty();
    assertThat(timers.stream().filter(t -> !t.task().isDone())).isEmpty();
  }

  @Test void ackAfterSuccessfulRenewalUsesNewProof() {
    start(false, 10); entries.next(new MessageStreamEntry.Envelope(envelope)); drain();
    advance(2000); renew(); fixture.flow.http.advance(2100);
    acks.next(UUIDUtil.fromByteString(envelope.getServerGuid())); drain();
    verify(stream).acknowledgeMessage(any(), anyLong(), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong());
    assertThat(probe.error).isNull();
  }

  @Test void ackQueuedOnOldProofCannotBorrowLaterRenewal() {
    start(false, 10); entries.next(new MessageStreamEntry.Envelope(envelope)); drain();
    acks.next(UUIDUtil.fromByteString(envelope.getServerGuid()));
    advance(2000); renew(); fixture.flow.http.advance(2100); drain();
    verify(stream, never()).acknowledgeMessage(any(), anyLong(), any()); unavailable();
  }

  @Test void storyDiscardUsesGuardedStorageMutation() {
    start(true, 1); entries.next(new MessageStreamEntry.Envelope(envelope.toBuilder().setStory(true).build())); drain();
    assertThat(probe.received).isEmpty();
    verify(stream).acknowledgeMessage(any(), anyLong(), any());
    verify(stream, never()).acknowledgeMessage(any(), anyLong());
  }

  @Test void expiredStoryDiscardDoesNotDelete() {
    start(true, 1); entries.next(new MessageStreamEntry.Envelope(envelope.toBuilder().setStory(true).build()));
    fixture.flow.http.advance(4000); drain();
    verify(stream, never()).acknowledgeMessage(any(), anyLong(), any()); unavailable();
  }

  @Test void queueDrainedNotificationRechecksAfterDemandWait() {
    start(false, 0); entries.next(new MessageStreamEntry.QueueEmpty()); drain();
    fixture.flow.http.advance(4000); probe.request(1); drain();
    assertThat(probe.received).isEmpty(); unavailable();
  }

  @Test void staleCachedDeviceGenerationCannotInitializeMessageStream() {
    device.setCreated(device.getCreated() - 128);
    start(false, 1); verifyNoInteractions(messages);
    unavailable();
  }

  @Test void deliveryExecutorRejectionFailsClosed() {
    sessions.stop(); sessions = new AdmissionGrpcSessionManager(scheduler, renewals::add,
        _ -> { throw new RejectedExecutionException(); });
    start(false, 1); unavailable(); verifyNoInteractions(messages);
  }

  @Test void closeNeverSchedulesPushFromCachedIdentity() {
    start(false, 1); probe.cancel(); drain();
    verify(messages, never()).mayHaveMessages(any(), any()); verifyNoInteractions(push);
  }

  @Test void actualSimpleGrpcBridgeWaitsForReadinessThenRejectsExpiredResponse() {
    @SuppressWarnings("unchecked") var observer = (ServerCallStreamObserver<GetMessagesResponse>) mock(ServerCallStreamObserver.class);
    var ready = new AtomicBoolean(false); var onReady = new AtomicReference<Runnable>();
    var error = new AtomicReference<Throwable>();
    when(observer.isReady()).thenAnswer(_ -> ready.get());
    doAnswer(call -> { onReady.set(call.getArgument(0)); return null; }).when(observer).setOnReadyHandler(any());
    doAnswer(call -> { error.set(call.getArgument(0)); return null; }).when(observer).onError(any());
    ServerCalls.serverStreamingCall("synthetic", observer,
        _ -> JdkFlowAdapter.publisherToFlowPublisher(responses(false)), failure -> failure);
    drain(); entries.next(new MessageStreamEntry.Envelope(envelope)); drain();
    verify(observer, never()).onNext(any());
    fixture.flow.http.advance(4000); ready.set(true); onReady.get().run(); drain();
    verify(observer, never()).onNext(any());
    assertThat(Status.fromThrowable(error.get()).getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }

  @Test void actualGrpcServiceCarriesProofIntoDeliveryAndAcknowledgment() throws Exception {
    var accounts = mock(AccountsManager.class);
    when(accounts.getByAccountIdentifier(fixture.aci)).thenReturn(Optional.of(account));
    var service = new MessagesGrpcService(accounts, mock(ReportMessageManager.class),
        mock(PhoneNumberIdentifierStore.class), mock(org.whispersystems.textsecuregcm.limits.RateLimiters.class),
        mock(MessageSender.class), mock(org.whispersystems.textsecuregcm.limits.CardinalityEstimator.class),
        mock(org.whispersystems.textsecuregcm.spam.SpamChecker.class), dispatcher, fixture.flow.http.clock, sessions);
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    var server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(service,
            new MockRequestAttributesInterceptor(),
            new org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor(
                org.whispersystems.textsecuregcm.auth.AccountAuthenticator.withAdmission(fixture.gate))))
        .build().start();
    var channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    try {
      var metadata = new io.grpc.Metadata();
      metadata.put(org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
          "Basic " + Base64.getEncoder().encodeToString((fixture.aci + ":" + fixture.flow.input.password())
              .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      var received = new ArrayList<GetMessagesResponse>(); var error = new AtomicReference<Throwable>();
      var requests = org.signal.chat.messages.MessagesGrpc.newStub(channel)
          .withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata))
          .getMessages(new io.grpc.stub.StreamObserver<GetMessagesResponse>() {
            @Override public void onNext(GetMessagesResponse value) { received.add(value); }
            @Override public void onError(Throwable failure) { error.set(failure); }
            @Override public void onCompleted() {}
          });
      drain();
      requests.onNext(org.signal.chat.messages.GetMessagesRequest.newBuilder()
          .setOptions(org.signal.chat.messages.GetMessagesRequest.GetMessageOptions.getDefaultInstance()).build());
      drain();
      entries.next(new MessageStreamEntry.Envelope(envelope)); drain();
      assertThat(error.get()).isNull(); assertThat(received).hasSize(1);
      requests.onNext(org.signal.chat.messages.GetMessagesRequest.newBuilder()
          .setServerGuidAck(envelope.getServerGuid()).build()); drain();
      verify(stream).acknowledgeMessage(any(), anyLong(), any());
      verify(stream, never()).acknowledgeMessage(any(), anyLong());
      advance(4000);
      assertThat(Status.fromThrowable(error.get()).getCode()).isEqualTo(Status.Code.UNAVAILABLE);
      entries.assertCancelled();
    } finally { channel.shutdownNow(); server.shutdownNow(); }
  }
}
