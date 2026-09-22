// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.lettuce.core.RedisFuture;
import io.lettuce.core.RedisNoScriptException;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.cluster.api.StatefulRedisClusterConnection;
import io.lettuce.core.cluster.api.async.RedisAdvancedClusterAsyncCommands;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.chat.messages.*;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.controllers.MessageController;
import org.whispersystems.textsecuregcm.controllers.MessageDeliveryNotAllowedException;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.push.*;
import org.whispersystems.textsecuregcm.redis.*;
import org.whispersystems.textsecuregcm.spam.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Native sender/recipient membership, real handler/manager boundaries and synthetic queue/provider effects only. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionSendPostgresTest {
  enum Route { HTTP, GRPC }
  enum Change { EXPIRE, SENDER_SUSPEND, RECIPIENT_SUSPEND, RECIPIENT_REPLACE, RECIPIENT_UNCONFIRM }
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  UUID recipientAci;
  AciServiceIdentifier recipientId;
  Account recipient;
  int registration;
  AccountsManager accounts;
  MessagesCache cache;
  MessagesManager manager;
  MessageSender sender;
  PushNotificationManager pushes;
  PushNotificationSender apns, fcm;
  PushNotificationScheduler scheduler;
  DynamicConfigurationManager<DynamicConfiguration> dynamic;
  RateLimiters rates;
  RateLimiter limiter;
  SpamChecker spam;
  Executor worker = Runnable::run;
  ExecutorService deletions;
  AtomicInteger enqueues = new AtomicInteger();
  Runnable inQueue = () -> {};
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  MessagesGrpc.MessagesBlockingStub grpc;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    recipientAci = UUID.randomUUID(); recipientId = new AciServiceIdentifier(recipientAci);
    cloneRecipient();
    recipient = new AccountsPostgres(fixture.flow.ds, fixture.flow.http.clock, Runnable::run)
        .getByAccountIdentifier(recipientAci).orElseThrow();
    recipient.getPrimaryDevice().setApnId("synthetic-recipient-token");
    try (var c = fixture.flow.ds.getConnection(); var s = c.prepareStatement("UPDATE signal.accounts SET data=?::jsonb WHERE aci=?")) {
      s.setString(1, SystemMapper.jsonMapper().writeValueAsString(recipient)); s.setObject(2, recipientAci); s.executeUpdate();
    }
    registration = recipient.getPrimaryDevice().getAccountRegistrationId();
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    accounts = mock(AccountsManager.class);
    when(accounts.getByServiceIdentifier(recipientId)).thenReturn(Optional.of(recipient));
    cache = mock(MessagesCache.class);
    when(cache.insert(any(), any(), anyByte(), any(), any())).thenAnswer(call -> {
      AdmissionMessageSendGuard guard = call.getArgument(4);
      return guard.dispatch(() -> { enqueues.incrementAndGet(); inQueue.run(); return CompletableFuture.completedFuture(false); });
    });
    deletions = Executors.newSingleThreadExecutor();
    manager = new MessagesManager(mock(PersistentMessageStore.class), cache, null,
        mock(RedisMessageAvailabilityManager.class), mock(ReportMessageManager.class), deletions,
        fixture.flow.http.clock, mock(ExperimentEnrollmentManager.class));
    apns = mock(PushNotificationSender.class); fcm = mock(PushNotificationSender.class);
    when(apns.sendNotification(any())).thenReturn(CompletableFuture.completedFuture(
        new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty())));
    scheduler = mock(PushNotificationScheduler.class);
    pushes = new PushNotificationManager(accounts, apns, fcm, scheduler);
    dynamic = mock(DynamicConfigurationManager.class);
    when(dynamic.getConfiguration()).thenReturn(new DynamicConfiguration());
    rebuildSender();
    rates = mock(RateLimiters.class); limiter = mock(RateLimiter.class);
    when(rates.getMessagesLimiter()).thenReturn(limiter); when(rates.getInboundMessageBytes()).thenReturn(limiter);
    spam = mock(SpamChecker.class);
    when(spam.checkForIndividualRecipientSpamHttp(any(), any(), any(), any(), any()))
        .thenReturn(new SpamCheckResult<>(Optional.empty(), Optional.empty()));
    when(spam.checkForIndividualRecipientSpamGrpc(any(), any(), any(), any()))
        .thenReturn(new SpamCheckResult<>(Optional.empty(), Optional.empty()));
    var authenticator = AccountAuthenticator.withAdmission(fixture.gate);
    var controller = new MessageController(rates, mock(CardinalityEstimator.class), sender, accounts,
        mock(PhoneNumberIdentifierStore.class), mock(ReportMessageManager.class), ServerSecretParams.generate(),
        spam, fixture.flow.http.clock, true);
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
            .setRealm("fixture").setAuthenticator(authenticator).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class)).register(controller));
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(new MessagesGrpcService(accounts, mock(ReportMessageManager.class),
            mock(PhoneNumberIdentifierStore.class), rates, sender, mock(CardinalityEstimator.class), spam,
            mock(MessageDispatcher.class), fixture.flow.http.clock, null, true),
            new MockRequestAttributesInterceptor(), new RequireAuthenticationInterceptor(authenticator)))
        .build().start();
    channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata = new io.grpc.Metadata();
    metadata.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    grpc = MessagesGrpc.newBlockingStub(channel).withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
    clearInvocations(apns, fcm, scheduler, accounts, cache, rates, limiter, spam);
  }
  void rebuildSender() { sender = new MessageSender(manager, pushes, dynamic, fixture.gate, command -> worker.execute(command)); }
  void cloneRecipient() {
    String permit = "11".repeat(32), verification = "22".repeat(32);
    fixture.sql("INSERT INTO signal.accounts(aci,pni,number,version,data) SELECT '" + recipientAci + "','" + UUID.randomUUID()
        + "','+13055550199',version,data FROM signal.accounts WHERE aci='" + fixture.aci + "'");
    fixture.sql("INSERT INTO signal.admissions SELECT (jsonb_populate_record(NULL::signal.admissions, to_jsonb(a) || jsonb_build_object("
        + "'aci','" + recipientAci + "','member_id','" + UUID.randomUUID() + "','signal_operation_id','" + UUID.randomUUID()
        + "','permit_id','\\x" + permit + "','server_verification_session_hash','\\x" + verification + "'))).* FROM signal.admissions a WHERE aci='" + fixture.aci + "'");
    fixture.sql("INSERT INTO signal.admission_confirmation_outbox(permit_id,confirmed_at) VALUES(decode('" + permit + "','hex'),clock_timestamp())");
  }
  @AfterEach void cleanup() throws Exception {
    if (channel != null) channel.shutdownNow(); if (server != null) server.shutdownNow();
    if (jersey != null) jersey.onShutdown(null); if (deletions != null) deletions.shutdownNow();
    if (fixture != null) fixture.close();
  }
  Envelope envelope(boolean urgent) { return Envelope.newBuilder().setType(Envelope.Type.CIPHERTEXT)
      .setSourceServiceId(new AciServiceIdentifier(fixture.aci).toCompactByteString()).setSourceDevice(1)
      .setDestinationServiceId(recipientId.toCompactByteString()).setServerTimestamp(fixture.flow.http.clock.millis())
      .setClientTimestamp(1).setContent(ByteString.copyFromUtf8("synthetic-ciphertext")).setUrgent(urgent).build(); }
  AdmissionMessageSendGuard guard() { return AdmissionMessageSendGuard.authorize(fixture.gate,
      AdmissionMessageSendGuard.http(principal), recipientAci, recipientId, command -> worker.execute(command)); }
  void directSend() throws Exception { sender.sendMessages(recipient, recipientId, Map.of((byte) 1, envelope(true)),
      Map.of((byte) 1, registration), Optional.empty(), "synthetic", AdmissionMessageSendGuard.http(principal)); }
  ContainerResponse http(boolean authenticated, boolean story) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"),
        URI.create("http://localhost/v1/messages/" + recipientAci + "?story=" + story), "PUT",
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), null);
    if (authenticated) request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    request.header("Content-Type", "application/json");
    request.setEntityStream(new java.io.ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(
        new IncomingMessageList(List.of(new IncomingMessage(1, (byte) 1, registration, new byte[]{1})), false, true, 1))));
    return jersey.apply(request).get(10, TimeUnit.SECONDS);
  }
  SendMessageAuthenticatedSenderResponse grpcSend() {
    return grpc.sendMessage(SendAuthenticatedSenderMessageRequest.newBuilder()
        .setDestination(GrpcServiceIdentifierUtil.toGrpcServiceIdentifier(recipientId)).setUrgent(true)
        .setMessages(IndividualRecipientMessageBundle.newBuilder().setTimestamp(1)
            .putMessages(1, IndividualRecipientMessageBundle.Message.newBuilder().setRegistrationId(registration)
                .setType(SendMessageType.DOUBLE_RATCHET).setPayload(ByteString.copyFromUtf8("synthetic-ciphertext")).build())).build());
  }
  void assertUnavailable(Route route) throws Exception {
    if (route == Route.HTTP) assertThat(http(true, false).getStatus()).isEqualTo(503);
    else assertThat(assertThrows(StatusRuntimeException.class, this::grpcSend).getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }
  void change(Change change) {
    switch (change) {
      case EXPIRE -> fixture.flow.http.advance(4000);
      case SENDER_SUSPEND -> fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp() WHERE aci='" + fixture.aci + "'");
      case RECIPIENT_SUSPEND -> fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp() WHERE aci='" + recipientAci + "'");
      case RECIPIENT_REPLACE -> fixture.sql("UPDATE signal.accounts SET version=version+1 WHERE aci='" + recipientAci + "'");
      case RECIPIENT_UNCONFIRM -> fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL WHERE permit_id=(SELECT permit_id FROM signal.admissions WHERE aci='" + recipientAci + "')");
    }
  }

  MessageDeliveryGuard deliveryGuard(Executor executor) {
    var proof = principal.admissionAuthorization();
    return new MessageDeliveryGuard() {
      @Override public AdmissionEntitlementGate.DeviceAuthorization admissionAuthorization() { return proof; }
      @Override public void requireCurrent() { proof.requireCurrent(fixture.aci, (byte) 1); }
      @Override public void requireCurrent(UUID aci, Device device) { proof.requireCurrent(aci, device.getId(), device.getCreated()); }
      @Override public void requireCurrent(java.sql.Connection connection, UUID aci, Device device) {
        proof.requireCurrent(connection, aci, device.getId(), device.getCreated());
      }
      @Override public Executor executor() { return executor; }
    };
  }

  @Test void actualRestAndGrpcSendEnqueueThenPushOnlyForCurrentMembers() throws Exception {
    assertThat(http(true, false).getStatus()).isEqualTo(200); assertThat(grpcSend().hasSuccess()).isTrue();
    assertThat(enqueues.get()).isEqualTo(2); verify(apns, times(2)).sendNotification(any()); verifyNoInteractions(fcm, scheduler);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void rateLimitWaitCannotBorrowNewSenderReceipt(Route route) throws Exception {
    doAnswer(_ -> { fixture.flow.http.advance(4000); return null; }).when(limiter).validate(fixture.aci, recipientAci);
    assertUnavailable(route); assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void spamWaitCannotReachQueueAfterExpiry(Route route) throws Exception {
    when(spam.checkForIndividualRecipientSpamHttp(any(), any(), any(), any(), any())).thenAnswer(_ -> {
      fixture.flow.http.advance(4000); return new SpamCheckResult<>(Optional.empty(), Optional.empty()); });
    when(spam.checkForIndividualRecipientSpamGrpc(any(), any(), any(), any())).thenAnswer(_ -> {
      fixture.flow.http.advance(4000); return new SpamCheckResult<>(Optional.empty(), Optional.empty()); });
    assertUnavailable(route); assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns);
  }
  @Test void staleAccountCacheCannotSelectDeviceRegistrationOrPushToken() throws Exception {
    recipient.getPrimaryDevice().setRegistrationId(registration + 1); recipient.getPrimaryDevice().setApnId("stale-cache-token");
    directSend();
    var notification = org.mockito.ArgumentCaptor.forClass(PushNotification.class);
    verify(apns).sendNotification(notification.capture());
    assertThat(notification.getValue().deviceToken()).isEqualTo("synthetic-recipient-token");
  }
  @Test void guardDestinationCopiesCannotSelectReplacementPushToken() throws Exception {
    var guard = guard(); guard.destination().getPrimaryDevice().setApnId("changed-copy");
    pushes.sendNewMessageNotification(recipient, (byte) 1, true, guard).join();
    var notification = org.mockito.ArgumentCaptor.forClass(PushNotification.class);
    verify(apns).sendNotification(notification.capture());
    assertThat(notification.getValue().deviceToken()).isEqualTo("synthetic-recipient-token");
  }
  @Test void recipientSuspensionDoesNotInvalidateSenderAuthentication() throws Exception {
    change(Change.RECIPIENT_SUSPEND);
    assertThat(http(true, false).getStatus()).isEqualTo(404);
    assertThat(grpcSend().hasDestinationNotFound()).isTrue();
    assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns);
  }
  @ParameterizedTest @EnumSource(Change.class)
  void queuedWorkerChecksOriginalSenderAndRecipientReceipts(Change change) {
    var guard = guard(); var pending = new ArrayDeque<Runnable>(); worker = pending::add;
    var future = guard.dispatch(() -> { enqueues.incrementAndGet(); return CompletableFuture.completedFuture(null); });
    change(change); pending.remove().run();
    assertThrows(CompletionException.class, future::join); assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns);
  }
  @ParameterizedTest @EnumSource(Change.class)
  void acceptedRedisEffectCannotAuthorizeLaterPush(Change change) {
    inQueue = () -> change(change);
    assertThrows(AdmissionMessageSendGuard.Failure.class, this::directSend);
    assertThat(enqueues.get()).isEqualTo(1); verifyNoInteractions(apns);
  }
  @ParameterizedTest @EnumSource(Change.class)
  void pushWorkerRechecksBothMembersAfterItsQueueWait(Change change) throws Exception {
    var guard = guard(); var pending = new ArrayDeque<Runnable>(); worker = pending::add;
    var future = pushes.sendNewMessageNotification(recipient, (byte) 1, true, guard);
    change(change); pending.remove().run(); assertThrows(CompletionException.class, future::join);
    verify(apns, never()).sendNotification(any()); verifyNoInteractions(fcm, scheduler);
  }
  @Test void originalSenderCannotBorrowRecipientFreshnessAfterPrivateHttpWait() {
    fixture.flow.http.advance(3990); fixture.duringHttp = () -> fixture.flow.http.advance(20);
    assertThrows(AdmissionMessageSendGuard.Failure.class, this::directSend);
    assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns);
  }
  @Test void allProoflessAndAnonymousFanoutPathsFailBeforeQueue() throws Exception {
    assertThrows(AdmissionMessageSendGuard.Failure.class, () -> sender.sendMessages(recipient, recipientId,
        Map.of((byte) 1, envelope(true)), Map.of((byte) 1, registration), Optional.empty(), "synthetic"));
    assertThrows(MessageDeliveryNotAllowedException.class, () -> sender.sendMultiRecipientMessage(null, null, 1, true, false, true, null));
    assertThat(http(false, false).getStatus()).isEqualTo(503); assertThat(http(false, true).getStatus()).isEqualTo(503);
    assertThat(http(true, true).getStatus()).isEqualTo(503);
    var anonymous = new MessagesAnonymousGrpcService(accounts, rates, sender, null, null, spam, fixture.flow.http.clock, false);
    assertThat(assertThrows(StatusRuntimeException.class, () -> anonymous.sendStory(SendStoryMessageRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(assertThrows(StatusRuntimeException.class, () -> anonymous.sendSingleRecipientMessage(SendSealedSenderMessageRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(assertThrows(StatusRuntimeException.class, () -> anonymous.sendMultiRecipientMessage(SendMultiRecipientMessageRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(assertThrows(StatusRuntimeException.class, () -> anonymous.sendMultiRecipientStory(SendMultiRecipientStoryRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(enqueues.get()).isZero(); verifyNoInteractions(apns, spam, limiter);
  }
  @Test void sourceEnvelopeCannotImpersonateAnotherMember() {
    var forged = envelope(true).toBuilder().setSourceServiceId(recipientId.toCompactByteString()).build();
    assertThrows(AdmissionMessageSendGuard.Failure.class, () -> sender.sendMessages(recipient, recipientId,
        Map.of((byte) 1, forged), Map.of((byte) 1, registration), Optional.empty(), "synthetic", AdmissionMessageSendGuard.http(principal)));
    assertThat(enqueues.get()).isZero();
  }
  @Test void recipientSecondaryDeviceRejectedBeforeAnyInsertion() {
    assertThrows(AdmissionMessageSendGuard.Failure.class, () -> manager.insert(recipientAci,
        Map.of((byte) 1, envelope(true), (byte) 2, envelope(true)), guard()));
    assertThat(enqueues.get()).isZero();
  }
  @Test void backgroundPushKeepsPriorityAndOriginalProofWithoutDurableScheduling() throws Exception {
    pushes.sendNewMessageNotification(recipient, (byte) 1, false, guard()).join();
    var notification = org.mockito.ArgumentCaptor.forClass(PushNotification.class); verify(apns).sendNotification(notification.capture());
    assertThat(notification.getValue().urgent()).isFalse(); verifyNoInteractions(scheduler);
  }
  @Test void unfinishedProviderFuturesHoldCapacityUntilSuccessOrFailure() throws Exception {
    var limited = new PushNotificationManager(accounts, apns, fcm, scheduler, 2);
    var first = new CompletableFuture<SendPushNotificationResult>();
    var second = new CompletableFuture<SendPushNotificationResult>();
    var third = new CompletableFuture<SendPushNotificationResult>();
    when(apns.sendNotification(any())).thenReturn(first, second, third);
    var guard = guard();
    var firstResult = limited.sendNewMessageNotification(recipient, (byte) 1, true, guard);
    var secondResult = limited.sendNewMessageNotification(recipient, (byte) 1, false, guard);
    var failure = assertThrows(AdmissionMessageSendGuard.Failure.class,
        () -> limited.sendNewMessageNotification(recipient, (byte) 1, true, guard));
    assertThat(((jakarta.ws.rs.WebApplicationException) failure.http()).getResponse().getStatus()).isEqualTo(503);
    verify(apns, times(2)).sendNotification(any());
    first.completeExceptionally(new IllegalStateException("synthetic provider failure"));
    assertThrows(CompletionException.class, firstResult::join);
    var thirdResult = limited.sendNewMessageNotification(recipient, (byte) 1, true, guard);
    var accepted = new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
    second.complete(accepted); third.complete(accepted); secondResult.join(); thirdResult.join();
    verify(apns, times(3)).sendNotification(any()); verifyNoInteractions(scheduler);
  }
  @Test void callerCancellationRetainsPermitUntilProviderCompletion() throws Exception {
    var limited = new PushNotificationManager(accounts, apns, fcm, scheduler, 1);
    var provider = new CompletableFuture<SendPushNotificationResult>();
    var accepted = new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
    when(apns.sendNotification(any())).thenReturn(provider, CompletableFuture.completedFuture(accepted));
    var guard = guard();
    var outward = limited.sendNewMessageNotification(recipient, (byte) 1, true, guard);
    assertThat(outward.cancel(false)).isTrue();
    assertThrows(AdmissionMessageSendGuard.Failure.class,
        () -> limited.sendNewMessageNotification(recipient, (byte) 1, true, guard));
    verify(apns, times(1)).sendNotification(any());
    provider.complete(accepted);
    limited.sendNewMessageNotification(recipient, (byte) 1, true, guard).join();
    verify(apns, times(2)).sendNotification(any());
  }
  @Test void synchronousProviderThrowReleasesCapacity() throws Exception {
    var limited = new PushNotificationManager(accounts, apns, fcm, scheduler, 1);
    var accepted = new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
    when(apns.sendNotification(any())).thenThrow(new IllegalStateException("synthetic provider throw"))
        .thenReturn(CompletableFuture.completedFuture(accepted));
    var guard = guard();
    assertThrows(CompletionException.class,
        () -> limited.sendNewMessageNotification(recipient, (byte) 1, true, guard).join());
    limited.sendNewMessageNotification(recipient, (byte) 1, true, guard).join();
    verify(apns, times(2)).sendNotification(any());
  }
  @Test void nativeDeliveryReceiptTraversesActualSenderQueueAndBackgroundPush() throws Exception {
    when(accounts.getByAccountIdentifier(recipientAci)).thenReturn(Optional.of(recipient));
    new ReceiptSender(accounts, sender, deletions).sendReceipt(new AciServiceIdentifier(fixture.aci), (byte) 1,
        recipientId, 10, deliveryGuard(deletions));
    deletions.submit(() -> {}).get(5, TimeUnit.SECONDS);
    assertThat(enqueues.get()).isEqualTo(1);
    var queued = org.mockito.ArgumentCaptor.forClass(Envelope.class);
    verify(cache).insert(any(), eq(recipientAci), eq((byte) 1), queued.capture(), any());
    assertThat(queued.getValue().getType()).isEqualTo(Envelope.Type.SERVER_DELIVERY_RECEIPT);
    assertThat(queued.getValue().getSourceServiceId()).isEqualTo(new AciServiceIdentifier(fixture.aci).toCompactByteString());
    var notification = org.mockito.ArgumentCaptor.forClass(PushNotification.class); verify(apns).sendNotification(notification.capture());
    assertThat(notification.getValue().urgent()).isFalse(); verifyNoInteractions(scheduler);
  }
  @Test void receiptSourceAciPniAndDeviceCannotBeRebound() {
    var delivery = deliveryGuard(Runnable::run);
    assertThrows(AdmissionMessageSendGuard.Failure.class,
        () -> AdmissionMessageSendGuard.receipt(recipientId, (byte) 1, delivery));
    assertThrows(AdmissionMessageSendGuard.Failure.class,
        () -> AdmissionMessageSendGuard.receipt(new org.whispersystems.textsecuregcm.identity.PniServiceIdentifier(UUID.randomUUID()), (byte) 1, delivery));
    assertThrows(AdmissionMessageSendGuard.Failure.class,
        () -> AdmissionMessageSendGuard.receipt(new AciServiceIdentifier(fixture.aci), (byte) 2, delivery));
    var pni = principal.admissionAuthorization().accountProjection().pni();
    AdmissionMessageSendGuard.receipt(new org.whispersystems.textsecuregcm.identity.PniServiceIdentifier(pni), (byte) 1, delivery).requireCurrent();
    assertThat(enqueues.get()).isZero();
  }
  @Test void queuedReceiptCannotBorrowRenewedSessionProof() {
    var pending = new ArrayDeque<Runnable>(); var original = deliveryGuard(pending::add);
    new ReceiptSender(accounts, sender, deletions).sendReceipt(new AciServiceIdentifier(fixture.aci), (byte) 1, recipientId, 10, original);
    fixture.flow.http.advance(3000);
    var renewed = principal.admissionAuthorization().renew(fixture.aci, (byte) 1);
    fixture.flow.http.advance(1000);
    renewed.requireCurrent(fixture.aci, (byte) 1);
    pending.remove().run();
    assertThat(enqueues.get()).isZero(); verify(accounts, never()).getByAccountIdentifier(recipientAci); verifyNoInteractions(apns);
  }
  @Test void redisNoScriptFallbackWaitCannotDispatchAfterExpiry() throws Exception {
    var guard = guard(); var redis = mock(FaultTolerantRedisClusterClient.class);
    StatefulRedisClusterConnection<byte[], byte[]> connection = mock(StatefulRedisClusterConnection.class);
    RedisAdvancedClusterAsyncCommands<byte[], byte[]> commands = mock(RedisAdvancedClusterAsyncCommands.class);
    when(redis.withBinaryCluster(any())).thenAnswer(call -> ((Function<StatefulRedisClusterConnection<byte[], byte[]>, ?>) call.getArgument(0)).apply(connection));
    when(connection.async()).thenReturn(commands);
    RedisFuture<Object> first = mock(RedisFuture.class); var completion = new CompletableFuture<Object>();
    when(first.toCompletableFuture()).thenReturn(completion);
    when(commands.evalsha(anyString(), any(), any(byte[][].class), any(byte[][].class))).thenReturn(first);
    var script = ClusterLuaScript.fromResource(redis, "lua/insert_item.lua", ScriptOutputType.BOOLEAN);
    var pending = new ArrayDeque<Runnable>(); worker = pending::add;
    var result = script.executeBinaryAsync(List.of(new byte[]{1}), List.of(new byte[]{2}), guard, guard.executor());
    pending.remove().run(); completion.completeExceptionally(new RedisNoScriptException("synthetic"));
    change(Change.EXPIRE); pending.remove().run(); assertThrows(CompletionException.class, result::join);
    verify(commands, never()).eval(anyString(), any(), any(byte[][].class), any(byte[][].class));
  }

  @ParameterizedTest @EnumSource(Route.class)
  void actualRedisConnectionWrapperPreservesAdmissionUnavailable(Route route) throws Exception {
    // The real withBinaryCluster -> withConnection implementation wraps Failure in RedisException.
    // Its connection is intentionally absent: the inner guard must reject before any command access.
    var redis = mock(FaultTolerantRedisClusterClient.class);
    when(redis.withBinaryCluster(any())).thenAnswer(call -> {
      fixture.flow.http.advance(4000); return call.callRealMethod();
    });
    var script = ClusterLuaScript.fromResource(redis, "lua/insert_item.lua", ScriptOutputType.BOOLEAN);
    doAnswer(call -> {
      AdmissionMessageSendGuard guard = call.getArgument(4);
      return script.executeBinaryAsync(List.of(new byte[]{1}), List.of(new byte[]{2}), guard, guard.executor())
          .thenApply(result -> (boolean) result);
    }).when(cache).insert(any(), any(), anyByte(), any(), any());
    assertUnavailable(route); verifyNoInteractions(apns);
  }

  @ParameterizedTest @EnumSource(Route.class)
  void guardedRedisExecutorRejectionIsUnavailable(Route route) throws Exception {
    var redis = mock(FaultTolerantRedisClusterClient.class);
    var script = ClusterLuaScript.fromResource(redis, "lua/insert_item.lua", ScriptOutputType.BOOLEAN);
    doAnswer(call -> {
      AdmissionMessageSendGuard guard = call.getArgument(4);
      return script.executeBinaryAsync(List.of(new byte[]{1}), List.of(new byte[]{2}), guard, guard.executor())
          .thenApply(result -> (boolean) result);
    }).when(cache).insert(any(), any(), anyByte(), any(), any());
    worker = _ -> { throw new RejectedExecutionException("synthetic saturation"); };
    assertUnavailable(route); verify(redis, never()).withBinaryCluster(any()); verifyNoInteractions(apns);
  }
  @Test void redisTimeoutRetryRechecksOriginalProofBeforeReDispatch() throws Exception {
    var guard = guard(); var redis = mock(FaultTolerantRedisClusterClient.class);
    StatefulRedisClusterConnection<byte[], byte[]> connection = mock(StatefulRedisClusterConnection.class);
    RedisAdvancedClusterAsyncCommands<byte[], byte[]> commands = mock(RedisAdvancedClusterAsyncCommands.class);
    when(redis.withBinaryCluster(any())).thenAnswer(call -> ((Function<StatefulRedisClusterConnection<byte[], byte[]>, ?>) call.getArgument(0)).apply(connection));
    when(connection.async()).thenReturn(commands);
    RedisFuture<Object> timeout = mock(RedisFuture.class);
    when(timeout.toCompletableFuture()).thenReturn(CompletableFuture.failedFuture(new io.lettuce.core.RedisCommandTimeoutException("synthetic")));
    when(commands.evalsha(anyString(), any(), any(byte[][].class), any(byte[][].class))).thenReturn(timeout);
    var retries = mock(ScheduledExecutorService.class); var pending = new ArrayDeque<Runnable>();
    when(retries.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class))).thenAnswer(call -> {
      pending.add(call.getArgument(0)); return mock(ScheduledFuture.class);
    });
    var result = AdmissionInsertScriptFixture.insert(redis, retries, recipientAci,
        envelope(true).toBuilder().setServerGuid(org.whispersystems.textsecuregcm.util.UUIDUtil.toByteString(UUID.randomUUID())).build(), guard).toCompletableFuture();
    assertThat(pending).hasSize(1); change(Change.EXPIRE); pending.remove().run();
    var failure = assertThrows(CompletionException.class, result::join);
    assertThat(AdmissionMessageSendGuard.unwrapDispatchFailure(failure)).isInstanceOf(AdmissionMessageSendGuard.Failure.class);
    verify(commands, times(1)).evalsha(anyString(), any(), any(byte[][].class), any(byte[][].class));
  }
}
