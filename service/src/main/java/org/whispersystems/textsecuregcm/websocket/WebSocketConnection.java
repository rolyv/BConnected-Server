/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.websocket;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Function;
import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.util.ConstantThrowable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.limits.MessageDeliveryLoopMonitor;
import org.whispersystems.textsecuregcm.metrics.MessageMetrics;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.metrics.UserAgentTagUtil;
import org.whispersystems.textsecuregcm.push.PushNotificationManager;
import org.whispersystems.textsecuregcm.push.PushNotificationScheduler;
import org.whispersystems.textsecuregcm.push.ReceiptSender;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.ClientReleaseManager;
import org.whispersystems.textsecuregcm.storage.ConflictingMessageConsumerException;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.MessageStream;
import org.whispersystems.textsecuregcm.storage.MessageDeliveryGuard;
import org.whispersystems.textsecuregcm.storage.MessageStreamEntry;
import org.whispersystems.textsecuregcm.storage.MessagesManager;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import org.whispersystems.textsecuregcm.util.ua.UserAgent;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;
import org.whispersystems.websocket.WebSocketClient;
import org.whispersystems.websocket.WebSocketResourceProvider;
import org.whispersystems.websocket.messages.WebSocketResponseMessage;
import reactor.adapter.JdkFlowAdapter;
import reactor.core.Disposable;
import reactor.core.observability.micrometer.Micrometer;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

public class WebSocketConnection {

  private static final Counter sendFailuresCounter = Metrics.counter(name(WebSocketConnection.class, "sendFailures"));

  private static final String NON_SUCCESS_RESPONSE_COUNTER_NAME = name(WebSocketConnection.class,
      "clientNonSuccessResponse");
  private static final String SEND_MESSAGES_FLUX_NAME = MetricsUtil.name(WebSocketConnection.class,
      "sendMessages");
  private static final String SEND_MESSAGE_ERROR_COUNTER = MetricsUtil.name(WebSocketConnection.class,
      "sendMessageError");

  private static final String STATUS_CODE_TAG = "status";
  private static final String STATUS_MESSAGE_TAG = "message";
  private static final String ERROR_TYPE_TAG = "errorType";
  private static final String EXCEPTION_TYPE_TAG = "exceptionType";

  @VisibleForTesting
  static final int MESSAGE_PUBLISHER_LIMIT_RATE = 100;

  @VisibleForTesting
  static final int MESSAGE_SENDER_MAX_CONCURRENCY = 256;

  private static final Duration CLOSE_WITH_PENDING_MESSAGES_NOTIFICATION_DELAY = Duration.ofMinutes(1);

  private static final Logger logger = LoggerFactory.getLogger(WebSocketConnection.class);

  private final ReceiptSender receiptSender;
  private final MessagesManager messagesManager;
  private final MessageMetrics messageMetrics;
  private final PushNotificationManager pushNotificationManager;
  private final PushNotificationScheduler pushNotificationScheduler;
  private final MessageDeliveryLoopMonitor messageDeliveryLoopMonitor;
  private final ExperimentEnrollmentManager experimentEnrollmentManager;

  private final Account authenticatedAccount;
  private final Device authenticatedDevice;
  private final MessageStream messageStream;
  private final WebSocketDeliveryAuthorization deliveryAuthorization;
  private final WebSocketClient client;
  private final @Nullable UserAgent userAgent;

  private final LongAdder sentMessageCounter = new LongAdder();
  private final AtomicReference<Disposable> messageSubscription = new AtomicReference<>();
  private final AtomicBoolean stopped = new AtomicBoolean();

  private final Scheduler messageDeliveryScheduler;

  private final ClientReleaseManager clientReleaseManager;

  public WebSocketConnection(
      final ReceiptSender receiptSender,
      final MessagesManager messagesManager,
      final MessageMetrics messageMetrics,
      final PushNotificationManager pushNotificationManager,
      final PushNotificationScheduler pushNotificationScheduler,
      final Account authenticatedAccount,
      final Device authenticatedDevice,
      final WebSocketClient client,
      final Scheduler messageDeliveryScheduler,
      final ClientReleaseManager clientReleaseManager,
      final MessageDeliveryLoopMonitor messageDeliveryLoopMonitor,
      final ExperimentEnrollmentManager experimentEnrollmentManager) {
    this(receiptSender, messagesManager, messageMetrics, pushNotificationManager, pushNotificationScheduler,
        authenticatedAccount, authenticatedDevice, client, messageDeliveryScheduler, clientReleaseManager,
        messageDeliveryLoopMonitor, experimentEnrollmentManager, null);
  }

  public WebSocketConnection(
      final ReceiptSender receiptSender, final MessagesManager messagesManager, final MessageMetrics messageMetrics,
      final PushNotificationManager pushNotificationManager, final PushNotificationScheduler pushNotificationScheduler,
      final Account authenticatedAccount, final Device authenticatedDevice, final WebSocketClient client,
      final Scheduler messageDeliveryScheduler, final ClientReleaseManager clientReleaseManager,
      final MessageDeliveryLoopMonitor messageDeliveryLoopMonitor,
      final ExperimentEnrollmentManager experimentEnrollmentManager,
      final WebSocketDeliveryAuthorization deliveryAuthorization) {
    this.deliveryAuthorization = deliveryAuthorization;
    this.receiptSender = receiptSender;
    this.messagesManager = messagesManager;
    this.messageMetrics = messageMetrics;
    this.pushNotificationManager = pushNotificationManager;
    this.pushNotificationScheduler = pushNotificationScheduler;
    this.authenticatedAccount = authenticatedAccount;
    this.authenticatedDevice = authenticatedDevice;
    this.client = client;
    this.messageDeliveryScheduler = messageDeliveryScheduler;
    this.clientReleaseManager = clientReleaseManager;
    this.messageDeliveryLoopMonitor = messageDeliveryLoopMonitor;
    this.experimentEnrollmentManager = experimentEnrollmentManager;

    this.messageStream =
        messagesManager.getMessages(authenticatedAccount.getAccountIdentifier(), authenticatedDevice);

    this.userAgent = UserAgentUtil.maybeParseUserAgentString(client.getUserAgent());
  }

  public void start() {
    authorized(guard -> {
      if (guard != null) guard.requireCurrent(authenticatedAccount.getAccountIdentifier(), authenticatedDevice);
      pushNotificationManager.handleMessagesRetrieved(authenticatedAccount, authenticatedDevice, client.getUserAgent());
      startStreaming();
      return CompletableFuture.completedFuture(null);
    }).exceptionally(failure -> { client.close(1013, "Current device authentication unavailable"); return null; });
  }

  private void startStreaming() {
    final Timer.Sample queueDrainStart = Timer.start();
    final AtomicBoolean hasSentFirstMessage = new AtomicBoolean();

    final Disposable subscription = JdkFlowAdapter.flowPublisherToFlux(messageStream.getMessages())
        .name(SEND_MESSAGES_FLUX_NAME)
        .tap(Micrometer.metrics(Metrics.globalRegistry))
        .limitRate(MESSAGE_PUBLISHER_LIMIT_RATE)
        // We want to handle conflicting connections as soon as possible, and so do this before we start processing
        // messages in the `flatMapSequential` stage below. If we didn't do this first, then we'd wait for clients to
        // process messages before sending the "connected elsewhere" signal, and while that's ultimately not harmful,
        // it's also not ideal.
        .doOnError(ConflictingMessageConsumerException.class, _ -> {
          messageMetrics.measureMessageStreamDisplaced(MessageMetrics.WEBSOCKET_CHANNEL, userAgent, true);
          client.close(4409, "Connected elsewhere");
        })
        .doOnNext(entry -> {
          if (entry instanceof MessageStreamEntry.Envelope(final Envelope message)) {
            if (hasSentFirstMessage.compareAndSet(false, true)) {
              messageDeliveryLoopMonitor.recordDeliveryAttempt(authenticatedAccount.getAccountIdentifier(),
                  authenticatedDevice.getId(),
                  UUIDUtil.fromByteString(message.getServerGuid()),
                  client.getUserAgent(),
                  MessageMetrics.WEBSOCKET_CHANNEL);
            }
          }
        })
        .flatMapSequential(entry -> switch (entry) {
          case MessageStreamEntry.Envelope envelope -> Mono.fromFuture(() -> sendMessage(envelope.message())).thenReturn(entry);
          case MessageStreamEntry.QueueEmpty _ -> Mono.just(entry);
        }, deliveryAuthorization == null ? MESSAGE_SENDER_MAX_CONCURRENCY : 8)
        // Preserve the upstream drain ordering: do not send queue-empty while preceding ACKs wait.
        .concatMap(entry -> entry instanceof MessageStreamEntry.QueueEmpty
            ? Mono.fromFuture(() -> authorized(guard -> {
                messageMetrics.measureQueueDrain(MessageMetrics.WEBSOCKET_CHANNEL, userAgent, sentMessageCounter.sum(), queueDrainStart);
                client.sendRequest("PUT", "/api/v1/queue/empty",
                    Collections.singletonList(HeaderUtils.getTimestampHeader()), Optional.empty());
                return CompletableFuture.completedFuture(null);
              })).thenReturn(entry)
            : Mono.just(entry))
        .subscribeOn(messageDeliveryScheduler)
        .subscribe(
            entry -> {},
            throwable -> {
              // `ConflictingMessageConsumerException` is handled before processing messages
              if (throwable instanceof ConflictingMessageConsumerException) {
                return;
              }

              measureSendMessageErrors(throwable);

              if (!client.isOpen()) {
                logger.debug("Client disconnected before queue cleared");
                return;
              }

              client.close(deliveryAuthorization == null ? 1011 : 1013, "Failed to retrieve messages");
            }
        );
    if (!messageSubscription.compareAndSet(null, subscription) || stopped.get()) subscription.dispose();
  }

  public void stop() {
    stopped.set(true);
    final Disposable subscription = messageSubscription.get();
    if (subscription != null) {
      subscription.dispose();
    }

    client.close(1000, "OK");

    // Closed pilot sessions have no live proof. A future guarded notification reconciler must
    // decide whether to wake this device; do not enqueue from the stale cached identity here.
    if (deliveryAuthorization != null) return;

    messagesManager.mayHaveMessages(authenticatedAccount.getAccountIdentifier(), authenticatedDevice)
        .thenAccept(mayHaveMessages -> {
          if (mayHaveMessages) {
            pushNotificationScheduler.scheduleDelayedNotification(authenticatedAccount,
                authenticatedDevice,
                CLOSE_WITH_PENDING_MESSAGES_NOTIFICATION_DELAY);
          }
        });
  }

  private CompletableFuture<Void> authorized(Function<MessageDeliveryGuard, CompletableFuture<Void>> action) {
    if (deliveryAuthorization == null) return action.apply(null);
    return deliveryAuthorization.execute(guard -> {
      if (stopped.get()) return CompletableFuture.failedFuture(
          new org.whispersystems.textsecuregcm.auth.AuthenticationUnavailableException());
      return action.apply(guard);
    });
  }

  private CompletableFuture<Void> acknowledge(UUID guid, long timestamp, MessageDeliveryGuard guard) {
    return guard == null ? messageStream.acknowledgeMessage(guid, timestamp)
        : messageStream.acknowledgeMessage(guid, timestamp, guard);
  }

  private CompletableFuture<Void> sendMessage(final Envelope message) {
    return authorized(guard -> sendAuthorizedMessage(message, guard));
  }

  private CompletableFuture<Void> sendAuthorizedMessage(final Envelope message, MessageDeliveryGuard guard) {
    if (guard != null) guard.requireCurrent(authenticatedAccount.getAccountIdentifier(), authenticatedDevice);
    if (message.getStory() && !client.shouldDeliverStories()) {
      return acknowledge(UUIDUtil.fromByteString(message.getServerGuid()), message.getServerTimestamp(), guard);
    }

    final Optional<byte[]> body = Optional.of(serializeMessage(message));

    sentMessageCounter.increment();
    messageMetrics.measureAccountEnvelopeUuidMismatches(authenticatedAccount, message);
    messageMetrics.measureMessageSent(body.map(bytes -> bytes.length).orElse(0));

    // Retain only the parts of the message we need to avoid retaining the whole `Envelope` in memory longer than
    // necessary
    final UUID messageGuid = UUIDUtil.fromByteString(message.getServerGuid());
    final long serverTimestamp = message.getServerTimestamp();
    final long clientTimestamp = message.getClientTimestamp();
    final boolean isUrgent = message.getUrgent();
    final boolean isEphemeral = message.getEphemeral();
    final ServiceIdentifier destinationServiceIdentifier =
        ServiceIdentifier.fromByteString(message.getDestinationServiceId());

    final boolean shouldSendDeliveryReceipt =
        message.hasSourceServiceId() && message.getType() != Envelope.Type.SERVER_DELIVERY_RECEIPT;
    // If the envelope has a source, and it is not a server delivery receipt, it will be an ACI.
    @Nullable final AciServiceIdentifier sourceServiceIdentifier = shouldSendDeliveryReceipt
        ? AciServiceIdentifier.fromByteString(message.getSourceServiceId())
        : null;

    final Timer.Sample sample = Timer.start();

    if (guard != null) guard.requireCurrent(); // Serialization/metrics must not extend the original lease.
    return client.sendRequest("PUT", "/api/v1/message",
            List.of(HeaderUtils.getTimestampHeader()), body)
        .whenComplete((ignored, throwable) -> {
          if (throwable != null) {
            sendFailuresCounter.increment();
          } else {
            messageMetrics.measureOutgoingMessageLatency(serverTimestamp,
                MessageMetrics.WEBSOCKET_CHANNEL,
                authenticatedDevice.isPrimary(),
                isUrgent,
                isEphemeral,
                userAgent,
                clientReleaseManager);
          }
        }).thenCompose(response -> {
          final CompletableFuture<Void> result;
          if (isSuccessResponse(response)) {

            // An ACK is a new use: a healthy connection may have renewed since the send. Capture
            // its current lineage now, then retain that exact proof through all deletion waits.
            result = authorized(ackGuard -> {
              var acknowledged = acknowledge(messageGuid, serverTimestamp, ackGuard);
              if (shouldSendDeliveryReceipt) {
                if (ackGuard == null) {
                  try {
                    receiptSender.sendReceipt(destinationServiceIdentifier, authenticatedDevice.getId(),
                        sourceServiceIdentifier, clientTimestamp);
                  } catch (RuntimeException failure) {
                    logger.warn("Failed to send receipt", failure);
                  }
                } else {
                  return acknowledged.thenRunAsync(() -> {
                    ackGuard.requireCurrent();
                    receiptSender.sendReceipt(destinationServiceIdentifier, authenticatedDevice.getId(),
                        sourceServiceIdentifier, clientTimestamp, ackGuard);
                  }, ackGuard.executor());
                }
              }
              return acknowledged;
            });
          } else {
            Tags tags = Tags.of(UserAgentTagUtil.getPlatformTag(userAgent), Tag.of(STATUS_CODE_TAG, String.valueOf(response.getStatus())));

            // TODO Remove this once we've identified the cause of message rejections from desktop clients
            if (StringUtils.isNotBlank(response.getMessage())) {
              tags = tags.and(Tag.of(STATUS_MESSAGE_TAG, response.getMessage()));
            }

            Metrics.counter(NON_SUCCESS_RESPONSE_COUNTER_NAME, tags).increment();

            result = CompletableFuture.completedFuture(null);
          }

          return result;
        })
        .thenRun(() -> messageMetrics.measureSendMessageDuration(MessageMetrics.WEBSOCKET_CHANNEL, userAgent, sample));
  }

  @VisibleForTesting
  static byte[] serializeMessage(final Envelope message) {
    return message.toBuilder().clearEphemeral().build().toByteArray();
  }

  private static boolean isSuccessResponse(final WebSocketResponseMessage response) {
    return response != null && response.getStatus() >= 200 && response.getStatus() < 300;
  }

  private void measureSendMessageErrors(final Throwable e) {
    final String errorType;

    if (e instanceof TimeoutException) {
      errorType = "timeout";
    } else if (isConnectionClosedException(e)) {
      errorType = "connectionClosed";
    } else {
      logger.warn("Send message failed", e);
      errorType = "other";
    }

    Metrics.counter(SEND_MESSAGE_ERROR_COUNTER, Tags.of(
            UserAgentTagUtil.getPlatformTag(userAgent),
            Tag.of(ERROR_TYPE_TAG, errorType),
            Tag.of(EXCEPTION_TYPE_TAG, e.getClass().getSimpleName())))
        .increment();
  }

  @VisibleForTesting
  static boolean isConnectionClosedException(final Throwable throwable) {
    return throwable instanceof java.nio.channels.ClosedChannelException ||
        throwable == WebSocketResourceProvider.CONNECTION_CLOSED_EXCEPTION ||
        throwable instanceof org.eclipse.jetty.io.EofException ||
        (throwable instanceof ConstantThrowable constantThrowable && "Closed".equals(constantThrowable.getMessage()));
  }
}
