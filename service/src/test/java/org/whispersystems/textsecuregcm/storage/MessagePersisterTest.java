/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.whispersystems.textsecuregcm.util.MockUtils.exactly;

import com.google.protobuf.ByteString;
import io.lettuce.core.RedisException;
import io.lettuce.core.cluster.SlotHash;
import io.lettuce.core.cluster.models.partitions.RedisClusterNode;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicMessagePersisterConfiguration;
import org.whispersystems.textsecuregcm.entities.MessageProtos;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.TestClock;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;
import reactor.util.retry.Retry;

@Timeout(value = 15, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class MessagePersisterTest {

  @RegisterExtension
  static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  private ExecutorService sharedExecutorService;
  private ScheduledExecutorService resubscribeRetryExecutorService;
  private Scheduler messageDeliveryScheduler;
  private Scheduler persistQueueScheduler;
  private MessagesCache messagesCache;
  private PersistentMessageStore messageStore;
  private MessagePersister messagePersister;
  private AccountsManager accountsManager;
  private MessagesManager messagesManager;
  private DynamicConfiguration dynamicConfiguration;

  private Account destinationAccount;

  private Answer<Integer> persistMessagesAnswer;

  private static final TestClock CLOCK = TestClock.pinned(Instant.now());

  private static final UUID DESTINATION_ACCOUNT_UUID = UUID.randomUUID();
  private static final String DESTINATION_ACCOUNT_NUMBER = "+18005551234";
  private static final byte DESTINATION_DEVICE_ID = 7;
  private static final Device DESTINATION_DEVICE = DevicesHelper.createDevice(DESTINATION_DEVICE_ID);

  private static final Duration PERSIST_DELAY = Duration.ofMinutes(5);

  private static final double EXTRA_ROOM_RATIO = 2.0;

  @BeforeEach
  void setUp() throws Exception {

    messagesManager = mock(MessagesManager.class);
    @SuppressWarnings("unchecked") final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager =
        mock(DynamicConfigurationManager.class);

    messageStore = mock(PersistentMessageStore.class);
    accountsManager = mock(AccountsManager.class);
    destinationAccount = mock(Account.class);

    when(accountsManager.getByAccountIdentifier(DESTINATION_ACCOUNT_UUID)).thenReturn(Optional.of(destinationAccount));
    when(accountsManager.getByAccountIdentifierAsync(DESTINATION_ACCOUNT_UUID))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(destinationAccount)));
    when(accountsManager.removeDevice(any(), anyByte()))
        .thenAnswer(invocation -> accountsManager.getByAccountIdentifier(invocation.getArgument(0)).orElseThrow());

    when(destinationAccount.getAccountIdentifier()).thenReturn(DESTINATION_ACCOUNT_UUID);
    when(destinationAccount.getNumber()).thenReturn(Optional.of(DESTINATION_ACCOUNT_NUMBER));
    when(destinationAccount.getDevice(DESTINATION_DEVICE_ID)).thenReturn(Optional.of(DESTINATION_DEVICE));

    dynamicConfiguration = mock(DynamicConfiguration.class);
    when(dynamicConfiguration.getMessagePersisterConfiguration())
        .thenReturn(new DynamicMessagePersisterConfiguration(true, EXTRA_ROOM_RATIO, Duration.ofHours(1), Duration.ZERO));
    when(dynamicConfigurationManager.getConfiguration()).thenReturn(dynamicConfiguration);

    sharedExecutorService = Executors.newSingleThreadExecutor();
    resubscribeRetryExecutorService = Executors.newSingleThreadScheduledExecutor();
    messageDeliveryScheduler = Schedulers.newBoundedElastic(10, 10_000, "messageDelivery");
    persistQueueScheduler = Schedulers.newBoundedElastic(10, 10_000, "persistQueue");
    messagesCache = spy(new MessagesCache(REDIS_CLUSTER_EXTENSION.getRedisCluster(),
        messageDeliveryScheduler, sharedExecutorService, mock(ScheduledExecutorService.class), CLOCK));
    messagePersister = new MessagePersister(messagesCache,
        messagesManager,
        accountsManager,
        dynamicConfigurationManager,
        persistQueueScheduler,
        CLOCK,
        PERSIST_DELAY,
        1,
        1024,
        Retry.backoff(1, Duration.ZERO));

    when(messagesManager.clear(any(UUID.class), anyByte())).thenReturn(CompletableFuture.completedFuture(null));

    persistMessagesAnswer = invocation -> {
      final UUID destinationUuid = invocation.getArgument(0);
      final Device destinationDevice = invocation.getArgument(1);
      final List<MessageProtos.Envelope> messages = invocation.getArgument(2);

      messageStore.store(messages, destinationUuid, destinationDevice);

      for (final MessageProtos.Envelope message : messages) {
        messagesCache.remove(destinationUuid, destinationDevice.getId(), UUIDUtil.fromByteString(message.getServerGuid())).get();
      }

      return messages.size();
    };

    when(messagesManager.persistMessages(any(UUID.class), any(), any())).thenAnswer(persistMessagesAnswer);
  }

  @AfterEach
  void tearDown() throws Exception {
    sharedExecutorService.shutdown();
    //noinspection ResultOfMethodCallIgnored
    sharedExecutorService.awaitTermination(1, TimeUnit.SECONDS);

    messageDeliveryScheduler.dispose();
    persistQueueScheduler.dispose();

    resubscribeRetryExecutorService.shutdown();
    //noinspection ResultOfMethodCallIgnored
    resubscribeRetryExecutorService.awaitTermination(1, TimeUnit.SECONDS);
  }

  @Test
  void persistQueue() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    messagePersister.persistQueue(destinationAccount, destinationAccount.getDevice(DESTINATION_DEVICE_ID).orElseThrow(), Tags.empty())
        .block();

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce())
        .store(messagesCaptor.capture(), eq(DESTINATION_ACCOUNT_UUID), eq(DESTINATION_DEVICE));

    assertEquals(messageCount, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @Test
  void persistNextNodeNoQueues() {
    assertEquals(0, messagePersister.persistNextNode());

    verify(accountsManager, never()).getByAccountIdentifier(any(UUID.class));
  }

  @Test
  void persistNodeSingleQueue() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    assertEquals(1, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce())
        .store(messagesCaptor.capture(), eq(DESTINATION_ACCOUNT_UUID), eq(DESTINATION_DEVICE));

    assertEquals(messageCount, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @Test
  void persistNodeSingleQueueTooSoon() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount, CLOCK.instant());

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void testPersistNextQueuesMultiplePages() {
    final int queueCount = (MessagePersister.QUEUE_BATCH_LIMIT * 3) + 7;
    final int messagesPerQueue = 10;

    for (int i = 0; i < queueCount; i++) {
      final UUID accountUuid = UUID.randomUUID();
      final byte deviceId = Device.PRIMARY_ID;

      final Account account = mock(Account.class);

      when(accountsManager.getByAccountIdentifierAsync(accountUuid))
          .thenReturn(CompletableFuture.completedFuture(Optional.of(account)));

      when(account.getAccountIdentifier()).thenReturn(accountUuid);
      when(account.getAccountIdentifier()).thenReturn(accountUuid);
      when(account.getDevice(anyByte())).thenAnswer(invocation -> Optional.of(DevicesHelper.createDevice(invocation.getArgument(0))));

      insertMessages(accountUuid, deviceId, messagesPerQueue, CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));
    }

    final Set<RedisClusterNode> persistedNodes = new HashSet<>();
    boolean addedNode;
    int queuesPersisted = 0;

    do {
      final RedisClusterNode node =
          messagesCache.claimNextNodeToPersist(messagePersister.getPersisterId(), Duration.ofHours(1)).orElseThrow();

      queuesPersisted += messagePersister.persistNode(node);

      messagesCache.releaseNodeClaim(node, messagePersister.getPersisterId());
      addedNode = persistedNodes.add(node);
    } while (addedNode);

    assertEquals(queueCount, queuesPersisted);

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce()).store(messagesCaptor.capture(), any(UUID.class), any());
    assertEquals(queueCount * messagesPerQueue, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @Test
  void testPersistNodePersistenceDisabled() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(dynamicConfiguration.getMessagePersisterConfiguration())
        .thenReturn(new DynamicMessagePersisterConfiguration(false, EXTRA_ROOM_RATIO, Duration.ofHours(1), Duration.ZERO));

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void testPersistNodeShouldPersistException() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    doReturn(Mono.error(new RedisException("Badness 10,000")))
        .when(messagesCache).getEarliestUndeliveredTimestamp(any(), anyByte());

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void testPersistNodeShouldPersistExceptionRetry() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    doReturn(Mono.error(new RedisException("Badness 10,000")))
        .doReturn(Mono.fromSupplier(() -> CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)).toEpochMilli()))
        .when(messagesCache).getEarliestUndeliveredTimestamp(any(), anyByte());

    assertEquals(1, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce())
        .store(messagesCaptor.capture(), eq(DESTINATION_ACCOUNT_UUID), eq(DESTINATION_DEVICE));

    assertEquals(messageCount, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @Test
  void persistNodeAccountNotFound() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(accountsManager.getByAccountIdentifierAsync(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void persistNodeFetchAccountException() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(accountsManager.getByAccountIdentifierAsync(any()))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Badness 10,000")));

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void persistNodeFetchAccountExceptionRetry() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(accountsManager.getByAccountIdentifierAsync(DESTINATION_ACCOUNT_UUID))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Badness 10,000")))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(destinationAccount)));

    assertEquals(1, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce())
        .store(messagesCaptor.capture(), eq(DESTINATION_ACCOUNT_UUID), eq(DESTINATION_DEVICE));

    assertEquals(messageCount, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @Test
  void persistNodePersistQueueException() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(messagesManager.persistMessages(any(), any(), any()))
        .thenThrow(new RuntimeException("Badness 10,000"));

    assertEquals(0, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    verify(messageStore, never()).store(any(), any(), any());
  }

  @Test
  void persistNodePersistQueueExceptionRetry() {
    final int messageCount = (MessagePersister.MESSAGE_BATCH_LIMIT * 3) + 7;

    insertMessages(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID, messageCount,
        CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));

    when(messagesManager.persistMessages(any(), any(), any()))
        .thenThrow(new RuntimeException("Badness 10,000"))
        .thenAnswer(persistMessagesAnswer);

    assertEquals(1, messagePersister.persistNode(
        getNodeWithKey(MessagesCache.getMessageQueueKey(DESTINATION_ACCOUNT_UUID, DESTINATION_DEVICE_ID))));

    @SuppressWarnings("unchecked") final ArgumentCaptor<List<MessageProtos.Envelope>> messagesCaptor =
        ArgumentCaptor.forClass(List.class);

    verify(messageStore, atLeastOnce())
        .store(messagesCaptor.capture(), eq(DESTINATION_ACCOUNT_UUID), eq(DESTINATION_DEVICE));

    assertEquals(messageCount, messagesCaptor.getAllValues().stream().mapToInt(List::size).sum());
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(bytes = {1, 7})
  void persistenceFailureRetainsQueueAndDeviceForRetry(final byte deviceId) {
    final Device device = DevicesHelper.createDevice(deviceId);
    when(destinationAccount.getDevice(deviceId)).thenReturn(Optional.of(device));
    insertMessages(DESTINATION_ACCOUNT_UUID, deviceId, 3, CLOCK.instant().minus(PERSIST_DELAY.plusSeconds(1)));
    final IllegalStateException storageFailure = new IllegalStateException("PostgreSQL unavailable");
    doThrow(storageFailure).doNothing().when(messageStore).store(anyList(), eq(DESTINATION_ACCOUNT_UUID), eq(device));

    StepVerifier.create(messagePersister.persistQueue(destinationAccount, device, Tags.empty()))
        .expectErrorMatches(error -> error == storageFailure)
        .verify(Duration.ofSeconds(5));
    assertTrue(messagesCache.hasMessagesAsync(DESTINATION_ACCOUNT_UUID, deviceId).join());
    verify(accountsManager, never()).removeDevice(any(), anyByte());
    verify(messagesManager, never()).delete(any(), any(), any(), anyLong());

    messagePersister.persistQueue(destinationAccount, device, Tags.empty()).block(Duration.ofSeconds(5));
    assertFalse(messagesCache.hasMessagesAsync(DESTINATION_ACCOUNT_UUID, deviceId).join());
    verify(messageStore, times(2)).store(anyList(), eq(DESTINATION_ACCOUNT_UUID), eq(device));
    verify(accountsManager, never()).removeDevice(any(), anyByte());
  }

  private static RedisClusterNode getNodeWithKey(final byte[] key) {
    return REDIS_CLUSTER_EXTENSION.getRedisCluster().withCluster(connection ->
            connection.getPartitions().stream().filter(node -> node.hasSlot(SlotHash.getSlot(key))).findFirst())
        .orElseThrow();
  }

  private void insertMessages(final UUID accountUuid, final byte deviceId, final int messageCount,
      final Instant firstMessageTimestamp) {
    for (int i = 0; i < messageCount; i++) {
      final UUID messageGuid = UUID.randomUUID();
      final MessageProtos.Envelope envelope = generateMessage(
          accountUuid, messageGuid, firstMessageTimestamp.toEpochMilli() + i, 256);
      messagesCache.insert(messageGuid, accountUuid, deviceId, envelope).join();
    }
  }

  private MessageProtos.Envelope generateMessage(UUID accountUuid, UUID messageGuid, long messageTimestamp, int contentSize) {
    return MessageProtos.Envelope.newBuilder()
        .setDestinationServiceId(new AciServiceIdentifier(accountUuid).toCompactByteString())
        .setClientTimestamp(messageTimestamp)
        .setServerTimestamp(messageTimestamp)
        .setContent(ByteString.copyFromUtf8(RandomStringUtils.secure().nextAlphanumeric(contentSize)))
        .setType(MessageProtos.Envelope.Type.CIPHERTEXT)
        .setServerGuid(UUIDUtil.toByteString(messageGuid))
        .build();
  }
}
