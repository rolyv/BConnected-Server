/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import java.sql.SQLException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.reactivestreams.Publisher;
import org.whispersystems.textsecuregcm.entities.MessageProtos;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

class MessagesPostgresTest {


  private static final Random random = new Random();
  private static final MessageProtos.Envelope MESSAGE1;
  private static final MessageProtos.Envelope MESSAGE2;
  private static final MessageProtos.Envelope MESSAGE3;

  static {
    final long serverTimestamp = System.currentTimeMillis();
    MessageProtos.Envelope.Builder builder = MessageProtos.Envelope.newBuilder();
    builder.setType(MessageProtos.Envelope.Type.UNIDENTIFIED_SENDER);
    builder.setClientTimestamp(123456789L);
    builder.setContent(ByteString.copyFrom(new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}));
    builder.setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()));
    builder.setServerTimestamp(serverTimestamp);
    builder.setDestinationServiceId(UUIDUtil.toByteString(UUID.randomUUID()));

    MESSAGE1 = builder.build();

    builder.setType(MessageProtos.Envelope.Type.CIPHERTEXT);
    builder.setSourceServiceId(UUIDUtil.toByteString(UUID.randomUUID()));
    builder.setSourceDevice(1);
    builder.setContent(ByteString.copyFromUtf8("MOO"));
    builder.setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()));
    builder.setServerTimestamp(serverTimestamp + 1);
    builder.setDestinationServiceId(UUIDUtil.toByteString(UUID.randomUUID()));

    MESSAGE2 = builder.build();

    builder.setType(MessageProtos.Envelope.Type.UNIDENTIFIED_SENDER);
    builder.clearSourceDevice();
    builder.clearSourceDevice();
    builder.setContent(ByteString.copyFromUtf8("COW"));
    builder.setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()));
    builder.setServerTimestamp(serverTimestamp);  // Test same millisecond arrival for two different messages
    builder.setDestinationServiceId(UUIDUtil.toByteString(UUID.randomUUID()));

    MESSAGE3 = builder.build();
  }

  private ExecutorService messageDeletionExecutorService;
  private PersistentMessageStore messageStore;

  @RegisterExtension
  static final PostgresMessageStoreExtension POSTGRES = new PostgresMessageStoreExtension();

  @BeforeEach
  void setup() {
    messageDeletionExecutorService = Executors.newSingleThreadExecutor();
    messageStore = POSTGRES.store(Duration.ofDays(14), messageDeletionExecutorService);
  }

  @AfterEach
  void teardown() throws Exception {
    messageDeletionExecutorService.shutdown();
    messageDeletionExecutorService.awaitTermination(5, TimeUnit.SECONDS);

    StepVerifier.resetDefaultTimeout();
  }

  @Test
  void testSimpleFetchAfterInsert() {
    final UUID destinationUuid = UUID.randomUUID();
    final byte destinationDeviceId = (byte) (random.nextInt(Device.MAXIMUM_DEVICE_ID) + 1);
    final Device destinationDevice = DevicesHelper.createDevice(destinationDeviceId);

    messageStore.store(List.of(MESSAGE1, MESSAGE2, MESSAGE3), destinationUuid, destinationDevice);

    final List<MessageProtos.Envelope> messagesStored = load(destinationUuid, destinationDevice,
        100);
    assertThat(messagesStored).isNotNull().hasSize(3);

    // Danger: `UUID#compareTo` does NOT do what you might expect because it uses
    // `Long.compare(a.mostSignificantBits(), b.mostSignificantBits())`, which means that a UUID whose binary
    // representation is lexicographically "greater than" another UUID might wind up "less than" the other UUID if its
    // most significant bit is `1`, which would cause `UUID#compareTo` to treat it as a negative number. To avoid that
    // surprise (and match PostgreSQL's unsigned UUID byte ordering), we just do string ordering.
    final MessageProtos.Envelope firstMessage =
        UUIDUtil.fromByteString(MESSAGE1.getServerGuid()).toString().compareTo(UUIDUtil.fromByteString(MESSAGE3.getServerGuid()).toString()) < 0 ? MESSAGE1 : MESSAGE3;
    final MessageProtos.Envelope secondMessage = firstMessage == MESSAGE1 ? MESSAGE3 : MESSAGE1;
    assertThat(messagesStored).element(0).isEqualTo(firstMessage);
    assertThat(messagesStored).element(1).isEqualTo(secondMessage);
    assertThat(messagesStored).element(2).isEqualTo(MESSAGE2);
  }

  @ParameterizedTest
  @ValueSource(ints = {10, 100, 100, 1_000, 3_000})
  void testLoadManyAfterInsert(final int messageCount) {
    final UUID destinationUuid = UUID.randomUUID();
    final byte destinationDeviceId = (byte) (random.nextInt(Device.MAXIMUM_DEVICE_ID) + 1);
    final Device destinationDevice = DevicesHelper.createDevice(destinationDeviceId);

    final List<MessageProtos.Envelope> messages = new ArrayList<>(messageCount);
    for (int i = 0; i < messageCount; i++) {
      messages.add(createMessage(UUID.randomUUID(), Device.PRIMARY_ID, destinationUuid, System.currentTimeMillis() + i, "message " + i));
    }

    messageStore.store(messages, destinationUuid, destinationDevice);

    final Publisher<?> fetchedMessages = messageStore.load(destinationUuid, destinationDevice, null);

    final long firstRequest = Math.min(10, messageCount);
    StepVerifier.setDefaultTimeout(Duration.ofSeconds(15));

    StepVerifier.Step<?> step = StepVerifier.create(fetchedMessages, 0)
        .expectSubscription()
        .thenRequest(firstRequest)
        .expectNextCount(firstRequest);

    if (messageCount > firstRequest) {
      step = step.thenRequest(messageCount)
          .expectNextCount(messageCount - firstRequest);
    }

    step.thenCancel()
        .verify();
  }

  @Test
  void laterPageFailureIsPropagatedAfterTheFirstPage() throws Exception {
    final int messageCount = 200;
    final UUID destinationUuid = UUID.randomUUID();
    final byte destinationDeviceId = (byte) (random.nextInt(Device.MAXIMUM_DEVICE_ID) + 1);
    final Device destinationDevice = DevicesHelper.createDevice(destinationDeviceId);

    final List<MessageProtos.Envelope> messages = new ArrayList<>(messageCount);
    for (int i = 0; i < messageCount; i++) {
      messages.add(createMessage(UUID.randomUUID(), Device.PRIMARY_ID, destinationUuid, System.currentTimeMillis() + i, "message " + i));
    }

    messageStore.store(messages, destinationUuid, destinationDevice);

    final AtomicInteger reads = new AtomicInteger();
    final DataSource failing = mock(DataSource.class);
    when(failing.getConnection()).thenAnswer(_ -> {
      if (reads.incrementAndGet() > 1) throw new SQLException("Injected later-page failure");
      return POSTGRES.dataSource().getConnection();
    });
    final PersistentMessageStore readStore = new MessagesPostgres(failing, Duration.ofDays(14), messageDeletionExecutorService);
    StepVerifier.create(readStore.load(destinationUuid, destinationDevice, 100), 0)
        .thenRequest(100)
        .expectNextCount(100)
        .thenRequest(1)
        .expectErrorMatches(error -> error instanceof IllegalStateException && error.getCause() instanceof SQLException)
        .verify(Duration.ofSeconds(5));
    assertThat(reads).hasValue(2);
  }

  @Test
  void testDeleteSingleMessage() throws Exception {
    final UUID destinationUuid = UUID.randomUUID();
    final UUID secondDestinationUuid = UUID.randomUUID();
    final Device primary = DevicesHelper.createDevice((byte) 1);
    final Device device2 = DevicesHelper.createDevice((byte) 2);

    messageStore.store(List.of(MESSAGE1), destinationUuid, primary);
    messageStore.store(List.of(MESSAGE2), secondDestinationUuid, primary);
    messageStore.store(List.of(MESSAGE3), destinationUuid, device2);

    assertThat(load(destinationUuid, primary, 100)).isNotNull().hasSize(1)
        .element(0).isEqualTo(MESSAGE1);
    assertThat(load(destinationUuid, device2, 100)).isNotNull()
        .hasSize(1)
        .element(0).isEqualTo(MESSAGE3);
    assertThat(load(secondDestinationUuid, primary, 100)).isNotNull()
        .hasSize(1).element(0).isEqualTo(MESSAGE2);

    messageStore.deleteMessage(secondDestinationUuid, primary,
        UUIDUtil.fromByteString(MESSAGE2.getServerGuid()), MESSAGE2.getServerTimestamp()).get(1, TimeUnit.SECONDS);

    assertThat(load(destinationUuid, primary, 100)).isNotNull().hasSize(1)
        .element(0).isEqualTo(MESSAGE1);
    assertThat(load(destinationUuid, device2, 100)).isNotNull()
        .hasSize(1)
        .element(0).isEqualTo(MESSAGE3);
    assertThat(load(secondDestinationUuid, primary, 100)).isNotNull()
        .isEmpty();
  }

  private List<MessageProtos.Envelope> load(final UUID destinationUuid, final Device destinationDevice,
      final int count) {
    return Flux.from(messageStore.load(destinationUuid, destinationDevice, count))
        .take(count, true)
        .collectList()
        .block();
  }

  @Test
  void testLazyMessageDeletion() throws Exception {
    final UUID destinationUuid = UUID.randomUUID();
    final Device primary = DevicesHelper.createDevice((byte) 1);
    primary.setCreated(System.currentTimeMillis());

    messageStore.store(List.of(MESSAGE1, MESSAGE2), destinationUuid, primary);
    assertThat(load(destinationUuid, primary, 100))
        .as("load should return all messages stored").containsOnly(MESSAGE1, MESSAGE2);

    messageStore.deleteMessage(destinationUuid, primary, UUIDUtil.fromByteString(MESSAGE1.getServerGuid()), MESSAGE1.getServerTimestamp())
        .get(1, TimeUnit.SECONDS);
    assertThat(load(destinationUuid, primary, 100))
        .as("deleting message by guid and timestamp should work").containsExactly(MESSAGE2);

    primary.setCreated(primary.getCreated() + 1000);
    assertThat(load(destinationUuid, primary, 100))
        .as("devices with the same id but different create timestamps should see no messages")
        .isEmpty();
  }

  @Test
  void mayHaveMessages() {
    final UUID destinationUuid = UUID.randomUUID();
    final byte destinationDeviceId = (byte) (random.nextInt(Device.MAXIMUM_DEVICE_ID) + 1);
    final Device destinationDevice = DevicesHelper.createDevice(destinationDeviceId);

    assertThat(messageStore.mayHaveMessages(destinationUuid, destinationDevice).join()).isFalse();

    messageStore.store(List.of(MESSAGE1, MESSAGE2, MESSAGE3), destinationUuid, destinationDevice);

    assertThat(messageStore.mayHaveMessages(destinationUuid, destinationDevice).join()).isTrue();
  }

  @Test
  void mayHaveUrgentMessages() {
    final UUID destinationUuid = UUID.randomUUID();
    final byte destinationDeviceId = (byte) (random.nextInt(Device.MAXIMUM_DEVICE_ID) + 1);
    final Device destinationDevice = DevicesHelper.createDevice(destinationDeviceId);

    assertThat(messageStore.mayHaveUrgentMessages(destinationUuid, destinationDevice).join()).isFalse();

    // used as the stable sort key, and the urgent message should be sorted last
    long serverTimestamp = System.currentTimeMillis();
    {
      final MessageProtos.Envelope nonUrgentMessage = MessageProtos.Envelope.newBuilder()
          .setUrgent(false)
          .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()))
          .setDestinationServiceId(new AciServiceIdentifier(destinationUuid).toCompactByteString())
          .setServerTimestamp(serverTimestamp++)
          .build();

      messageStore.store(List.of(nonUrgentMessage), destinationUuid, destinationDevice);
    }

    assertThat(messageStore.mayHaveUrgentMessages(destinationUuid, destinationDevice).join()).isFalse();

    {
      final List<MessageProtos.Envelope> messages = new ArrayList<>();
      // store more non-urgent messages
      for (int i = 0; i < 500; i++) {
        messages.add(MessageProtos.Envelope.newBuilder()
            .setUrgent(false)
            .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()))
            .setDestinationServiceId(new AciServiceIdentifier(destinationUuid).toCompactByteString())
            .setServerTimestamp(serverTimestamp++)
            .build());
      }

      // and one urgent message
      messages.add(MessageProtos.Envelope.newBuilder()
          .setUrgent(true)
          .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()))
          .setDestinationServiceId(new AciServiceIdentifier(destinationUuid).toCompactByteString())
          .setServerTimestamp(serverTimestamp++)
          .build());

      messageStore.store(messages, destinationUuid, destinationDevice);
    }

    assertThat(messageStore.mayHaveUrgentMessages(destinationUuid, destinationDevice).join()).isTrue();
  }

  private static MessageProtos.Envelope createMessage(final UUID senderUuid,
      final byte senderDeviceId,
      final UUID destinationUuid,
      long timestamp,
      final String content) {

    return MessageProtos.Envelope.newBuilder()
        .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()))
        .setType(MessageProtos.Envelope.Type.CIPHERTEXT)
        .setClientTimestamp(timestamp)
        .setServerTimestamp(timestamp)
        .setSourceServiceId(new AciServiceIdentifier(senderUuid).toCompactByteString())
        .setSourceDevice(senderDeviceId)
        .setDestinationServiceId(new AciServiceIdentifier(destinationUuid).toCompactByteString())
        .setContent(ByteString.copyFrom(content.getBytes(StandardCharsets.UTF_8)))
        .build();
  }
}
