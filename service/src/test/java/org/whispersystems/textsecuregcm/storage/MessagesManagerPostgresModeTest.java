// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.push.RedisMessageAvailabilityManager;
import org.whispersystems.textsecuregcm.storage.foundationdb.FoundationDbMessageStore;
import org.whispersystems.textsecuregcm.storage.foundationdb.FoundationDbMessageStream;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.UUIDUtil;
import reactor.adapter.JdkFlowAdapter;
import reactor.core.publisher.Flux;

class MessagesManagerPostgresModeTest {
  private PersistentMessageStore persistent;
  private MessagesCache cache;
  private RedisMessageAvailabilityManager availability;
  private ReportMessageManager reports;
  private ExperimentEnrollmentManager experiments;
  private ExecutorService deletionExecutor;
  private MessagesManager manager;
  private final UUID destination = UUID.randomUUID();
  private final Device device = DevicesHelper.createDevice((byte) 1);

  @BeforeEach
  void setUp() {
    persistent = mock(PersistentMessageStore.class);
    cache = mock(MessagesCache.class);
    availability = mock(RedisMessageAvailabilityManager.class);
    reports = mock(ReportMessageManager.class);
    experiments = mock(ExperimentEnrollmentManager.class);
    // Every FoundationDB flag is enabled deliberately; absent backend capability must take priority.
    when(experiments.isEnrolled(any(UUID.class), anyString())).thenReturn(true);
    deletionExecutor = Executors.newSingleThreadExecutor();
    manager = new MessagesManager(persistent, cache, null, availability, reports,
        deletionExecutor, Clock.systemUTC(), experiments);
  }

  @AfterEach
  void tearDown() throws Exception {
    deletionExecutor.shutdown();
    assertThat(deletionExecutor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
  }

  private Envelope envelope() {
    return Envelope.newBuilder().setType(Envelope.Type.CIPHERTEXT)
        .setServerGuid(UUIDUtil.toByteString(UUID.randomUUID()))
        .setDestinationServiceId(new AciServiceIdentifier(destination).toCompactByteString())
        .setServerTimestamp(System.currentTimeMillis())
        .setContent(ByteString.copyFromUtf8("synthetic encrypted envelope bytes")).build();
  }

  @Test
  void insertionUsesRedisAndReturnsPresenceDespiteAllFoundationDbFlags() {
    UUID sender = UUID.randomUUID();
    Envelope message = envelope().toBuilder()
        .setSourceServiceId(new AciServiceIdentifier(sender).toCompactByteString()).build();
    when(cache.insert(any(UUID.class), eq(destination), eq(device.getId()), eq(message)))
        .thenReturn(CompletableFuture.completedFuture(true));
    assertThat(manager.hasFoundationDbStore()).isFalse();
    assertThat(manager.insert(destination, Map.of(device.getId(), message))).containsEntry(device.getId(), true);
    verify(cache).insert(any(UUID.class), eq(destination), eq(device.getId()), eq(message));
    verify(reports).store(eq(sender.toString()), any(UUID.class));
    verifyNoInteractions(experiments, persistent);
  }

  @Test
  void clearUsesRedisWithoutSchedulingFoundationDbWork() {
    when(cache.clear(destination)).thenReturn(CompletableFuture.completedFuture(null));
    when(cache.clear(destination, device.getId())).thenReturn(CompletableFuture.completedFuture(null));
    manager.clear(destination).join();
    manager.clear(destination, device.getId()).join();
    verify(cache).clear(destination);
    verify(cache).clear(destination, device.getId());
    verifyNoInteractions(experiments, persistent);
  }

  @Test
  void liveStreamReadsPersistentThenCachedMessagesAndKeepsRedisAvailabilityListening() {
    Envelope persisted = envelope();
    Envelope cached = envelope();
    when(persistent.load(destination, device, null)).thenReturn(Flux.just(persisted));
    when(cache.get(destination, device.getId())).thenReturn(Flux.just(cached));
    MessageStream stream = manager.getMessages(destination, device);
    assertThat(stream).isExactlyInstanceOf(RedisDynamoDbMessageStream.class);
    List<MessageStreamEntry> entries = JdkFlowAdapter.flowPublisherToFlux(stream.getMessages())
        .take(3).collectList().block(Duration.ofSeconds(5));
    assertThat(entries).containsExactly(new MessageStreamEntry.Envelope(persisted),
        new MessageStreamEntry.Envelope(cached), new MessageStreamEntry.QueueEmpty());
    verify(availability).handleClientConnected(eq(destination), eq(device.getId()), any());
    verify(availability).handleClientDisconnected(eq(destination), eq(device.getId()), any());
    verifyNoInteractions(experiments);
  }

  @Test
  void deletionFallsBackToThePersistentStoreWhenRedisHasNoMessage() {
    Envelope message = envelope();
    UUID guid = UUIDUtil.fromByteString(message.getServerGuid());
    when(cache.remove(destination, device.getId(), guid)).thenReturn(CompletableFuture.completedFuture(Optional.empty()));
    when(persistent.deleteMessage(destination, device, guid, message.getServerTimestamp()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(message)));
    assertThat(manager.delete(destination, device, guid, message.getServerTimestamp()).join())
        .contains(RemovedMessage.fromEnvelope(message));
    verify(persistent).deleteMessage(destination, device, guid, message.getServerTimestamp());
    verifyNoInteractions(experiments);
  }

  @Test
  void deletingACachedMessageDoesNotDeleteAnUnrelatedPersistentMessage() {
    Envelope message = envelope();
    UUID guid = UUIDUtil.fromByteString(message.getServerGuid());
    RemovedMessage removed = RemovedMessage.fromEnvelope(message);
    when(cache.remove(destination, device.getId(), guid)).thenReturn(CompletableFuture.completedFuture(Optional.of(removed)));
    assertThat(manager.delete(destination, device, guid, message.getServerTimestamp()).join()).contains(removed);
    verifyNoInteractions(persistent, experiments);
  }

  @Test
  void persistenceAndPresenceChecksUseTheConfiguredPersistentStore() {
    Envelope message = envelope();
    UUID guid = UUIDUtil.fromByteString(message.getServerGuid());
    when(cache.remove(destination, device.getId(), List.of(guid)))
        .thenReturn(CompletableFuture.completedFuture(List.of(RemovedMessage.fromEnvelope(message))));
    assertThat(manager.persistMessages(destination, device, List.of(message))).isEqualTo(1);
    verify(persistent).store(List.of(message), destination, device);
    when(cache.hasMessagesAsync(destination, device.getId())).thenReturn(CompletableFuture.completedFuture(false));
    when(persistent.mayHaveMessages(destination, device)).thenReturn(CompletableFuture.completedFuture(true));
    when(persistent.mayHaveUrgentMessages(destination, device)).thenReturn(CompletableFuture.completedFuture(true));
    assertThat(manager.mayHaveMessages(destination, device).join()).isTrue();
    assertThat(manager.mayHavePersistedMessages(destination, device).join()).isTrue();
    assertThat(manager.mayHaveUrgentPersistedMessages(destination, device).join()).isTrue();
    verifyNoInteractions(experiments);
  }

  @Test
  void foundationDbMaintenanceFailsExplicitlyIncludingDryRunTrimming() {
    List<Runnable> operations = List.of(manager::recordFoundationDbVersionstamps,
        () -> manager.expireOldFoundationDbVersionstamps(Instant.now()),
        () -> manager.deleteFoundationDbMessagesBefore(Map.of(new AciServiceIdentifier(destination), List.of(device.getId())), Instant.now()),
        () -> manager.trimQueue(new AciServiceIdentifier(destination), device, 100, 50, 20, false),
        () -> manager.trimQueue(new AciServiceIdentifier(destination), device, 100, 50, 20, true));
    for (Runnable operation : operations) {
      UnsupportedOperationException exception = assertThrows(UnsupportedOperationException.class, operation::run);
      assertThat(exception).hasMessageContaining("FoundationDB message storage is not configured");
    }
    verifyNoInteractions(persistent, cache, availability, experiments);
  }

  @Test
  void providingFoundationDbPreservesExperimentDrivenStreamSelection() {
    FoundationDbMessageStore foundationDb = mock(FoundationDbMessageStore.class);
    when(foundationDb.getMessages(any(), eq(device.getId()))).thenReturn(mock(FoundationDbMessageStream.class));
    MessagesManager legacy = new MessagesManager(persistent, cache, foundationDb, availability, reports,
        deletionExecutor, Clock.systemUTC(), experiments);
    assertThat(legacy.hasFoundationDbStore()).isTrue();
    assertThat(legacy.getMessages(destination, device)).isInstanceOf(ConcatenatingMessageStream.class);
    when(experiments.isEnrolled(destination, MessagesManager.READ_LIVE_MESSAGES_FROM_FOUNDATIONDB_EXPERIMENT_NAME))
        .thenReturn(false);
    assertThat(legacy.getMessages(destination, device)).isInstanceOf(MirroringMessageStream.class);
    verify(persistent, never()).load(any(), any(), any());
  }
}
