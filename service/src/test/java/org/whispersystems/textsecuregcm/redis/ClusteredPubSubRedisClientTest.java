package org.whispersystems.textsecuregcm.redis;

import static org.junit.jupiter.api.Assertions.*;

import io.lettuce.core.SetArgs;
import io.lettuce.core.cluster.SlotHash;
import io.lettuce.core.cluster.models.partitions.RedisClusterNode;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.resource.ClientResources;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.configuration.ClusteredPubSubRedisConfiguration;
import org.whispersystems.textsecuregcm.configuration.FaultTolerantRedisClientFactory;
import org.whispersystems.textsecuregcm.configuration.RedisConfiguration;
import org.whispersystems.textsecuregcm.push.ProvisioningManager;
import org.whispersystems.textsecuregcm.storage.PubSubProtos;
import org.whispersystems.textsecuregcm.util.SystemMapper;

@Timeout(15)
class ClusteredPubSubRedisClientTest {
  @RegisterExtension
  static final RedisClusterExtension REDIS = RedisClusterExtension.builder().build();

  private ClientResources resources;
  private FaultTolerantRedisClusterClient cluster;
  private ClusteredPubSubRedisClient client;

  @BeforeEach
  void setUp() {
    resources = ClientResources.builder().socketAddressResolver(REDIS.getSocketAddressResolver()).build();
    cluster = new FaultTolerantRedisClusterClient("pubsub-test", resources.mutate(),
        RedisClusterExtension.getRedisURIs(), Duration.ofSeconds(2), null);
    client = new ClusteredPubSubRedisClient(cluster);
  }

  @AfterEach
  void tearDown() throws Exception {
    client.shutdown();
    resources.shutdown().await();
  }

  private List<RedisClusterNode> primaries() {
    return cluster.withCluster(c -> c.getPartitions().stream()
        .filter(n -> n.is(RedisClusterNode.NodeFlag.UPSTREAM)).toList());
  }

  private String keyOn(final RedisClusterNode node) {
    String key;
    do { key = "test:" + UUID.randomUUID(); } while (!node.hasSlot(SlotHash.getSlot(key)));
    return key;
  }

  @Test
  void routesKeysAcrossEveryPrimaryAndPreservesTtl() throws Exception {
    assertTrue(primaries().size() >= 3);
    for (final RedisClusterNode node : primaries()) {
      final String key = keyOn(node);
      assertEquals("OK", client.set(key, "payload", SetArgs.Builder.ex(30)).get(2, TimeUnit.SECONDS));
      assertEquals("payload", client.get(key).get(2, TimeUnit.SECONDS));
      assertTrue(cluster.withCluster(c -> c.sync().ttl(key)) > 0);
    }
  }

  @Test
  void observesAndRepairsKeyspaceSubscriptionsOnEveryPrimary() throws Exception {
    for (final RedisClusterNode node : primaries()) {
      cluster.useCluster(c -> c.getConnection(node.getNodeId()).sync().configSet("notify-keyspace-events", "K$"));
    }
    final ClusteredPubSubConnection<String, String> subscription =
        (ClusteredPubSubConnection<String, String>) client.createPubSubConnection();
    final BlockingQueue<String> events = new LinkedBlockingQueue<>();
    final RedisPubSubAdapter<String, String> listener = new RedisPubSubAdapter<>() {
      @Override public void message(final String pattern, final String channel, final String message) {
        if ("set".equals(message)) events.add(channel);
      }
    };
    subscription.subscribeKeyspace(listener, new String[] {"__keyspace@0__:test:*"});
    for (final RedisClusterNode node : primaries()) {
      final String key = keyOn(node);
      client.set(key, "payload", SetArgs.Builder.ex(30)).get();
      assertEquals("__keyspace@0__:" + key, events.poll(2, TimeUnit.SECONDS));
    }
    // Emulate losing node-local subscriptions across a reconnect/topology transition.
    subscription.usePubSubConnection(c -> ((io.lettuce.core.cluster.pubsub.StatefulRedisClusterPubSubConnection<String, String>) c)
        .sync().all().commands().punsubscribe());
    subscription.repairSubscriptions();
    final String repairedKey = keyOn(primaries().getLast());
    client.set(repairedKey, "payload", SetArgs.Builder.ex(30)).get();
    assertEquals("__keyspace@0__:" + repairedKey, events.poll(2, TimeUnit.SECONDS));
    subscription.unsubscribeKeyspace(listener);
    subscription.repairSubscriptions();
    client.set(repairedKey, "updated", SetArgs.Builder.ex(30)).get();
    assertNull(events.poll(100, TimeUnit.MILLISECONDS));
  }

  @Test
  void provisioningReportsListenersAndDeliversOnEveryShard() throws Exception {
    final ProvisioningManager manager = new ProvisioningManager(client);
    manager.start();
    try {
      for (final RedisClusterNode node : primaries()) {
        final String address = keyOn(node);
        final BlockingQueue<PubSubProtos.PubSubMessage> received = new LinkedBlockingQueue<>();
        manager.addListener(address, received::add);
        assertTrue(manager.sendProvisioningMessage(address, new byte[] {1, 2, 3}));
        assertArrayEquals(new byte[] {1, 2, 3}, received.poll(2, TimeUnit.SECONDS).getContent().toByteArray());
        manager.removeListener(address);
        assertFalse(manager.sendProvisioningMessage(address, new byte[] {4}));
        assertNull(received.poll(100, TimeUnit.MILLISECONDS));
      }
    } finally { manager.stop(); }
  }

  @Test
  void shardUnsubscribeWithEqualBytesSurvivesRepair() throws Exception {
    final ClusteredPubSubConnection<byte[], byte[]> subscription =
        (ClusteredPubSubConnection<byte[], byte[]>) client.createBinaryPubSubConnection();
    final String address = keyOn(primaries().getLast());
    final byte[] channel = address.getBytes(StandardCharsets.UTF_8);
    subscription.subscribeChannel(channel);
    assertEquals(1, client.publishToChannel(channel, new byte[] {1}));
    subscription.unsubscribeChannel(address.getBytes(StandardCharsets.UTF_8));
    subscription.repairSubscriptions();
    assertEquals(0, client.publishToChannel(channel, new byte[] {1}));
    subscription.close();
    assertThrows(IllegalStateException.class, () -> subscription.subscribeChannel(channel));
  }

  @Test
  void ordinaryBroadcastReachesClusterConnection() throws Exception {
    final FaultTolerantPubSubConnection<byte[], byte[]> subscription = client.createBinaryPubSubConnection();
    final BlockingQueue<byte[]> received = new LinkedBlockingQueue<>();
    final byte[] channel = "disconnects".getBytes(StandardCharsets.UTF_8);
    subscription.usePubSubConnection(c -> {
      c.addListener(new RedisPubSubAdapter<>() {
        @Override public void message(final byte[] ignored, final byte[] message) { received.add(message); }
      });
      c.sync().subscribe(channel);
    });
    client.publish(channel, new byte[] {7}).get(2, TimeUnit.SECONDS);
    assertArrayEquals(new byte[] {7}, received.poll(2, TimeUnit.SECONDS));
  }

  @Test
  void factoryDiscoveryRetainsLegacyAndSupportsManagedClusterConfiguration() throws Exception {
    assertInstanceOf(RedisConfiguration.class, SystemMapper.jsonMapper().readValue(
        "{\"uri\":\"redis://localhost:6379\"}", FaultTolerantRedisClientFactory.class));
    assertInstanceOf(ClusteredPubSubRedisConfiguration.class, SystemMapper.jsonMapper().readValue("""
        {"type":"cluster","cluster":{"configurationUri":"rediss://10.1.2.3:6379",
          "gcpIam":{"caCertificateFile":"/owned/redis-ca.pem"}}}
        """, FaultTolerantRedisClientFactory.class));
  }
}
