package org.whispersystems.textsecuregcm.redis;

import io.lettuce.core.SetArgs;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/** Cluster routing for keys and shard-local provisioning subscriber counts. */
public final class ClusteredPubSubRedisClient implements PubSubRedisClient {
  private final FaultTolerantRedisClusterClient cluster;
  private final List<ClusteredPubSubConnection<?, ?>> subscriptions = new ArrayList<>();

  public ClusteredPubSubRedisClient(final FaultTolerantRedisClusterClient cluster) {
    this.cluster = cluster;
  }

  @Override public String getName() { return cluster.getName(); }
  @Override public void shutdown() {
    subscriptions.forEach(ClusteredPubSubConnection::close);
    cluster.shutdown();
  }
  @Override public CompletableFuture<String> get(final String key) {
    return cluster.withCluster(connection -> connection.async().get(key).toCompletableFuture());
  }
  @Override public CompletableFuture<String> set(final String key, final String value, final SetArgs args) {
    return cluster.withCluster(connection -> connection.async().set(key, value, args).toCompletableFuture());
  }
  @Override public CompletableFuture<Long> publish(final byte[] channel, final byte[] value) {
    return cluster.withBinaryCluster(connection -> connection.async().publish(channel, value).toCompletableFuture());
  }
  @Override public long publishToChannel(final byte[] channel, final byte[] value) {
    // SPUBLISH and SSUBSCRIBE use the same slot owner. PUBLISH counts only local subscribers,
    // even though ordinary messages are broadcast throughout a Redis cluster.
    return cluster.withBinaryCluster(connection -> connection.sync().spublish(channel, value));
  }
  @Override public FaultTolerantPubSubConnection<String, String> createPubSubConnection() {
    final ClusteredPubSubConnection<String, String> connection = cluster.createPubSubConnection()
        .withPubSubConnection(c -> new ClusteredPubSubConnection<>(getName(), c));
    subscriptions.add(connection);
    return connection;
  }
  @Override public FaultTolerantPubSubConnection<byte[], byte[]> createBinaryPubSubConnection() {
    final ClusteredPubSubConnection<byte[], byte[]> connection = cluster.createBinaryPubSubConnection()
        .withPubSubConnection(c -> new ClusteredPubSubConnection<>(getName(), c));
    subscriptions.add(connection);
    return connection;
  }
}
