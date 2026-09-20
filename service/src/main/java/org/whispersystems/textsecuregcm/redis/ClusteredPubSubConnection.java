package org.whispersystems.textsecuregcm.redis;

import io.lettuce.core.cluster.event.ClusterTopologyChangedEvent;
import io.lettuce.core.cluster.models.partitions.RedisClusterNode;
import io.lettuce.core.cluster.pubsub.RedisClusterPubSubAdapter;
import io.lettuce.core.cluster.pubsub.StatefulRedisClusterPubSubConnection;
import io.lettuce.core.pubsub.RedisPubSubListener;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Disposable;

/** Subscription routing and repair for a single managed Redis cluster connection. */
final class ClusteredPubSubConnection<K, V> extends FaultTolerantPubSubConnection<K, V> {
  private static final Logger logger = LoggerFactory.getLogger(ClusteredPubSubConnection.class);
  private final StatefulRedisClusterPubSubConnection<K, V> connection;
  private final ScheduledExecutorService repairs;
  private final Disposable topologySubscription;
  private final Map<Object, K> channels = new HashMap<>();
  private final Map<RedisPubSubListener<K, V>, RedisClusterPubSubAdapter<K, V>> channelListeners = new java.util.IdentityHashMap<>();
  private K[] patterns;
  private RedisClusterPubSubAdapter<K, V> keyspaceListener;
  private boolean closed;

  ClusteredPubSubConnection(final String name, final StatefulRedisClusterPubSubConnection<K, V> connection) {
    super(name, connection);
    this.connection = connection;
    this.connection.setNodeMessagePropagation(true);
    repairs = Executors.newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon()
        .name(name + "-pubsub-repair").factory());
    topologySubscription = connection.getResources().eventBus().get()
        .filter(event -> event instanceof ClusterTopologyChangedEvent changed &&
            connection.getPartitions().stream().anyMatch(node -> changed.before().contains(node) || changed.after().contains(node)))
        // Never make a synchronous Redis call from a Lettuce/Netty event callback.
        .subscribe(_ -> {
          if (!repairs.isShutdown()) {
            try {
              repairs.execute(this::repairSubscriptions);
            } catch (final java.util.concurrent.RejectedExecutionException ignored) {
              // Shutdown raced with delivery of the final topology event.
            }
          }
        });
    // Also retry transient subscription failures and recover events missed during topology transitions.
    repairs.scheduleWithFixedDelay(this::repairSubscriptions, 5, 5, TimeUnit.SECONDS);
  }

  @Override
  public synchronized void addChannelListener(final RedisPubSubListener<K, V> listener) {
    ensureOpen();
    if (channelListeners.containsKey(listener)) return;
    final RedisClusterPubSubAdapter<K, V> adapter = new RedisClusterPubSubAdapter<>() {
      @Override public void smessage(final RedisClusterNode node, final K channel, final V message) {
        listener.message(channel, message);
      }
      @Override public void sunsubscribed(final RedisClusterNode node, final K channel, final long count) {
        listener.unsubscribed(channel, count);
      }
    };
    channelListeners.put(listener, adapter);
    connection.addListener(adapter);
  }

  @Override
  public synchronized void removeChannelListener(final RedisPubSubListener<K, V> listener) {
    final RedisClusterPubSubAdapter<K, V> adapter = channelListeners.remove(listener);
    if (adapter != null) connection.removeListener(adapter);
  }

  @Override
  public synchronized void subscribeChannel(final K channel) {
    ensureOpen();
    connection.sync().ssubscribe(channel);
    channels.put(channelKey(channel), channel);
  }

  @Override
  public synchronized void unsubscribeChannel(final K channel) {
    ensureOpen();
    // Retain the desired subscription if Redis rejects the unsubscribe.
    connection.sync().sunsubscribe(channel);
    channels.remove(channelKey(channel));
  }

  @Override
  public synchronized void subscribeKeyspace(final RedisPubSubListener<K, V> listener, final K[] patterns) {
    ensureOpen();
    if (keyspaceListener == null) {
      keyspaceListener = new RedisClusterPubSubAdapter<>() {
        @Override
        public void message(final RedisClusterNode node, final K pattern, final K channel, final V message) {
          listener.message(pattern, channel, message);
        }
      };
      connection.addListener(keyspaceListener);
    }
    this.patterns = patterns.clone();
    // Keyspace events are node-local. Replicas would duplicate events from their primary.
    connection.sync().upstream().commands().psubscribe(patterns);
  }

  @Override
  public synchronized void unsubscribeKeyspace(final RedisPubSubListener<K, V> listener) {
    // Stop repairs first even if a disconnected node prevents the unsubscribe command.
    patterns = null;
    if (keyspaceListener != null) {
      connection.removeListener(keyspaceListener);
      keyspaceListener = null;
    }
    if (!closed) connection.sync().all().commands().punsubscribe();
  }

  synchronized void repairSubscriptions() {
    if (closed) return;
    try {
      if (patterns != null) {
        connection.sync().upstream().commands().psubscribe(patterns);
        // A primary may have become a replica. Remove its former keyspace subscriptions.
        connection.sync().replicas().commands().punsubscribe();
      }
      for (final K channel : channels.values()) connection.sync().ssubscribe(channel);
    } catch (final RuntimeException e) {
      // Do not log channels, keys, or subscription contents.
      logger.warn("Redis Pub/Sub subscription repair failed for {} ({})", getName(), e.getClass().getSimpleName());
    }
  }

  @Override
  public void close() {
    synchronized (this) {
      if (closed) return;
      closed = true;
      channels.clear();
      patterns = null;
    }
    topologySubscription.dispose();
    repairs.shutdownNow();
    connection.close();
  }

  private void ensureOpen() {
    if (closed) throw new IllegalStateException("Pub/Sub connection is closed");
  }

  private static Object channelKey(final Object channel) {
    return channel instanceof byte[] bytes ? ByteBuffer.wrap(bytes) : channel;
  }
}
