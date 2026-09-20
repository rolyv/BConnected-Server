/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.redis;

import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;

public class FaultTolerantPubSubConnection<K, V> extends AbstractFaultTolerantPubSubConnection<K, V, StatefulRedisPubSubConnection<K, V>> {

  protected FaultTolerantPubSubConnection(final String name,
      final StatefulRedisPubSubConnection<K, V> pubSubConnection) {

    super(name, pubSubConnection);
  }

  public void addChannelListener(final io.lettuce.core.pubsub.RedisPubSubListener<K, V> listener) {
    usePubSubConnection(connection -> connection.addListener(listener));
  }

  public void removeChannelListener(final io.lettuce.core.pubsub.RedisPubSubListener<K, V> listener) {
    usePubSubConnection(connection -> connection.removeListener(listener));
  }

  public void subscribeChannel(final K channel) {
    usePubSubConnection(connection -> connection.sync().subscribe(channel));
  }

  public void unsubscribeChannel(final K channel) {
    usePubSubConnection(connection -> connection.sync().unsubscribe(channel));
  }

  public void subscribeKeyspace(final io.lettuce.core.pubsub.RedisPubSubListener<K, V> listener, final K[] patterns) {
    usePubSubConnection(connection -> {
      connection.addListener(listener);
      connection.sync().psubscribe(patterns);
    });
  }

  public void unsubscribeKeyspace(final io.lettuce.core.pubsub.RedisPubSubListener<K, V> listener) {
    usePubSubConnection(connection -> {
      connection.sync().punsubscribe();
      connection.removeListener(listener);
    });
  }

  public void close() {
    usePubSubConnection(io.lettuce.core.pubsub.StatefulRedisPubSubConnection::close);
  }
}
