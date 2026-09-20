package org.whispersystems.textsecuregcm.redis;

import io.lettuce.core.SetArgs;
import java.util.concurrent.CompletableFuture;

/** Redis operations used by device linking, provisioning, and connection revocation. */
public interface PubSubRedisClient {
  String getName();
  void shutdown();
  CompletableFuture<String> get(String key);
  CompletableFuture<String> set(String key, String value, SetArgs args);
  CompletableFuture<Long> publish(byte[] channel, byte[] value);
  long publishToChannel(byte[] channel, byte[] value);
  FaultTolerantPubSubConnection<String, String> createPubSubConnection();
  FaultTolerantPubSubConnection<byte[], byte[]> createBinaryPubSubConnection();
}
