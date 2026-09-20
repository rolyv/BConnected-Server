package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.lettuce.core.resource.ClientResources;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.whispersystems.textsecuregcm.redis.ClusteredPubSubRedisClient;

@JsonTypeName("cluster")
public final class ClusteredPubSubRedisConfiguration implements FaultTolerantRedisClientFactory {
  @JsonProperty @Valid @NotNull
  private RedisClusterConfiguration cluster;

  @Override
  public ClusteredPubSubRedisClient build(final String name, final ClientResources resources) {
    return new ClusteredPubSubRedisClient(cluster.build(name, resources.mutate()));
  }
}
