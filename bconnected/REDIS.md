# Managed Redis Cluster

For the GCP pilot, use the managed cluster's stable discovery endpoint for all Redis configurations, including the `pubsub` service. Do not pin Pub/Sub to a current node IP. Google requires a cluster-aware client and documents discovery, redirection, and topology refresh behavior in its [Redis Cluster client guidance](https://docs.cloud.google.com/memorystore/docs/cluster/general-best-practices).

The Pub/Sub factory has an explicit cluster configuration:

```yaml
pubsub:
  type: cluster
  cluster:
    configurationUri: rediss://DISCOVERY_ADDRESS:6379
    timeout: PT5S
    gcpIam:
      caCertificateFile: /etc/bconnected/redis-ca.pem
```

`gcpIam` uses application default credentials with refreshed IAM access tokens and the mounted cluster CA. The existing default standalone `pubsub.uri` configuration remains available for legacy deployments. Cluster clients use adaptive refresh plus a 30-second periodic topology refresh.

The managed instance must enable `notify-keyspace-events` containing `K$`. Account/device-link operations store short-lived records using slot-routed GET/SET. Their SET notifications use keyspace pattern subscriptions on every primary. These subscriptions are repaired after topology changes and periodically after transient failures. [Redis documents that keyspace events stay node-local](https://redis.io/docs/latest/develop/pubsub/keyspace-notifications/); [Lettuce requires explicit resubscription on new nodes](https://redis.github.io/lettuce/user-guide/pubsub/).

Provisioning uses Redis 7 sharded SSUBSCRIBE/SPUBLISH in cluster mode, so its subscriber-presence result is counted on the same slot owner that holds the subscription. Connection-revocation broadcasts retain ordinary cluster-wide SUBSCRIBE/PUBLISH. Pub/Sub remains transient: records have TTLs and existing read-after-subscribe checks, but a Redis interruption can still require a client retry.

The local integration suite exercises three real Redis primaries. It does not establish a successful connection to the managed GCP instance or prove failover delivery. Live private startup and managed TLS/IAM connectivity are separate deployment checks.
