// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

/** The caller owns the existing S3 client lifecycle. Selected only for legacy deployments. */
public final class S3AvatarObjectStorage implements AvatarObjectStorage {
  private final S3AsyncClient client;
  private final String bucket;

  public S3AvatarObjectStorage(S3AsyncClient client, String bucket) {
    this.client = Objects.requireNonNull(client);
    this.bucket = Objects.requireNonNull(bucket);
  }

  @Override
  public CompletableFuture<Void> delete(String key) {
    return client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build()).thenApply(_ -> null);
  }

  @Override
  public CompletableFuture<Boolean> refresh(String key) {
    return client.copyObject(CopyObjectRequest.builder()
            .sourceBucket(bucket).sourceKey(key).destinationBucket(bucket).destinationKey(key)
            .metadataDirective(MetadataDirective.REPLACE)
            .metadata(Map.of("t", String.valueOf(Instant.now().getEpochSecond())))
            .build())
        .handle((_, error) -> {
          if (error == null) return true;
          Throwable cause = error;
          while (cause instanceof CompletionException && cause.getCause() != null) cause = cause.getCause();
          if (cause instanceof NoSuchKeyException) return false;
          throw new CompletionException(cause);
        });
  }
}
