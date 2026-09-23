// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.ServiceAccountSigner;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.whispersystems.textsecuregcm.util.ProfileHelper;

/** Native GCS objects and IAM-backed V4 RSA upload policies; no AWS credentials or compatibility client. */
public final class GcsAvatarStorage implements AvatarObjectStorage, AvatarUploadPolicyGenerator, AutoCloseable {
  public static final String ALGORITHM = "GOOG4-RSA-SHA256";
  private static final ObjectMapper POLICY_MAPPER = new ObjectMapper();
  private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyyMMdd", Locale.ROOT)
      .withZone(ZoneOffset.UTC);
  private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT)
      .withZone(ZoneOffset.UTC);
  private final Storage storage;
  private final String bucket;
  private final ServiceAccountSigner signer;
  private final Executor executor;
  private final Clock clock;

  public GcsAvatarStorage(Storage storage, String bucket, ServiceAccountSigner signer, Executor executor, Clock clock) {
    this.storage = Objects.requireNonNull(storage);
    this.bucket = Objects.requireNonNull(bucket);
    this.signer = Objects.requireNonNull(signer);
    this.executor = Objects.requireNonNull(executor);
    this.clock = Objects.requireNonNull(clock);
  }

  @Override
  public UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime) {
    return createFor(objectName, maxSizeInBytes, currentTime, () -> {});
  }

  @Override
  public UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime, Runnable requireCurrent) {
    requireCurrent.run();
    requireAvatarKey(objectName);
    if (maxSizeInBytes < 1 || maxSizeInBytes > ProfileHelper.MAX_PROFILE_AVATAR_SIZE_BYTES) {
      throw new IllegalArgumentException("Avatar upload length is outside the supported range");
    }
    String timestamp = TIMESTAMP.format(currentTime);
    String credential = signer.getAccount() + "/" + DATE.format(currentTime) + "/auto/storage/goog4_request";
    // ACL is intentionally absent: uniform bucket-level IAM controls all objects. Do not grant public access.
    Map<String, Object> document = Map.of(
        "expiration", DateTimeFormatter.ISO_INSTANT.format(currentTime.plusSeconds(30 * 60)),
        "conditions", List.of(Map.of("bucket", bucket), Map.of("key", objectName),
            List.of("starts-with", "$Content-Type", ""), List.of("content-length-range", 1, maxSizeInBytes),
            Map.of("x-goog-credential", credential), Map.of("x-goog-algorithm", ALGORITHM),
            Map.of("x-goog-date", timestamp)));
    final String encoded;
    try {
      encoded = Base64.getEncoder().encodeToString(POLICY_MAPPER.writeValueAsBytes(document));
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Could not serialize avatar upload policy", e);
    }
    // V4 POST signatures sign the base64 policy bytes, not the decoded JSON or a signed-URL string-to-sign.
    requireCurrent.run();
    String signature = HexFormat.of().formatHex(signer.sign(encoded.getBytes(StandardCharsets.UTF_8)));
    requireCurrent.run();
    return new UploadPolicy(credential, "", ALGORITHM, timestamp, encoded, signature);
  }

  @Override
  public CompletableFuture<Void> delete(String key) {
    requireAvatarKey(key);
    return CompletableFuture.runAsync(() -> storage.delete(BlobId.of(bucket, key)), executor);
  }

  @Override
  public CompletableFuture<Void> delete(String key, Runnable requireCurrent) {
    requireAvatarKey(key);
    requireCurrent.run();
    return CompletableFuture.runAsync(() -> {
      requireCurrent.run();
      storage.delete(BlobId.of(bucket, key));
      requireCurrent.run();
    }, executor);
  }

  @Override
  public CompletableFuture<Boolean> refresh(String key) {
    requireAvatarKey(key);
    return CompletableFuture.supplyAsync(() -> {
      try {
        var current = storage.get(BlobId.of(bucket, key));
        if (current == null) return false;
        Map<String, String> metadata = new HashMap<>(current.getMetadata() == null ? Map.of() : current.getMetadata());
        metadata.put("t", Long.toString(clock.instant().getEpochSecond()));
        var target = current.toBuilder().setBlobId(BlobId.of(bucket, key)).setMetadata(metadata).build();
        // A new generation resets creation age. Both preconditions stop a stale refresh from resurrecting a
        // deleted object or overwriting a replacement that arrived after the metadata read.
        storage.copy(Storage.CopyRequest.newBuilder()
            .setSource(current.getBlobId())
            .setSourceOptions(Storage.BlobSourceOption.generationMatch(current.getGeneration()))
            .setTarget(target, Storage.BlobTargetOption.generationMatch(current.getGeneration()))
            .build()).getResult();
        return true;
      } catch (StorageException e) {
        if (e.getCode() == 404) return false;
        // In particular, a 412 concurrent change is not 'missing'. The manager may retry from a fresh read.
        throw e;
      }
    }, executor);
  }

  private static void requireAvatarKey(String key) {
    // Preserve the exact upstream 16-byte, padded base64url object encoding and profiles/ prefix.
    if (key == null || !key.matches("profiles/[A-Za-z0-9_-]{22}==")) {
      throw new IllegalArgumentException("Expected a server-generated avatar object key");
    }
  }

  @Override
  public void close() throws Exception { storage.close(); }
}
