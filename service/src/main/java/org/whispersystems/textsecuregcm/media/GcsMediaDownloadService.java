// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.media;

import com.google.auth.ServiceAccountSigner;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.HttpMethod;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.whispersystems.textsecuregcm.configuration.GcsMediaDownloadConfiguration;

/** Authenticated account + possession of Signal's opaque media key grants a short-lived, generation-bound read. */
public final class GcsMediaDownloadService implements AutoCloseable {
  private static final DateTimeFormatter SIGNING_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT)
      .withZone(ZoneOffset.UTC);
  private final Storage storage;
  private final ServiceAccountSigner signer;
  private final GcsMediaDownloadConfiguration configuration;
  private final Clock clock;

  public GcsMediaDownloadService(Storage storage, ServiceAccountSigner signer,
      GcsMediaDownloadConfiguration configuration, Clock clock) {
    this.storage = Objects.requireNonNull(storage);
    this.signer = Objects.requireNonNull(signer);
    this.configuration = Objects.requireNonNull(configuration);
    this.clock = Objects.requireNonNull(clock);
  }

  public record DownloadCapability(String url, long expiresAt, long contentLength) {
    @Override public String toString() { return "DownloadCapability[redacted]"; }
  }

  public static final class MissingMediaException extends RuntimeException {
    public MissingMediaException() { super(null, null, false, false); }
  }

  public DownloadCapability issue(int cdn, String key) {
    validateKey(cdn, key);
    String bucket = cdn == 0 ? configuration.avatarBucket() : configuration.attachmentBucket();
    String objectName = cdn == 0 ? key : configuration.attachmentObjectPrefix() + key;
    final com.google.cloud.storage.Blob object;
    try {
      object = storage.get(BlobId.of(bucket, objectName));
    } catch (StorageException e) {
      if (e.getCode() == 404) throw new MissingMediaException();
      throw e;
    }
    if (object == null) throw new MissingMediaException();
    if (object.getGeneration() == null || object.getGeneration() <= 0 || object.getSize() == null || object.getSize() < 0) {
      throw new IllegalStateException("Invalid media object metadata");
    }
    long generation = object.getGeneration();
    URI signed = URI.create(storage.signUrl(BlobInfo.newBuilder(bucket, objectName).build(),
        configuration.validity().toSeconds(), TimeUnit.SECONDS,
        Storage.SignUrlOption.withV4Signature(), Storage.SignUrlOption.httpMethod(HttpMethod.GET),
        Storage.SignUrlOption.withPathStyle(), Storage.SignUrlOption.signWith(signer),
        Storage.SignUrlOption.withQueryParams(Map.of("generation", Long.toString(generation)))).toString());
    // Defense in depth around SDK output; callers may never select a host, URL, bucket, or object prefix.
    long expiration = validateSignedUrl(signed, bucket, objectName, generation, configuration.validity(), clock.instant());
    return new DownloadCapability(signed.toASCIIString(), expiration, object.getSize());
  }

  public static void validateKey(int cdn, String key) {
    if (key == null) throw new IllegalArgumentException("Invalid media key");
    String encoded;
    int byteLength;
    if (cdn == 0 && key.matches("profiles/[A-Za-z0-9_-]{22}==")) {
      encoded = key.substring("profiles/".length());
      byteLength = 16;
    } else if (cdn == 2 && key.matches("[A-Za-z0-9_-]{20}")) {
      encoded = key;
      byteLength = 15;
    } else {
      throw new IllegalArgumentException("Invalid media key or CDN");
    }
    byte[] bytes = Base64.getUrlDecoder().decode(encoded);
    if (bytes.length != byteLength || !Base64.getUrlEncoder().encodeToString(bytes).equals(encoded)) {
      throw new IllegalArgumentException("Non-canonical media key");
    }
  }

  static long validateSignedUrl(URI url, String bucket, String objectName, long generation,
      Duration validity, Instant now) {
    if (!"https".equals(url.getScheme()) || !"storage.googleapis.com".equals(url.getHost())
        || url.getPort() != -1 || url.getRawUserInfo() != null || url.getRawFragment() != null
        || !("/" + bucket + "/" + objectName).equals(url.getPath())) {
      throw new IllegalStateException("Invalid signed media URL");
    }
    Map<String, String> query = new HashMap<>();
    for (String field : Objects.requireNonNull(url.getRawQuery()).split("&")) {
      String[] pair = field.split("=", 2);
      if (pair.length != 2 || query.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
          URLDecoder.decode(pair[1], StandardCharsets.UTF_8)) != null) {
        throw new IllegalStateException("Invalid signed media query");
      }
    }
    if (!query.keySet().equals(java.util.Set.of("X-Goog-Algorithm", "X-Goog-Credential", "X-Goog-Date",
        "X-Goog-Expires", "X-Goog-SignedHeaders", "X-Goog-Signature", "generation"))
        || !"GOOG4-RSA-SHA256".equals(query.get("X-Goog-Algorithm"))
        || !"host".equals(query.get("X-Goog-SignedHeaders"))
        || !Long.toString(generation).equals(query.get("generation"))) {
      throw new IllegalStateException("Invalid signed media scope");
    }
    long seconds = Long.parseLong(query.get("X-Goog-Expires"));
    Instant signedAt = Instant.from(SIGNING_DATE.parse(query.get("X-Goog-Date")));
    Instant expiresAt = signedAt.plusSeconds(seconds);
    if (seconds < 1 || seconds > validity.toSeconds() || seconds > 300
        || !expiresAt.isAfter(now) || signedAt.isAfter(now.plusSeconds(5))) {
      throw new IllegalStateException("Invalid signed media expiry");
    }
    return expiresAt.getEpochSecond();
  }

  @Override public void close() throws Exception { storage.close(); }
}
