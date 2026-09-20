// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.redis;

import com.google.auth.oauth2.GoogleCredentials;
import io.lettuce.core.RedisCredentials;
import io.lettuce.core.RedisCredentialsProvider;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/** Short-lived ADC tokens are resolved for each connection; never put in a Redis URI or log message. */
public final class GcpRedisCredentialsProvider implements RedisCredentialsProvider {
  private final GoogleCredentials credentials;
  public GcpRedisCredentialsProvider(GoogleCredentials credentials) { this.credentials = Objects.requireNonNull(credentials); }
  public static GcpRedisCredentialsProvider create() {
    try {
      return new GcpRedisCredentialsProvider(GoogleCredentials.getApplicationDefault()
          .createScoped(List.of("https://www.googleapis.com/auth/cloud-platform")));
    } catch (IOException failure) { throw new IllegalStateException("GCP Redis credentials are unavailable"); }
  }
  @Override
  public Mono<RedisCredentials> resolveCredentials() {
    return Mono.fromCallable(() -> {
      try {
        synchronized (credentials) {
          credentials.refreshIfExpired();
          var token = credentials.getAccessToken();
          if (token == null || token.getTokenValue() == null || token.getTokenValue().isBlank()
              || token.getExpirationTime() == null || !token.getExpirationTime().toInstant().isAfter(Instant.now())) {
            throw new IOException("Missing or expired token");
          }
          // Memorystore accepts AUTH <token>; an account email is not a Redis username.
          return RedisCredentials.just(null, token.getTokenValue());
        }
      } catch (IOException failure) { throw new IllegalStateException("GCP Redis authentication is unavailable"); }
    }).subscribeOn(Schedulers.boundedElastic());
  }
  @Override public String toString() { return "GcpRedisCredentialsProvider[ADC]"; }
}
