// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.redis;

import static org.junit.jupiter.api.Assertions.*;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import io.lettuce.core.RedisCredentials;
import io.lettuce.core.SslVerifyMode;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.GcpRedisConfiguration;
import reactor.core.publisher.Mono;

class GcpRedisCredentialsProviderTest {
  @Test void retrievesFreshTokenForConnectionsAndHidesItFromUri() throws IOException {
    var count = new AtomicInteger();
    var credentials = new GoogleCredentials() {
      @Override public AccessToken refreshAccessToken() {
        return new AccessToken("fixture-" + count.incrementAndGet(), Date.from(Instant.now().plusSeconds(3600)));
      }
    };
    var provider = new GcpRedisCredentialsProvider(credentials);
    var first = provider.resolveCredentials().block(Duration.ofSeconds(5));
    assertFalse(first.hasUsername());
    assertEquals("fixture-1", new String(first.getPassword()));
    credentials.refresh();
    var second = provider.resolveCredentials().block(Duration.ofSeconds(5));
    assertEquals("fixture-2", new String(second.getPassword()));
    var uri = new GcpRedisConfiguration("/mounted/owned-ca.pem")
        .createUri("rediss://10.72.1.2:6379", Duration.ofSeconds(5), provider);
    assertTrue(uri.isSsl());
    assertEquals(SslVerifyMode.CA, uri.getVerifyMode());
    assertSame(provider, uri.getCredentialsProvider());
    assertFalse(uri.toString().contains("fixture"));
    assertFalse(provider.toString().contains("fixture"));
  }
  @Test void refreshFailureIsUnavailableWithoutLeakingProviderMessage() {
    var credentials = new GoogleCredentials() {
      @Override public AccessToken refreshAccessToken() throws IOException { throw new IOException("sensitive-response"); }
    };
    var error = assertThrows(IllegalStateException.class,
        () -> new GcpRedisCredentialsProvider(credentials).resolveCredentials().block(Duration.ofSeconds(5)));
    assertFalse(error.toString().contains("sensitive-response"));
    assertNull(error.getCause());
  }
  @ParameterizedTest @ValueSource(strings={"redis://10.72.1.2:6379", "rediss://user:token@10.72.1.2:6379",
      "rediss://10.72.1.2:6379?verifyPeer=NONE", "rediss://10.72.1.2:6379/1", "rediss://10.72.1.2:6379#x"})
  void rejectsInsecureOrCredentialBearingConfiguration(String uri) {
    assertThrows(IllegalArgumentException.class, () -> new GcpRedisConfiguration("/unused")
        .createUri(uri, Duration.ofSeconds(1), () -> Mono.just(RedisCredentials.just(null,"unused"))));
  }
  @Test void missingCaCannotFallBackToSystemRoots() {
    assertThrows(IllegalArgumentException.class, () -> new GcpRedisConfiguration("/nonexistent-bconnected-ca").sslOptions());
  }
}
