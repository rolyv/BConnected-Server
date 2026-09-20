// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import io.lettuce.core.RedisCredentialsProvider;
import io.lettuce.core.RedisURI;
import io.lettuce.core.SslOptions;
import io.lettuce.core.SslVerifyMode;
import jakarta.validation.constraints.NotBlank;
import java.io.File;
import java.net.URI;
import java.time.Duration;
import org.whispersystems.textsecuregcm.redis.GcpRedisCredentialsProvider;
import org.whispersystems.textsecuregcm.redis.RedisUriUtil;

/** A per-cluster CA authenticates managed Redis endpoints, whose addresses may change on discovery. */
public record GcpRedisConfiguration(@NotBlank String caCertificateFile) {
  public RedisURI createUri(String value, Duration timeout) {
    validateUri(value);
    return createUri(value, timeout, GcpRedisCredentialsProvider.create());
  }
  public RedisURI createUri(String value, Duration timeout, RedisCredentialsProvider provider) {
    validateUri(value);
    RedisURI uri = RedisUriUtil.createRedisUriWithTimeout(value, timeout);
    uri.setCredentialsProvider(provider);
    // Keep certificate-chain verification against ONLY this cluster's CA, including discovered nodes.
    uri.setVerifyPeer(SslVerifyMode.CA);
    return uri;
  }
  private static void validateUri(String value) {
    URI uri = URI.create(value);
    if (!"rediss".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
        || uri.getQuery() != null || uri.getFragment() != null
        || (uri.getPath() != null && !uri.getPath().isEmpty() && !"/".equals(uri.getPath()))) {
      throw new IllegalArgumentException("GCP Redis requires a rediss endpoint without inline credentials or URI overrides");
    }
  }
  public SslOptions sslOptions() {
    if (caCertificateFile == null || !new File(caCertificateFile).isFile()) {
      throw new IllegalArgumentException("A mounted per-cluster Redis CA file is required");
    }
    return SslOptions.builder().jdkSslProvider().trustManager(new File(caCertificateFile))
        .handshakeTimeout(Duration.ofSeconds(10)).protocols("TLSv1.3", "TLSv1.2").build();
  }
}
