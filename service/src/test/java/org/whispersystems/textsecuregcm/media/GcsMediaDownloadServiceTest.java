// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.media;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.GcsMediaDownloadConfiguration;

class GcsMediaDownloadServiceTest {
  private static final String AVATAR = "profiles/AAAAAAAAAAAAAAAAAAAAAA==";
  private static final String ATTACHMENT = "AAAAAAAAAAAAAAAAAAAA";
  private static final String SIGNER = "media@test-project.iam.gserviceaccount.com";
  private Storage storage;
  private GcsMediaDownloadService service;
  private final AtomicReference<byte[]> signedBytes = new AtomicReference<>();
  private KeyPair pair;

  @BeforeEach void setUp() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    pair = generator.generateKeyPair();
    var credentials = GoogleCredentials.create(new AccessToken("offline-fixture", Date.from(Instant.now().plusSeconds(3600))));
    storage = spy(StorageOptions.newBuilder().setProjectId("test-project").setCredentials(credentials).build().getService());
    ServiceAccountSigner signer = new ServiceAccountSigner() {
      @Override public String getAccount() { return SIGNER; }
      @Override public byte[] sign(byte[] input) {
        signedBytes.set(input.clone());
        try {
          var signature = Signature.getInstance("SHA256withRSA");
          signature.initSign(pair.getPrivate()); signature.update(input); return signature.sign();
        } catch (Exception e) { throw new AssertionError(e); }
      }
    };
    service = new GcsMediaDownloadService(storage, signer, configuration(Duration.ofMinutes(5)), Clock.systemUTC());
  }

  @AfterEach void tearDown() throws Exception { if (service != null) service.close(); }

  private static GcsMediaDownloadConfiguration configuration(Duration validity) {
    return new GcsMediaDownloadConfiguration("private-avatars", "private-attachments", "", SIGNER, validity);
  }

  private void object(String bucket, String name) {
    Blob blob = mock(Blob.class);
    when(blob.getGeneration()).thenReturn(42L);
    when(blob.getSize()).thenReturn(1024L);
    doReturn(blob).when(storage).get(BlobId.of(bucket, name));
  }

  @Test void signsExactGetGenerationWithBoundedExpiryAndValidRsa() throws Exception {
    object("private-avatars", AVATAR);
    var capability = service.issue(0, AVATAR);
    URI url = URI.create(capability.url());
    assertThat(url.getScheme()).isEqualTo("https");
    assertThat(url.getHost()).isEqualTo("storage.googleapis.com");
    assertThat(url.getPath()).isEqualTo("/private-avatars/" + AVATAR);
    Map<String, String> query = query(url);
    assertThat(query.get("generation")).isEqualTo("42");
    assertThat(query.get("X-Goog-Expires")).isEqualTo("300");
    assertThat(query.get("X-Goog-SignedHeaders")).isEqualTo("host");
    assertThat(capability.expiresAt()).isBetween(Instant.now().getEpochSecond() + 290, Instant.now().getEpochSecond() + 300);
    assertThat(capability.contentLength()).isEqualTo(1024);
    assertThat(capability.toString()).doesNotContain(capability.url(), AVATAR);
    String canonicalQuery = Arrays.stream(url.getRawQuery().split("&"))
        .filter(field -> !field.startsWith("X-Goog-Signature=")).sorted().collect(Collectors.joining("&"));
    String canonical = "GET\n" + url.getRawPath() + "\n" + canonicalQuery
        + "\nhost:storage.googleapis.com\n\nhost\nUNSIGNED-PAYLOAD";
    String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    assertThat(new String(signedBytes.get(), StandardCharsets.UTF_8)).endsWith("\n" + digest);
    var verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(pair.getPublic()); verifier.update(signedBytes.get());
    assertThat(verifier.verify(HexFormat.of().parseHex(query.get("X-Goog-Signature")))).isTrue();
  }

  @Test void attachmentKeyMapsOnlyToConfiguredBucketWithoutClientCdnPathPrefix() {
    object("private-attachments", ATTACHMENT);
    var capability = service.issue(2, ATTACHMENT);
    assertThat(URI.create(capability.url()).getPath()).isEqualTo("/private-attachments/" + ATTACHMENT);
    verify(storage).get(BlobId.of("private-attachments", ATTACHMENT));
  }

  @Test void rejectsTraversalUrlsUnknownCdnAndNoncanonicalBitsBeforeCloudAccess() {
    for (String key : List.of("https://evil.example/x", "../secret", "profiles/%2e%2e/secret", AVATAR + "?x=y",
        "profiles/AAAAAAAAAAAAAAAAAAAAAB==", "profiles/AAAAAAAAAAAAAAAAAAAAAA", "attachments/" + ATTACHMENT)) {
      assertThrows(IllegalArgumentException.class, () -> service.issue(0, key));
    }
    assertThrows(IllegalArgumentException.class, () -> service.issue(3, ATTACHMENT));
    assertThrows(IllegalArgumentException.class, () -> service.issue(2, AVATAR));
    verify(storage, never()).get(any(BlobId.class));
    assertThat(signedBytes.get()).isNull();
  }

  @Test void missingObjectCannotBeSignedAndForbiddenIsNotTreatedAsMissing() {
    doReturn(null).when(storage).get(BlobId.of("private-avatars", AVATAR));
    assertThrows(GcsMediaDownloadService.MissingMediaException.class, () -> service.issue(0, AVATAR));
    doThrow(new StorageException(403, "fixture")).when(storage).get(BlobId.of("private-avatars", AVATAR));
    assertThrows(StorageException.class, () -> service.issue(0, AVATAR));
    assertThat(signedBytes.get()).isNull();
  }

  @Test void rejectsExpiredOverlongForeignHostAndChangedGenerationUrls() {
    object("private-avatars", AVATAR);
    URI valid = URI.create(service.issue(0, AVATAR).url());
    for (String changed : List.of(valid.toString().replace("https:", "http:"),
        valid.toString().replace("storage.googleapis.com", "evil.example"),
        valid.toString().replace("private-avatars", "other-bucket"),
        valid.toString().replace("generation=42", "generation=43"),
        valid.toString().replace("X-Goog-Expires=300", "X-Goog-Expires=301"),
        valid + "&generation=42")) {
      assertThrows(IllegalStateException.class, () -> GcsMediaDownloadService.validateSignedUrl(URI.create(changed),
          "private-avatars", AVATAR, 42, Duration.ofMinutes(5), Instant.now()));
    }
    assertThrows(IllegalStateException.class, () -> GcsMediaDownloadService.validateSignedUrl(valid,
        "private-avatars", AVATAR, 42, Duration.ofMinutes(5), Instant.now().plusSeconds(301)));
  }

  @Test void configurationCannotExtendValidityOrEscapeObjectPrefix() {
    for (Duration bad : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(301), Duration.ofMillis(1500))) {
      assertThrows(IllegalArgumentException.class, () -> configuration(bad));
    }
    for (String prefix : List.of("/", "../", "x/../", "https://evil/", "x?y/")) {
      assertThrows(IllegalArgumentException.class, () -> new GcsMediaDownloadConfiguration("private-avatars",
          "private-attachments", prefix, SIGNER, Duration.ofMinutes(5)));
    }
  }

  private static Map<String, String> query(URI uri) {
    return Arrays.stream(uri.getRawQuery().split("&")).map(field -> field.split("=", 2)).collect(Collectors.toMap(
        pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8), pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8)));
  }
}
