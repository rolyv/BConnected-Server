// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.auth.ServiceAccountSigner;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.GcsAvatarConfiguration;
import org.whispersystems.textsecuregcm.grpc.ProfileGrpcHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class GcsAvatarStorageTest {
  private static final String BUCKET = "avatar-unit-test";
  private static final String KEY = "profiles/AAAAAAAAAAAAAAAAAAAAAA==";
  private static final String EMAIL = "avatar@test-project.iam.gserviceaccount.com";
  private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-20T10:15:30Z"), ZoneOffset.UTC);
  private HttpServer server;
  private GcsAvatarStorage avatars;
  private KeyPair keyPair;
  private final List<Request> requests = new ArrayList<>();
  private int getStatus = 200;
  private int copyStatus = 200;
  private int deleteStatus = 204;

  @BeforeEach void setUp() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      var requestBody = "gzip".equalsIgnoreCase(exchange.getRequestHeaders().getFirst("Content-Encoding"))
          ? new GZIPInputStream(exchange.getRequestBody()) : exchange.getRequestBody();
      String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
      requests.add(new Request(exchange.getRequestMethod(), exchange.getRequestURI(), body));
      boolean rewrite = exchange.getRequestURI().getPath().contains("/rewriteTo/");
      int status = rewrite ? copyStatus : exchange.getRequestMethod().equals("DELETE") ? deleteStatus : getStatus;
      String response = status >= 400 ? "{\"error\":{\"code\":" + status + ",\"message\":\"unit-test\"}}"
          : rewrite ? "{\"kind\":\"storage#rewriteResponse\",\"done\":true,\"totalBytesRewritten\":\"8\",\"objectSize\":\"8\",\"resource\":" + object("8") + "}"
          : object("7");
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      if (status == 204) {
        exchange.sendResponseHeaders(status, -1);
      } else {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
      }
      exchange.close();
    });
    server.start();
    var storage = StorageOptions.newBuilder().setHost("http://127.0.0.1:" + server.getAddress().getPort())
        .setProjectId("test-project")
        .setCredentials(GoogleCredentials.create(new AccessToken("local-fixture", Date.from(Instant.now().plusSeconds(3600)))))
        .setRetrySettings(StorageOptions.getDefaultRetrySettings().toBuilder().setMaxAttempts(1).build())
        .build().getService();
    ServiceAccountSigner signer = new ServiceAccountSigner() {
      @Override public String getAccount() { return EMAIL; }
      @Override public byte[] sign(byte[] input) {
        try {
          Signature signature = Signature.getInstance("SHA256withRSA");
          signature.initSign(keyPair.getPrivate());
          signature.update(input);
          return signature.sign();
        } catch (Exception e) { throw new AssertionError(e); }
      }
    };
    avatars = new GcsAvatarStorage(storage, BUCKET, signer, Runnable::run, CLOCK);
  }

  @AfterEach void tearDown() throws Exception {
    if (avatars != null) avatars.close();
    if (server != null) server.stop(0);
  }

  private static String object(String generation) {
    return "{\"kind\":\"storage#object\",\"bucket\":\"" + BUCKET + "\",\"name\":\"" + KEY
        + "\",\"generation\":\"" + generation + "\",\"metageneration\":\"1\",\"size\":\"8\","
        + "\"contentType\":\"application/octet-stream\",\"metadata\":{\"keep\":\"existing\"}}";
  }

  @Test void policyBindsBucketExactEncodedKeySizeExpiryAndRsaSignature() throws Exception {
    var policy = avatars.createFor(KEY, 4096, CLOCK.instant());
    JsonNode document = SystemMapper.jsonMapper().readTree(Base64.getDecoder().decode(policy.encodedPolicy()));
    assertThat(policy.algorithm()).isEqualTo("GOOG4-RSA-SHA256");
    assertThat(policy.acl()).isEmpty();
    assertThat(policy.credential()).isEqualTo(EMAIL + "/20260920/auto/storage/goog4_request");
    assertThat(policy.formattedTimestamp()).isEqualTo("20260920T101530Z");
    assertThat(document.path("expiration").asText()).isEqualTo("2026-09-20T10:45:30Z");
    assertThat(document.path("conditions").toString()).contains("\"bucket\":\"" + BUCKET + "\"",
        "\"key\":\"" + KEY + "\"", "[\"content-length-range\",1,4096]", "x-goog-credential",
        "x-goog-algorithm", "x-goog-date").doesNotContain("x-amz", "\"acl\"");
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(keyPair.getPublic());
    verifier.update(policy.encodedPolicy().getBytes(StandardCharsets.UTF_8));
    assertThat(verifier.verify(HexFormat.of().parseHex(policy.signature()))).isTrue();
    assertThat(requests).isEmpty();
  }

  @Test void grpcAndRestResponsesCarryGoogleFieldsWithoutAwsConstants() throws Exception {
    var grpc = ProfileGrpcHelper.generateAvatarUploadForm(KEY, 1234, avatars, CLOCK);
    var rest = SystemMapper.jsonMapper().valueToTree(avatars.createFor(KEY, 1234, CLOCK.instant()).attributes(KEY));
    assertThat(grpc.getAlgorithm()).isEqualTo("GOOG4-RSA-SHA256");
    assertThat(grpc.getAcl()).isEmpty();
    assertThat(grpc.getKey()).isEqualTo(KEY);
    assertThat(rest.path("algorithm").asText()).isEqualTo(grpc.getAlgorithm());
    assertThat(rest.path("acl").asText()).isEmpty();
    assertThat(rest.path("policy").asText()).isEqualTo(grpc.getPolicy());
    assertThat(rest.path("signature").asText()).isEqualTo(grpc.getSignature());
  }

  @Test void invalidKeysLengthsAndConfigurationFailBeforeStorageAccess() {
    for (String key : List.of("other/object", "profiles/../x", "profiles/AAAAAAAAAAAAAAAAAAAAAA==?x=y")) {
      assertThrows(IllegalArgumentException.class, () -> avatars.createFor(key, 100, CLOCK.instant()));
      assertThrows(IllegalArgumentException.class, () -> avatars.delete(key));
      assertThrows(IllegalArgumentException.class, () -> avatars.refresh(key));
    }
    assertThrows(IllegalArgumentException.class, () -> avatars.createFor(KEY, 0, CLOCK.instant()));
    assertThrows(IllegalArgumentException.class, () -> avatars.createFor(KEY, 10 * 1024 * 1024 + 1, CLOCK.instant()));
    assertThrows(IllegalArgumentException.class, () -> new GcsAvatarConfiguration("https://wrong", EMAIL));
    assertThrows(IllegalArgumentException.class, () -> new GcsAvatarConfiguration(BUCKET, "not-a-service-account"));
    assertThat(requests).isEmpty();
  }

  @Test void deleteUsesExactBucketAndEncodedKeyAndMissingIsIdempotent() {
    avatars.delete(KEY).join();
    deleteStatus = 404;
    avatars.delete(KEY).join();
    assertThat(requests).hasSize(2).allSatisfy(request -> {
      assertThat(request.method).isEqualTo("DELETE");
      assertThat(request.uri.getPath()).endsWith("/b/" + BUCKET + "/o/" + KEY);
    });
  }

  @Test void refreshRewritesGenerationWithBothPreconditionsAndKeepsMetadata() throws Exception {
    assertThat(avatars.refresh(KEY).join()).isTrue();
    assertThat(requests).hasSize(2);
    Request rewrite = requests.get(1);
    assertThat(rewrite.method).isEqualTo("POST");
    assertThat(rewrite.uri.getPath()).contains("/rewriteTo/b/" + BUCKET + "/o/" + KEY);
    assertThat(rewrite.uri.getQuery()).contains("ifGenerationMatch=7", "ifSourceGenerationMatch=7", "sourceGeneration=7");
    JsonNode body = SystemMapper.jsonMapper().readTree(rewrite.body);
    assertThat(body.path("metadata").path("t").asText()).isEqualTo(Long.toString(CLOCK.instant().getEpochSecond()));
    assertThat(body.path("metadata").path("keep").asText()).isEqualTo("existing");
    assertThat(body.path("contentType").asText()).isEqualTo("application/octet-stream");
  }

  @Test void missingRefreshNeverCreatesAnObject() {
    getStatus = 404;
    assertThat(avatars.refresh(KEY).join()).isFalse();
    assertThat(requests).hasSize(1);
    assertThat(requests.getFirst().method).isEqualTo("GET");
  }

  @Test void concurrentDeleteOrReplacementFailsClosedOnCopyPrecondition() {
    copyStatus = 412;
    assertThatThrownBy(() -> avatars.refresh(KEY).join()).isInstanceOf(CompletionException.class)
        .hasCauseInstanceOf(StorageException.class)
        .satisfies(error -> assertThat(((StorageException) error.getCause()).getCode()).isEqualTo(412));
    assertThat(requests).hasSize(2);
  }

  @Test void permissionFailureIsNotMistakenForMissingObject() {
    getStatus = 403;
    assertThatThrownBy(() -> avatars.refresh(KEY).join()).hasCauseInstanceOf(StorageException.class);
    assertThat(requests).hasSize(1);
  }

  private record Request(String method, URI uri, String body) {}
}
