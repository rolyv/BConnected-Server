// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.mockito.ArgumentMatchers;
import org.whispersystems.textsecuregcm.util.MutableClock;

final class AdmissionProtocolFixture implements AutoCloseable {
  final MutableClock clock =
      new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
  final AtomicLong nanos = new AtomicLong();
  final KeyPair key = AdmissionTestData.keys();
  final AdmissionPermitVerifier verifier =
      new AdmissionPermitVerifier(Map.of("test-key", key.getPublic()), clock);
  final List<JsonNode> claims = new CopyOnWriteArrayList<>(),
      attestations = new CopyOnWriteArrayList<>();
  final AdmissionServiceClient client;
  long epoch = 7, expires = clock.millis() + 120000;
  int claimStatus = 200, attestStatus = 200;
  Consumer<Map<String, Object>> mutateClaim = b -> {}, mutateAttest = b -> {};
  Runnable beforeClaim = () -> {}, afterClaim = () -> {};
  final Map<String, Map<String, Object>> issued = new ConcurrentHashMap<>();

  AdmissionProtocolFixture() throws Exception {
    var http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    when(http.cookieHandler()).thenReturn(Optional.empty());
    client =
        new AdmissionServiceClient(
            AdmissionServiceConfiguration.pilot(),
            http,
            () -> "synthetic.header.signature",
            clock,
            nanos::get,
            new SecureRandom());
    when(http.sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenAnswer(
            call -> {
              HttpRequest request = call.getArgument(0);
              JsonNode body = body(request);
              boolean claim = request.uri().getPath().endsWith("/claims");
              Map<String, Object> result = new LinkedHashMap<>();
              if (claim) {
                beforeClaim.run();
                claims.add(body);
                result.put("signalOperationId", body.get("signalOperationId").textValue());
                result.put("memberId", body.get("memberId").textValue());
                result.put("approvalEpoch", epoch);
                result.put("expiresAt", expires);
                result.put("status", "claimed");
                result.put("registrationAuthorized", false);
                mutateClaim.accept(result);
                afterClaim.run();
              } else {
                attestations.add(body);
                String operation = body.get("signalOperationId").textValue();
                if (issued.containsKey(operation)) result.putAll(issued.get(operation));
                else {
                  var expected =
                      new AdmissionPermitVerifier.ExpectedBinding(
                          UUID.fromString(body.get("memberId").textValue()),
                          epoch,
                          UUID.fromString(operation),
                          body.get("registrationAttemptHash").textValue(),
                          body.get("serverVerificationSessionHash").textValue(),
                          body.get("deviceKeyCommitment").textValue(),
                          body.get("phoneBinding").textValue(),
                          body.get("serverRequestCommitment").textValue(),
                          "+13055550123");
                  String id = AdmissionTestData.id();
                  var signed =
                      AdmissionTestData.claims(expected, id, clock.instant().getEpochSecond());
                  long deadline =
                      Math.min(
                              Math.min(expires, body.get("sessionExpiresAt").longValue()),
                              clock.millis() + 30000)
                          / 1000;
                  signed.put("exp", deadline);
                  result.put(
                      "assertion", AdmissionTestData.sign(key, AdmissionTestData.header(), signed));
                  result.put("permitId", id);
                  result.put("expiresAt", deadline * 1000);
                  issued.put(operation, new LinkedHashMap<>(result));
                }
                mutateAttest.accept(result);
              }
              @SuppressWarnings("unchecked")
              HttpResponse<byte[]> response = mock(HttpResponse.class);
              when(response.statusCode()).thenReturn(claim ? claimStatus : attestStatus);
              when(response.uri()).thenReturn(request.uri());
              when(response.previousResponse()).thenReturn(Optional.empty());
              when(response.headers())
                  .thenReturn(
                      HttpHeaders.of(
                          Map.of("Content-Type", List.of("application/json")), (a, b) -> true));
              when(response.body()).thenReturn(AdmissionTestData.JSON.writeValueAsBytes(result));
              return CompletableFuture.completedFuture(response);
            });
  }

  void advance(long millis) {
    clock.incrementMillis(millis);
    nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis));
  }

  static JsonNode body(HttpRequest request) throws Exception {
    var complete = new CompletableFuture<byte[]>();
    request
        .bodyPublisher()
        .orElseThrow()
        .subscribe(
            new Flow.Subscriber<ByteBuffer>() {
              final ByteArrayOutputStream out = new ByteArrayOutputStream();

              public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
              }

              public void onNext(ByteBuffer value) {
                byte[] bytes = new byte[value.remaining()];
                value.get(bytes);
                out.writeBytes(bytes);
              }

              public void onError(Throwable error) {
                complete.completeExceptionally(error);
              }

              public void onComplete() {
                complete.complete(out.toByteArray());
              }
            });
    return AdmissionTestData.JSON.readTree(complete.get(1, TimeUnit.SECONDS));
  }

  @Override
  public void close() {
    client.close();
  }
}
