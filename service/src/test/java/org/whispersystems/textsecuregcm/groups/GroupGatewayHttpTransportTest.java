// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenCredentials;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;

/** Injected network/token faults; live private TLS and IAM remain separate integration gates. */
class GroupGatewayHttpTransportTest {
  final HttpClient http = mock(HttpClient.class);
  final IdTokenCredentials credentials = mock(IdTokenCredentials.class);
  final String handle = GroupBridgeProtocol.encode(new byte[32]);
  final String path = "/v1/bconnected/group-operations/" + UUID.randomUUID();
  GroupGatewayHttpTransportTest() {
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    IdToken token = mock(IdToken.class);
    when(token.getTokenValue()).thenReturn("synthetic.signal.identity");
    when(credentials.getIdToken()).thenReturn(token);
  }
  GroupGatewayHttpTransport transport() {
    return new GroupGatewayHttpTransport(URI.create("https://groups.example.test"), credentials, http);
  }
  @SuppressWarnings("unchecked") HttpResponse<byte[]> response(int status, Map<String, List<String>> headers) {
    HttpResponse<byte[]> r = mock(HttpResponse.class);
    when(r.statusCode()).thenReturn(status);
    when(r.headers()).thenReturn(HttpHeaders.of(headers, (_, _) -> true));
    when(r.body()).thenReturn("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    return r;
  }
  @Test void sendsOnlyFixedOriginIamAndPrivateHandle() throws Exception {
    when(http.<byte[]>sendAsync(any(), any())).thenAnswer(invocation -> {
      HttpRequest request = invocation.getArgument(0);
      assertThat(request.uri().toString()).isEqualTo("https://groups.example.test" + path);
      assertThat(request.method()).isEqualTo("GET");
      assertThat(request.headers().firstValue("Authorization")).contains("Bearer synthetic.signal.identity");
      assertThat(request.headers().firstValue(GroupGatewayHttpTransport.PROOF_HEADER)).contains(handle);
      assertThat(request.headers().firstValue("Content-Type")).isEmpty();
      return CompletableFuture.completedFuture(response(200, Map.of("Content-Type", List.of("application/json"))));
    });
    try (var transport = transport()) {
      var outcome = transport.dispatch("GET", path, new byte[0], handle, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {})
          .get(4, TimeUnit.SECONDS);
      assertThat(new String(outcome.json(), java.nio.charset.StandardCharsets.UTF_8)).isEqualTo("{}");
    }
    verify(credentials).refreshIfExpired();
  }
  @Test void rejectsRedirectCompressionAndUnapprovedResponseType() throws Exception {
    try (var transport = transport()) {
      for (var result : List.of(response(302, Map.of("Content-Type", List.of("application/json"))),
          response(200, Map.of("Content-Type", List.of("application/json"), "Content-Encoding", List.of("gzip"))),
          response(200, Map.of("Content-Type", List.of("text/plain"))))) {
        when(http.<byte[]>sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(result));
        try {
          transport.dispatch("GET", path, new byte[0], handle, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {})
              .get(4, TimeUnit.SECONDS);
          org.junit.jupiter.api.Assertions.fail("Invalid gateway result was accepted");
        } catch (java.util.concurrent.ExecutionException expected) {
          assertThat(expected.getCause()).isInstanceOf(java.io.IOException.class);
        }
      }
    }
  }
  @Test void lateUninterruptibleTokenProviderCannotSend() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
    doAnswer(_ -> {
      entered.countDown();
      while (release.getCount() != 0) {
        try { release.await(); } catch (InterruptedException ignored) { /* Deliberately uninterruptible fixture. */ }
      }
      return null;
    }).when(credentials).refreshIfExpired();
    try (var transport = transport()) {
      var work = transport.dispatch("GET", path, new byte[0], handle, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(150), () -> {});
      assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      Thread.sleep(200);
      release.countDown();
      try { work.get(1, TimeUnit.SECONDS); org.junit.jupiter.api.Assertions.fail("Expired proof dispatched"); }
      catch (java.util.concurrent.ExecutionException expected) {
        assertThat(expected.getCause()).isInstanceOf(java.util.concurrent.TimeoutException.class);
      }
      verify(http, never()).sendAsync(any(), any());
    } finally { release.countDown(); }
  }
  @Test void changedOriginalProofDuringTokenWaitCannotSend() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
    var current = new AtomicBoolean(true);
    doAnswer(_ -> { entered.countDown(); release.await(); return null; }).when(credentials).refreshIfExpired();
    try (var transport = transport()) {
      var work = transport.dispatch("GET", path, new byte[0], handle,
          System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {
            if (!current.get()) throw new SecurityException("Original proof changed");
          });
      assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      current.set(false); release.countDown();
      try { work.get(2, TimeUnit.SECONDS); org.junit.jupiter.api.Assertions.fail("Changed proof dispatched"); }
      catch (java.util.concurrent.ExecutionException expected) {
        assertThat(expected.getCause()).isInstanceOf(SecurityException.class);
      }
      verify(http, never()).sendAsync(any(), any());
    } finally { release.countDown(); }
  }
  @Test void streamingBodyCancelsAsSoonAsItExceedsLimit() {
    var subscriber = new GroupGatewayHttpTransport.LimitedBody();
    var cancelled = new AtomicBoolean();
    subscriber.onSubscribe(new Flow.Subscription() {
      @Override public void request(long count) {}
      @Override public void cancel() { cancelled.set(true); }
    });
    subscriber.onNext(List.of(ByteBuffer.allocate(20 * 1024 * 1024 + 1)));
    assertThat(cancelled).isTrue();
    assertThat(subscriber.getBody().toCompletableFuture()).isCompletedExceptionally();
  }
  @Test void tokenWorkerAndQueueSaturationRejectsWithoutNetwork() throws Exception {
    var entered = new CountDownLatch(4); var release = new CountDownLatch(1);
    doAnswer(_ -> { entered.countDown(); release.await(); return null; }).when(credentials).refreshIfExpired();
    var pending = new ArrayList<CompletableFuture<GroupDispatchService.GatewayResult>>();
    try (var transport = transport()) {
      for (int i = 0; i < 4; i++) pending.add(transport.dispatch("GET", path, new byte[0], handle,
          System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {}));
      assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      for (int i = 0; i < 8; i++) pending.add(transport.dispatch("GET", path, new byte[0], handle,
          System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {}));
      var rejected = transport.dispatch("GET", path, new byte[0], handle,
          System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> {});
      try { rejected.get(1, TimeUnit.SECONDS); org.junit.jupiter.api.Assertions.fail("Saturated queue accepted work"); }
      catch (java.util.concurrent.ExecutionException expected) {
        assertThat(expected.getCause()).isInstanceOf(java.util.concurrent.RejectedExecutionException.class);
      }
      verify(http, never()).sendAsync(any(), any());
    } finally {
      pending.forEach(f -> f.cancel(true)); release.countDown();
    }
  }
}
