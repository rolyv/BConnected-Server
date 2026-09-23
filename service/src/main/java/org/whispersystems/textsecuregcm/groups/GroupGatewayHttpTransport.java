// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Unregistered fixed-origin IAM transport. Token acquisition and queue time consume the original proof. */
public final class GroupGatewayHttpTransport implements GroupDispatchService.Transport, AutoCloseable {
  public static final String PROOF_HEADER = "X-BConnected-Original-Proof";
  private static final int MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
  private final URI origin;
  private final IdTokenCredentials credentials;
  private final HttpClient client;
  private final ThreadPoolExecutor workers = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
      new ArrayBlockingQueue<>(8), Thread.ofPlatform().daemon().name("group-gateway-", 0).factory(),
      new ThreadPoolExecutor.AbortPolicy());

  public GroupGatewayHttpTransport(URI fixedGroupsOrigin, IdTokenProvider dedicatedSignalProvider) {
    this(fixedGroupsOrigin, IdTokenCredentials.newBuilder().setIdTokenProvider(Objects.requireNonNull(dedicatedSignalProvider))
        .setTargetAudience(exactOrigin(fixedGroupsOrigin)).build(),
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build());
  }
  GroupGatewayHttpTransport(URI fixedGroupsOrigin, IdTokenCredentials credentials, HttpClient client) {
    exactOrigin(fixedGroupsOrigin);
    if (client.followRedirects() != HttpClient.Redirect.NEVER) throw new IllegalArgumentException("Group redirects forbidden");
    origin = fixedGroupsOrigin; this.credentials = Objects.requireNonNull(credentials); this.client = Objects.requireNonNull(client);
  }
  @Override public CompletableFuture<GroupDispatchService.GatewayResult> dispatch(String method, String path, byte[] body,
      String handle, long deadlineNanos, Runnable requireOriginalCurrent) {
    var result = new CompletableFuture<GroupDispatchService.GatewayResult>();
    try {
      GroupDispatchRequest.parse(method, path, "POST".equals(method) ? "application/json" : null, null, body);
      GroupBridgeProtocol.binary(handle, 32);
      var task = workers.submit(() -> {
        try { result.complete(send(method, path, body, handle, deadlineNanos, requireOriginalCurrent)); }
        catch (Exception failure) { result.completeExceptionally(failure); }
      });
      result.whenComplete((_, failure) -> { if (result.isCancelled()) task.cancel(true); });
    } catch (RuntimeException unavailable) { result.completeExceptionally(unavailable); }
    return result;
  }
  private GroupDispatchService.GatewayResult send(String method, String path, byte[] body, String handle,
      long deadline, Runnable requireOriginalCurrent) throws Exception {
    requireRemaining(deadline);
    requireOriginalCurrent.run();
    requireRemaining(deadline);
    credentials.refreshIfExpired();
    requireRemaining(deadline); // An uninterruptible provider cannot dispatch after the original deadline.
    requireOriginalCurrent.run();
    requireRemaining(deadline);
    var token = credentials.getIdToken();
    if (token == null || token.getTokenValue() == null || token.getTokenValue().length() > 8192)
      throw new IOException("Group IAM identity unavailable");
    long httpNanos = Math.min(TimeUnit.SECONDS.toNanos(2), requireRemaining(deadline));
    requireOriginalCurrent.run();
    requireRemaining(deadline);
    var builder = HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofNanos(httpNanos))
        .header("Authorization", "Bearer " + token.getTokenValue())
        .header(PROOF_HEADER, handle).header("Accept", "application/json");
    var request = "POST".equals(method)
        ? builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build()
        : builder.GET().build();
    requireRemaining(deadline);
    requireOriginalCurrent.run();
    requireRemaining(deadline);
    var pending = client.sendAsync(request, _ -> new LimitedBody());
    try {
      var response = pending.get(Math.min(httpNanos, requireRemaining(deadline)), TimeUnit.NANOSECONDS);
      requireRemaining(deadline);
      if (!response.headers().allValues("content-encoding").isEmpty()) throw new IOException("Compressed group response");
      if (response.statusCode() == 200 && response.headers().allValues("content-type").equals(List.of("application/json")))
        return new GroupDispatchService.GatewayResult(200, response.body());
      if (response.statusCode() == 403 || response.statusCode() == 404 || response.statusCode() == 409 || response.statusCode() == 503)
        throw new GroupDispatchService.GatewayException(response.statusCode());
      throw new IOException("Private group gateway unavailable");
    } catch (Exception failure) { pending.cancel(true); throw failure; }
  }
  private static String exactOrigin(URI origin) {
    if (origin == null || !"https".equals(origin.getScheme()) || origin.getHost() == null || origin.getPort() != -1
        || !origin.getPath().isEmpty() || origin.getUserInfo() != null || origin.getQuery() != null
        || origin.getFragment() != null) throw new IllegalArgumentException("Fixed HTTPS Groups origin required");
    return origin.toString();
  }
  private static long requireRemaining(long deadline) throws Exception {
    if (Thread.currentThread().isInterrupted()) throw new InterruptedException("Group dispatch interrupted");
    long remaining = deadline - System.nanoTime();
    if (remaining <= 0 || remaining > GroupBridgeProtocol.MAX_LIFETIME_NANOS)
      throw new java.util.concurrent.TimeoutException("Group dispatch deadline exceeded");
    return remaining;
  }
  static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
    private final CompletableFuture<byte[]> result = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private Flow.Subscription subscription;
    @Override public CompletionStage<byte[]> getBody() { return result; }
    @Override public void onSubscribe(Flow.Subscription s) { subscription = s; s.request(1); }
    @Override public void onNext(List<ByteBuffer> items) {
      try {
        for (var item : items) {
          if (item.remaining() > MAX_RESPONSE_BYTES - bytes.size()) throw new IOException("Group response too large");
          byte[] chunk = new byte[item.remaining()]; item.get(chunk); bytes.writeBytes(chunk);
        }
        subscription.request(1);
      } catch (Exception failure) { subscription.cancel(); result.completeExceptionally(failure); }
    }
    @Override public void onError(Throwable failure) { result.completeExceptionally(failure); }
    @Override public void onComplete() { result.complete(bytes.toByteArray()); }
  }
  @Override public void close() { workers.shutdownNow(); client.shutdownNow(); }
  @Override public String toString() { return "GroupGatewayHttpTransport[redacted]"; }
}
