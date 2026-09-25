// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.whispersystems.textsecuregcm.util.MutableClock;

class AdmissionServiceClientTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String TOKEN = "synthetic.header.signature";
  private HttpClient http;
  private AdmissionServiceClient client;
  private MutableClock clock;
  private AtomicLong nanos;
  private AtomicInteger credentialCalls;
  private AdmissionServiceClient.Binding binding;
  private Consumer<Map<String, Object>> mutate;
  private Runnable responseDelay;
  private List<HttpRequest> requests;
  private List<JsonNode> bodies;
  private int status;
  private String contentType, encoding, rawBody;
  private java.util.function.UnaryOperator<String> rawTransform =
      java.util.function.UnaryOperator.identity();
  private byte[] rawBytes;
  private URI responseUri;

  @BeforeEach
  void setup() throws Exception {
    http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    when(http.cookieHandler()).thenReturn(Optional.empty());
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    nanos = new AtomicLong();
    credentialCalls = new AtomicInteger();
    binding =
        new AdmissionServiceClient.Binding(
            UUID.randomUUID(), 1, UUID.randomUUID(), AdmissionTestData.id(), UUID.randomUUID());
    mutate = body -> {};
    responseDelay = () -> {};
    requests = new ArrayList<>();
    bodies = new ArrayList<>();
    status = 200;
    contentType = "application/json";
    client =
        newClient(
            () -> {
              credentialCalls.incrementAndGet();
              return TOKEN;
            },
            AdmissionServiceConfiguration.pilot());
    when(http.sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenAnswer(
            call -> {
              HttpRequest request = call.getArgument(0);
              requests.add(request);
              JsonNode body = requestBody(request);
              bodies.add(body);
              var responseBody = new LinkedHashMap<String, Object>();
              body.fields()
                  .forEachRemaining(
                      entry ->
                          responseBody.put(
                              entry.getKey(),
                              entry.getValue().isIntegralNumber()
                                  ? entry.getValue().longValue()
                                  : entry.getValue().textValue()));
              responseBody.put("status", "confirmed");
              responseBody.put("confirmedAt", clock.millis() - 1000);
              responseBody.put("checkedAt", clock.millis());
              responseBody.put("validUntil", clock.millis() + 4000);
              mutate.accept(responseBody);
              @SuppressWarnings("unchecked")
              HttpResponse<byte[]> response = mock(HttpResponse.class);
              when(response.statusCode()).thenReturn(status);
              when(response.uri()).thenReturn(responseUri == null ? request.uri() : responseUri);
              when(response.previousResponse()).thenReturn(Optional.empty());
              var headers = new LinkedHashMap<String, List<String>>();
              if (contentType != null) headers.put("Content-Type", List.of(contentType));
              if (encoding != null) headers.put("Content-Encoding", List.of(encoding));
              when(response.headers()).thenReturn(HttpHeaders.of(headers, (key, value) -> true));
              when(response.body())
                  .thenReturn(
                      rawBytes != null
                          ? rawBytes
                          : rawBody != null
                              ? rawBody.getBytes(StandardCharsets.UTF_8)
                              : rawTransform
                                  .apply(JSON.writeValueAsString(responseBody))
                                  .getBytes(StandardCharsets.UTF_8));
              responseDelay.run();
              return CompletableFuture.completedFuture(response);
            });
  }

  @Test void signupSupersessionPrivateContractIsExactAndExpiredReceiptDoesNotRenew() throws Exception {
    UUID original = UUID.randomUUID(), correction = UUID.randomUUID(), replacement = UUID.randomUUID();
    rawBody = JSON.writeValueAsString(Map.of("applicationId", original.toString(), "signupOperationId", original.toString(),
        "status", "supersession_eligible"));
    client.requireSignupSupersessionEligible(original, "a".repeat(64), "b".repeat(64), "c".repeat(64));
    assertThat(requests.getLast().uri().getPath()).endsWith("/signup-supersession-eligibility");
    assertThat(bodies.getLast().size()).isEqualTo(5);
    var receipt = new LinkedHashMap<String, Object>(Map.of("correctionId", correction.toString(),
        "originalApplicationId", original.toString(), "replacementApplicationId", replacement.toString(),
        "state", "replacement_ready", "expiresAt", clock.millis() - 1000, "registrationAuthorized", false));
    rawBody = JSON.writeValueAsString(receipt);
    assertThat(client.supersedeSignup(original, "a".repeat(64), "b".repeat(64), "c".repeat(64), correction,
        replacement, "d".repeat(64), "e".repeat(64))).isEqualTo(clock.millis() - 1000);
    assertThat(requests.getLast().uri().getPath()).endsWith("/signup-supersessions");
    assertThat(bodies.getLast().size()).isEqualTo(9);
    for (String field : List.of("correctionId", "originalApplicationId", "replacementApplicationId", "state", "registrationAuthorized")) {
      var wrong = new LinkedHashMap<>(receipt);
      wrong.put(field, field.equals("registrationAuthorized") ? true : UUID.randomUUID().toString());
      rawBody = JSON.writeValueAsString(wrong);
      assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.supersedeSignup(original,
          "a".repeat(64), "b".repeat(64), "c".repeat(64), correction, replacement, "d".repeat(64), "e".repeat(64)));
    }
    receipt.put("phoneVerified", true); rawBody = JSON.writeValueAsString(receipt);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.supersedeSignup(original,
        "a".repeat(64), "b".repeat(64), "c".repeat(64), correction, replacement, "d".repeat(64), "e".repeat(64)));
  }

  private void directoryResponse(Map<String, Object> response, int count) {
    var caller = new LinkedHashMap<String, Object>();
    for (String field : List.of("memberId", "approvalEpoch", "signalOperationId", "jti", "aci")) caller.put(field, response.get(field));
    Object nonce = response.get("requestNonce");
    Object target = response.get("targetAci");
    var rows = new ArrayList<Map<String, Object>>();
    for (int index = 0; index < count; index++) {
      var row = new LinkedHashMap<>(caller);
      row.put("aci", target == null ? UUID.randomUUID().toString() : target);
      row.put("confirmedAt", clock.millis() - 1000);
      row.put("fullName", "Synthetic " + "x".repeat(90));
      row.put("graduationYear", 2005);
      rows.add(row);
    }
    response.clear();
    response.put("caller", caller); response.put("requestNonce", nonce); response.put("status", "confirmed");
    response.put("checkedAt", clock.millis()); response.put("validUntil", clock.millis() + 4000);
    response.put("members", rows); response.put("nextOffset", count == 20 ? 20 : null);
  }

  @Test void directoryUsesExactCallerAndBodyOnlyQueryWithLargerBoundedBatch() throws Exception {
    mutate = response -> {
      directoryResponse(response, 20);
      assertThat(JSON.valueToTree(response).toString().getBytes(StandardCharsets.UTF_8).length)
          .isGreaterThan(AdmissionServiceClient.MAX_RESPONSE_BYTES).isLessThan(AdmissionServiceClient.MAX_DIRECTORY_RESPONSE_BYTES);
    };
    var page = client.directory(binding, "Synthetic 2005", 0, null);
    assertThat(page.members).hasSize(20);
    assertThat(page.nextOffset).isEqualTo(20);
    assertThat(requests.getLast().uri().getPath()).isEqualTo("/internal/v1/admission/directory-search");
    assertThat(requests.getLast().uri().getQuery()).isNull();
    assertThat(bodies.getLast().size()).isEqualTo(8);
    assertThat(bodies.getLast().get("query").textValue()).isEqualTo("Synthetic 2005");
    nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(4000));
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, page::requireFresh);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, page.members.getFirst().entitlement()::requireFresh);
  }

  @Test void directoryNeverRenewsOriginalBudgetForEmptyOrDelayedResponses() {
    mutate = response -> directoryResponse(response, 0);
    var empty = client.directory(binding, "", 0, null);
    assertThat(empty.members).isEmpty();
    nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(4000));
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, empty::requireFresh);
    responseDelay = () -> nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(4000));
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.directory(binding, "", 0, null));
  }

  @Test void directoryRejectsChangedCallerNoncePaginationAndMetadata() {
    for (String bad : List.of("caller", "nonce", "status", "name", "year", "aci", "unknown", "duplicate", "offset", "deadline")) {
      mutate = response -> {
        directoryResponse(response, 1);
        @SuppressWarnings("unchecked") var rows = (List<Map<String, Object>>) response.get("members");
        switch (bad) {
          case "caller" -> {
            @SuppressWarnings("unchecked") var caller = (Map<String, Object>) response.get("caller");
            caller.put("aci", UUID.randomUUID().toString());
          }
          case "nonce" -> response.put("requestNonce", AdmissionTestData.id());
          case "status" -> response.put("status", "pending");
          case "name" -> rows.getFirst().put("fullName", "bad\nname");
          case "year" -> rows.getFirst().put("graduationYear", 3000);
          case "aci" -> rows.getFirst().put("aci", "1-1-1-1-1");
          case "unknown" -> rows.getFirst().put("phoneNumber", "+10000000000");
          case "duplicate" -> rows.add(rows.getFirst());
          case "offset" -> response.put("nextOffset", 20);
          case "deadline" -> response.put("validUntil", clock.millis() + 4001);
        }
      };
      assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.directory(binding, "", 0, null), bad);
    }
  }

  @Test void directoryResolveBindsExactTargetAndNeverPages() {
    var target = UUID.randomUUID();
    mutate = response -> directoryResponse(response, 1);
    assertThat(client.directory(binding, null, null, target).members.getFirst().entitlement().binding().aci()).isEqualTo(target);
    assertThat(bodies.getLast().size()).isEqualTo(7);
    assertThat(requests.getLast().uri().getPath()).endsWith("/directory-resolve");
    mutate = response -> {
      directoryResponse(response, 1);
      @SuppressWarnings("unchecked") var rows = (List<Map<String, Object>>) response.get("members");
      rows.getFirst().put("aci", UUID.randomUUID().toString());
    };
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.directory(binding, null, null, target));
  }

  @Test void directoryStillRejectsOversizedAndDuplicateKeyPrivateResponses() {
    mutate = response -> directoryResponse(response, 1);
    rawTransform = value -> value + " ".repeat(AdmissionServiceClient.MAX_DIRECTORY_RESPONSE_BYTES);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.directory(binding, "", 0, null));
    rawTransform = value -> value.replace("\"status\":\"confirmed\"", "\"status\":\"confirmed\",\"status\":\"confirmed\"");
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> client.directory(binding, "", 0, null));
  }

  private AdmissionServiceClient newClient(
      AdmissionServiceClient.TokenProvider token, AdmissionServiceConfiguration config) {
    return new AdmissionServiceClient(config, http, token, clock, nanos::get, new SecureRandom());
  }

  @AfterEach
  void close() {
    client.close();
    Thread.interrupted();
  }

  private static JsonNode requestBody(HttpRequest request) throws Exception {
    var result = new CompletableFuture<byte[]>();
    request
        .bodyPublisher()
        .orElseThrow()
        .subscribe(
            new Flow.Subscriber<ByteBuffer>() {
              final ByteArrayOutputStream out = new ByteArrayOutputStream();

              public void onSubscribe(Flow.Subscription s) {
                s.request(Long.MAX_VALUE);
              }

              public void onNext(ByteBuffer buffer) {
                byte[] part = new byte[buffer.remaining()];
                buffer.get(part);
                out.writeBytes(part);
              }

              public void onError(Throwable e) {
                result.completeExceptionally(e);
              }

              public void onComplete() {
                result.complete(out.toByteArray());
              }
            });
    return JSON.readTree(result.get(1, TimeUnit.SECONDS));
  }

  private AdmissionServiceClient.AdmissionServiceException rejects() {
    var e =
        assertThrows(
            AdmissionServiceClient.AdmissionServiceException.class,
            () -> client.currentEntitlement(binding));
    assertThat(e.getMessage()).isEqualTo("Private admission unavailable");
    assertThat(e.getCause()).isNull();
    return e;
  }

  @Test
  void postsExactTupleToPinnedPathsWithNewNonceAndCredentialPerRequest() throws Exception {
    var confirmation = client.confirm(binding);
    var entitlement = client.currentEntitlement(binding);
    assertThat(confirmation.binding()).isEqualTo(binding);
    assertThat(entitlement.isFresh()).isTrue();
    assertThat(credentialCalls.get()).isEqualTo(2);
    assertThat(requests.get(0).uri().toString())
        .isEqualTo(
            AdmissionServiceConfiguration.PILOT_ORIGIN + "/internal/v1/admission/confirmations");
    assertThat(requests.get(1).uri().toString())
        .isEqualTo(
            AdmissionServiceConfiguration.PILOT_ORIGIN + "/internal/v1/admission/entitlements");
    for (int i = 0; i < 2; i++) {
      var request = requests.get(i);
      var body = bodies.get(i);
      assertThat(request.method()).isEqualTo("POST");
      assertThat(request.headers().firstValue("Authorization")).contains("Bearer " + TOKEN);
      assertThat(body.size()).isEqualTo(6);
      assertThat(body.get("memberId").textValue()).isEqualTo(binding.memberId().toString());
      assertThat(body.get("approvalEpoch").longValue()).isEqualTo(1);
      assertThat(body.get("jti").textValue()).isEqualTo(binding.permitId());
      assertThat(body.get("aci").textValue()).isEqualTo(binding.aci().toString());
      assertThat(body.get("requestNonce").textValue()).matches("[A-Za-z0-9_-]{43}");
    }
    assertThat(bodies.get(0).get("requestNonce")).isNotEqualTo(bodies.get(1).get("requestNonce"));
    assertThat(confirmation.toString()).isEqualTo("FreshEntitlement[redacted]");
    assertThat(binding.toString()).isEqualTo("AdmissionBinding[redacted]");
    assertThat(AdmissionServiceClient.FreshEntitlement.class.getDeclaredConstructors())
        .allMatch(c -> java.lang.reflect.Modifier.isPrivate(c.getModifiers()));
  }

  @Test
  void entitlementReceiptCannotBeUsedAsPendingAccountConfirmation() {
    var confirmed = client.confirm(binding);
    confirmed.requireFreshConfirmation();
    assertThat(confirmed.purpose()).isEqualTo(AdmissionServiceClient.ReceiptPurpose.CONFIRMATION);
    var entitled = client.currentEntitlement(binding);
    entitled.requireFresh();
    assertThat(entitled.purpose())
        .isEqualTo(AdmissionServiceClient.ReceiptPurpose.CURRENT_ENTITLEMENT);
    assertThrows(
        AdmissionServiceClient.AdmissionServiceException.class, entitled::requireFreshConfirmation);
    nanos.addAndGet(TimeUnit.SECONDS.toNanos(4));
    assertThrows(
        AdmissionServiceClient.AdmissionServiceException.class,
        confirmed::requireFreshConfirmation);
  }

  @Test
  void everyBindingNonceAndStatusMismatchFailsClosed() {
    for (String field :
        List.of(
            "memberId",
            "approvalEpoch",
            "signalOperationId",
            "jti",
            "aci",
            "requestNonce",
            "status")) {
      mutate = body -> body.put(field, field.equals("approvalEpoch") ? 2L : "wrong");
      assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.INVALID_RESPONSE);
    }
  }

  @Test
  void priorReceiptCannotReplayOnFreshNonce() {
    client.currentEntitlement(binding);
    String previous = bodies.getFirst().get("requestNonce").textValue();
    mutate = body -> body.put("requestNonce", previous);
    rejects();
  }

  @Test
  void lifetimeStartsBeforeCredentialFetchAndNetworkDelayRatherThanResponseArrival() {
    client.close();
    client =
        newClient(
            () -> {
              nanos.addAndGet(TimeUnit.SECONDS.toNanos(1));
              return TOKEN;
            },
            AdmissionServiceConfiguration.pilot());
    responseDelay = () -> nanos.addAndGet(TimeUnit.SECONDS.toNanos(2));
    var result = client.currentEntitlement(binding);
    assertThat(result.isFresh()).isTrue();
    assertThat(requests.getFirst().timeout()).contains(Duration.ofSeconds(3));
    nanos.addAndGet(TimeUnit.SECONDS.toNanos(1));
    assertThat(result.isFresh()).isFalse();
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, result::requireFresh);
  }

  @Test
  void lateCredentialResultCannotDispatchHttpAndLateHttpReceiptCannotBeAccepted() {
    client.close();
    client =
        newClient(
            () -> {
              nanos.addAndGet(TimeUnit.SECONDS.toNanos(4));
              return TOKEN;
            },
            AdmissionServiceConfiguration.pilot());
    assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
    assertThat(requests).isEmpty();
    client.close();
    nanos.set(0);
    client = newClient(() -> TOKEN, AdmissionServiceConfiguration.pilot());
    responseDelay = () -> nanos.addAndGet(TimeUnit.SECONDS.toNanos(4));
    assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
  }

  @Test
  void shorterRemoteLeaseAndWallExpiryConservativelyShortenFreshness() {
    mutate = body -> body.put("validUntil", clock.millis() + 1000);
    var receipt = client.currentEntitlement(binding);
    nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(1000));
    assertThat(receipt.isFresh()).isFalse();
    nanos.set(0);
    var second = client.currentEntitlement(binding);
    clock.incrementMillis(1000);
    assertThat(second.isFresh()).isFalse();
  }

  @Test
  void wallClockRollbackDoesNotExtendMonotonicFreshness() {
    var receipt = client.currentEntitlement(binding);
    clock.incrementMillis(-100000);
    nanos.addAndGet(TimeUnit.SECONDS.toNanos(4));
    assertThat(receipt.isFresh()).isFalse();
  }

  @Test
  void strictTimestampTypesBoundsAndFutureSkewAreEnforced() {
    for (Consumer<Map<String, Object>> change :
        List.<Consumer<Map<String, Object>>>of(
            b -> b.put("checkedAt", "1"),
            b -> b.put("checkedAt", 1.0),
            b -> b.put("checkedAt", -1),
            b -> b.put("validUntil", 9_007_199_254_740_992L),
            b -> b.put("validUntil", clock.millis()),
            b -> b.put("validUntil", clock.millis() + 4001),
            b -> b.put("confirmedAt", clock.millis() + 1),
            b -> {
              b.put("checkedAt", clock.millis() + 5001);
              b.put("validUntil", clock.millis() + 9001);
            })) {
      mutate = change;
      rejects();
    }
  }

  @Test
  void duplicateUnknownMissingFieldsAndTrailingDocumentsAreRejected() throws Exception {
    mutate = b -> b.put("extra", true);
    rejects();
    mutate = b -> b.remove("aci");
    rejects();
    mutate = b -> {};
    rawTransform = json -> json.substring(0, json.length() - 1) + ",\"status\":\"confirmed\"}";
    rejects();
    rawTransform = json -> json + " {}";
    rejects();
  }

  @Test
  void invalidUtf8CompressedOversizedAndWrongContentTypeResponsesAreRejected() {
    rawBytes = new byte[] {(byte) 0xc3, (byte) 0x28};
    rejects();
    rawBytes = new byte[8193];
    rejects();
    rawBytes = null;
    encoding = "gzip";
    rejects();
    encoding = null;
    contentType = "text/plain";
    rejects();
    contentType = null;
    rejects();
    contentType = "application/json";
    responseUri = URI.create("https://other.invalid/");
    rejects();
  }

  @Test
  void nonSuccessIncludingRedirectNeverGrantsEntitlementAndNeverRetries() {
    for (int code : List.of(201, 204, 301, 302, 400, 401, 403, 404, 409, 429, 500, 503)) {
      status = code;
      rejects();
    }
    assertThat(requests).hasSize(12);
  }

  @Test
  void tokenErrorsAndRawTransportDetailsNeverEscape() {
    client.close();
    client =
        newClient(
            () -> {
              throw new IOException("secret-token-private-body");
            },
            AdmissionServiceConfiguration.pilot());
    assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.CREDENTIALS);
    assertThat(requests).isEmpty();
    client.close();
    client =
        newClient(() -> "token\r\nAuthorization: secret", AdmissionServiceConfiguration.pilot());
    rejects();
    assertThat(requests).isEmpty();
  }

  @Test
  void requestTimeoutCancelsHungResponseAndDoesNotRetry() throws Exception {
    client.close();
    client =
        newClient(
            () -> TOKEN,
            new AdmissionServiceConfiguration(
                AdmissionServiceConfiguration.PILOT_ORIGIN, Duration.ofMillis(30)));
    var pending = new CompletableFuture<HttpResponse<byte[]>>();
    when(http.sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenReturn(pending);
    assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
    assertThat(pending.isCancelled()).isTrue();
    verify(http, times(1))
        .sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any());
  }

  @Test
  void interruptedCallerRestoresInterruptFlagAndCannotAuthorize() {
    Thread.currentThread().interrupt();
    assertThat(rejects().failure()).isEqualTo(AdmissionServiceClient.Failure.TRANSPORT);
    assertThat(Thread.currentThread().isInterrupted()).isTrue();
  }

  @Test
  void configurationCannotRouteServiceCredentialsToOtherOriginsOrEnableRedirects() {
    for (String uri :
        List.of(
            "http://bconnected-admission-mk5xfhz7jq-ue.a.run.app",
            "https://other.a.run.app",
            "https://BCONNECTED-ADMISSION-MK5XFHZ7JQ-UE.a.run.app",
            AdmissionServiceConfiguration.PILOT_ORIGIN + "/",
            AdmissionServiceConfiguration.PILOT_ORIGIN + "?x=1",
            "https://user@bconnected-admission-mk5xfhz7jq-ue.a.run.app"))
      assertThrows(
          IllegalArgumentException.class,
          () -> new AdmissionServiceConfiguration(URI.create(uri), Duration.ofSeconds(4)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AdmissionServiceConfiguration(
                AdmissionServiceConfiguration.PILOT_ORIGIN, Duration.ofSeconds(5)));
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.ALWAYS);
    assertThrows(
        IllegalArgumentException.class,
        () -> newClient(() -> TOKEN, AdmissionServiceConfiguration.pilot()));
  }

  @Test
  void bodySubscriberCancelsBeforeBufferingOversizedStream() {
    var subscriber =
        AdmissionServiceClient.boundedBodyHandler().apply(mock(HttpResponse.ResponseInfo.class));
    var subscription = mock(Flow.Subscription.class);
    subscriber.onSubscribe(subscription);
    subscriber.onNext(List.of(ByteBuffer.allocate(8193)));
    verify(subscription).cancel();
    assertThrows(
        java.util.concurrent.CompletionException.class,
        () -> subscriber.getBody().toCompletableFuture().join());
  }
}
