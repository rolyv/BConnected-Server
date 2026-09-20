// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class TelnyxVerifyClientTest {
  private static final String KEY = "synthetic-test-key";
  private static final String PHONE = "+13055550123";
  private static final UUID PROFILE = UUID.fromString("12ade33a-21c0-473b-b055-b3c836e1c292");
  private static final UUID VERIFICATION = UUID.fromString("83dcc297-0722-410c-bcd6-10421cf4839b");
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
  private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-20T00:00:00Z"), ZoneOffset.UTC);
  private HttpClient http;
  private TelnyxVerifyClient client;

  @BeforeEach
  void setUp() {
    http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    client = new TelnyxVerifyClient(http, PROFILE, () -> KEY, Duration.ofMinutes(5), CLOCK);
  }

  private Map<String, Object> sendReceipt() {
    return Map.of("id", VERIFICATION.toString(), "type", "sms", "phone_number", PHONE,
        "verify_profile_id", PROFILE.toString(), "timeout_secs", 300, "status", "accepted");
  }

  @SuppressWarnings("unchecked")
  private void respond(final int status, final String json, final Map<String, List<String>> headers) throws Exception {
    HttpResponse<byte[]> response = mock(HttpResponse.class);
    when(response.statusCode()).thenReturn(status);
    when(response.body()).thenReturn(json.getBytes(StandardCharsets.UTF_8));
    when(response.headers()).thenReturn(HttpHeaders.of(headers, (key, value) -> true));
    when(http.send(any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any())).thenReturn(response);
  }

  private void respond(final Map<String, ?> data) throws Exception {
    respond(200, SystemMapper.jsonMapper().writeValueAsString(Map.of("data", data)), Map.of());
  }

  private HttpRequest request() throws Exception {
    ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
    verify(http).send(captor.capture(), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any());
    return captor.getValue();
  }

  private JsonNode requestBody(final HttpRequest request) throws Exception {
    var done = new CompletableFuture<byte[]>();
    request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
      private final ByteArrayOutputStream output = new ByteArrayOutputStream();
      @Override public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
      @Override public void onNext(ByteBuffer bytes) {
        byte[] copy = new byte[bytes.remaining()];
        bytes.get(copy);
        output.writeBytes(copy);
      }
      @Override public void onError(Throwable throwable) { done.completeExceptionally(throwable); }
      @Override public void onComplete() { done.complete(output.toByteArray()); }
    });
    return SystemMapper.jsonMapper().readTree(done.get(1, TimeUnit.SECONDS));
  }

  @Test
  void sendsTheOfficialSmsContractAndReturnsAReceiptWithoutClaimingVerification() throws Exception {
    respond(sendReceipt());
    assertThat(client.sendSms(PHONE, REQUEST_TIMEOUT))
        .isEqualTo(new TelnyxVerifyClient.Verification(VERIFICATION, PHONE, 300));
    HttpRequest request = request();
    assertThat(request.uri().toString()).isEqualTo("https://api.telnyx.com/v2/verifications/sms");
    assertThat(request.method()).isEqualTo("POST");
    assertThat(request.timeout()).contains(REQUEST_TIMEOUT);
    assertThat(request.headers().firstValue("Authorization")).contains("Bearer " + KEY);
    JsonNode body = requestBody(request);
    assertThat(body.size()).isEqualTo(3);
    assertThat(body.path("phone_number").asText()).isEqualTo(PHONE);
    assertThat(body.path("verify_profile_id").asText()).isEqualTo(PROFILE.toString());
    assertThat(body.path("timeout_secs").intValue()).isEqualTo(300);
    assertThat(body.has("custom_code")).isFalse();
    assertThat(body.has("status")).isFalse();
  }

  @Test
  void checksTheSpecificProviderVerificationAndOnlySubmitsTheUserCode() throws Exception {
    respond(Map.of("phone_number", PHONE, "response_code", "accepted"));
    assertThat(client.verify(VERIFICATION, PHONE, "012345", REQUEST_TIMEOUT)).isTrue();
    HttpRequest request = request();
    assertThat(request.uri().toString()).isEqualTo("https://api.telnyx.com/v2/verifications/" + VERIFICATION + "/actions/verify");
    assertThat(requestBody(request)).isEqualTo(SystemMapper.jsonMapper().readTree("{\"code\":\"012345\"}"));
  }

  @Test
  void explicitlyRejectedCodesRemainUnverified() throws Exception {
    respond(Map.of("phone_number", PHONE, "response_code", "rejected"));
    assertThat(client.verify(VERIFICATION, PHONE, "123456", REQUEST_TIMEOUT)).isFalse();
    request(); // Exactly one attempt; there is no implicit verification retry.
  }

  @Test
  void rejectsMismatchedProviderIdentityAndUnrecognizedSuccessBodies() throws Exception {
    List<Map<String, ?>> invalidChecks = List.of(
        Map.of("phone_number", "+13055550999", "response_code", "accepted"),
        Map.of("phone_number", PHONE, "response_code", "accepted", "id", UUID.randomUUID().toString()),
        Map.of("phone_number", PHONE, "response_code", "pending"),
        Map.of("phone_number", PHONE, "status", "accepted"));
    for (Map<String, ?> body : invalidChecks) {
      respond(body);
      assertThat(assertThrows(TelnyxVerifyException.class,
          () -> client.verify(VERIFICATION, PHONE, "123456", REQUEST_TIMEOUT)).reason())
          .isEqualTo(TelnyxVerifyException.Reason.INVALID_RESPONSE);
    }
  }

  @Test
  void sendReceiptMustMatchProfilePhoneTransportAndActualLifetime() throws Exception {
    var invalid = new ArrayList<Map<String, ?>>();
    for (Map.Entry<String, Object> change : Map.<String, Object>of("verify_profile_id", UUID.randomUUID().toString(),
        "phone_number", "+13055550999", "type", "call", "timeout_secs", 301, "id", "not-a-uuid").entrySet()) {
      var body = new java.util.HashMap<>(sendReceipt());
      body.put(change.getKey(), change.getValue());
      invalid.add(body);
    }
    var missingLifetime = new java.util.HashMap<>(sendReceipt());
    missingLifetime.remove("timeout_secs");
    invalid.add(missingLifetime);
    for (Map<String, ?> body : invalid) {
      respond(body);
      assertThat(assertThrows(TelnyxVerifyException.class, () -> client.sendSms(PHONE, REQUEST_TIMEOUT)).reason())
          .isEqualTo(TelnyxVerifyException.Reason.INVALID_RESPONSE);
    }
  }

  @Test
  void rateLimitsExposeSafeRetryMetadataAndDoNotRetry() throws Exception {
    respond(429, "{\"errors\":[{\"code\":\"80003\",\"detail\":\"sensitive provider text\"}]}",
        Map.of("Retry-After", List.of("45")));
    TelnyxVerifyException error = assertThrows(TelnyxVerifyException.class, () -> client.sendSms(PHONE, REQUEST_TIMEOUT));
    assertThat(error.reason()).isEqualTo(TelnyxVerifyException.Reason.RATE_LIMITED);
    assertThat(error.httpStatus()).isEqualTo(429);
    assertThat(error.retryAfter()).contains(Duration.ofSeconds(45));
    assertThat(error.providerCode()).contains("80003");
    assertThat(error.toString()).doesNotContain("sensitive provider text");
    request();
  }

  @Test
  void dateRetryHeadersAndAuthenticationFailuresRemainFailures() throws Exception {
    respond(503, "{}", Map.of("Retry-After", List.of("Sun, 20 Sep 2026 00:01:00 GMT")));
    TelnyxVerifyException unavailable = assertThrows(TelnyxVerifyException.class, () -> client.sendSms(PHONE, REQUEST_TIMEOUT));
    assertThat(unavailable.reason()).isEqualTo(TelnyxVerifyException.Reason.PROVIDER_UNAVAILABLE);
    assertThat(unavailable.retryAfter()).contains(Duration.ofSeconds(60));
    respond(401, "{\"errors\":[{\"detail\":\"" + KEY + " " + PHONE + " 123456\"}]}", Map.of());
    TelnyxVerifyException auth = assertThrows(TelnyxVerifyException.class,
        () -> client.verify(VERIFICATION, PHONE, "123456", REQUEST_TIMEOUT));
    assertThat(auth.reason()).isEqualTo(TelnyxVerifyException.Reason.AUTHENTICATION);
    assertThat(auth.toString()).doesNotContain(KEY, PHONE, "123456");
    assertThat(auth.getCause()).isNull();
    verify(http, times(2)).send(any(), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any());
  }

  @Test
  void ambiguousTransportFailuresAreRedactedAndNeverRetried() throws Exception {
    when(http.send(any(), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenThrow(new IOException("transport exception containing " + KEY));
    TelnyxVerifyException error = assertThrows(TelnyxVerifyException.class, () -> client.sendSms(PHONE, REQUEST_TIMEOUT));
    assertThat(error.reason()).isEqualTo(TelnyxVerifyException.Reason.TRANSPORT_FAILURE);
    assertThat(error.toString()).doesNotContain(KEY);
    assertThat(error.getCause()).isNull();
    request();
  }

  @Test
  void interruptedRequestsPreserveTheThreadInterrupt() throws Exception {
    when(http.send(any(), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any())).thenThrow(new InterruptedException());
    try {
      assertThrows(TelnyxVerifyException.class, () -> client.sendSms(PHONE, REQUEST_TIMEOUT));
      assertThat(Thread.currentThread().isInterrupted()).isTrue();
    } finally { Thread.interrupted(); }
    request();
  }

  @Test
  void malformedOversizeOrErrorBearingSuccessResponsesNeverVerify() throws Exception {
    for (String body : List.of("not json", "{}", "{\"data\":{\"phone_number\":\"" + PHONE
        + "\",\"response_code\":\"accepted\"},\"errors\":[]}", "x".repeat(TelnyxVerifyClient.MAX_RESPONSE_BYTES + 1))) {
      respond(200, body, Map.of());
      assertThat(assertThrows(TelnyxVerifyException.class,
          () -> client.verify(VERIFICATION, PHONE, "123456", REQUEST_TIMEOUT)).reason())
          .isEqualTo(TelnyxVerifyException.Reason.INVALID_RESPONSE);
    }
  }

  @Test
  void responseSubscriberCancelsBeforeBufferingMoreThanTheLimit() {
    HttpResponse.BodySubscriber<byte[]> subscriber = TelnyxVerifyClient.boundedBodyHandler()
        .apply(mock(HttpResponse.ResponseInfo.class));
    Flow.Subscription subscription = mock(Flow.Subscription.class);
    subscriber.onSubscribe(subscription);
    subscriber.onNext(List.of(ByteBuffer.wrap(new byte[TelnyxVerifyClient.MAX_RESPONSE_BYTES])));
    subscriber.onNext(List.of(ByteBuffer.wrap(new byte[1])));
    subscriber.onComplete();
    assertThrows(CompletionException.class, () -> subscriber.getBody().toCompletableFuture().join());
    verify(subscription).cancel();
  }

  @Test
  void configurationContainsOnlyASecretReferenceAndRejectsMissingSecretsAndUnsafeClients() {
    var config = new TelnyxVerifyConfiguration("BCONNECTED_TEST_NONEXISTENT_TELNYX_SECRET", PROFILE, null);
    assertThat(config.verificationTimeout()).isEqualTo(Duration.ofMinutes(5));
    assertThrows(IllegalStateException.class, config::build);
    assertThrows(IllegalStateException.class,
        () -> new TelnyxVerifyClient(http, PROFILE, () -> "secret\r\nInjected: bad", Duration.ofMinutes(5), CLOCK));
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.ALWAYS);
    assertThrows(IllegalArgumentException.class,
        () -> new TelnyxVerifyClient(http, PROFILE, () -> KEY, Duration.ofMinutes(5), CLOCK));
    assertThrows(IllegalArgumentException.class,
        () -> new TelnyxVerifyConfiguration("NOT AN ENV NAME", PROFILE, Duration.ofMinutes(5)));
    assertThrows(IllegalArgumentException.class,
        () -> new TelnyxVerifyConfiguration("TELNYX_API_KEY", PROFILE, Duration.ofSeconds(601)));
  }

  @Test
  void closeReleasesTheOwnedHttpClient() {
    client.close();
    verify(http).close();
  }
}
