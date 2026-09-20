// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.function.Supplier;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Telnyx Verify v2 SMS transport. All operations make exactly one HTTP request; ambiguous sends are never retried.
 * The registration coordinator must persist its own session, attempt limits and provider verification ID.
 */
public final class TelnyxVerifyClient implements AutoCloseable {
  static final int MAX_RESPONSE_BYTES = 64 * 1024;
  private static final URI ENDPOINT = URI.create("https://api.telnyx.com/v2/");
  private final HttpClient client;
  private final Supplier<String> apiKey;
  private final UUID profileId;
  private final int lifetimeSeconds;
  private final Clock clock;

  /** A send receipt, never a proof that the user supplied a correct code. */
  public record Verification(UUID id, String phoneNumber, int timeoutSeconds) {}

  public TelnyxVerifyClient(final UUID verifyProfileId, final Supplier<String> apiKeySupplier,
      final Duration verificationLifetime) {
    this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER).build(), verifyProfileId, apiKeySupplier,
        verificationLifetime, Clock.systemUTC());
  }

  TelnyxVerifyClient(final HttpClient client, final UUID verifyProfileId, final Supplier<String> apiKeySupplier,
      final Duration verificationLifetime, final Clock clock) {
    this.client = Objects.requireNonNull(client);
    if (client.followRedirects() != HttpClient.Redirect.NEVER) {
      throw new IllegalArgumentException("Telnyx client must not follow redirects");
    }
    this.profileId = Objects.requireNonNull(verifyProfileId);
    this.apiKey = Objects.requireNonNull(apiKeySupplier);
    this.clock = Objects.requireNonNull(clock);
    validateVerificationLifetime(verificationLifetime);
    this.lifetimeSeconds = (int) verificationLifetime.toSeconds();
    validateApiKey(apiKeySupplier.get());
  }

  public Verification sendSms(final String e164, final Duration requestTimeout) throws TelnyxVerifyException {
    validatePhoneNumber(e164);
    JsonNode data = post("verifications/sms", Map.of("phone_number", e164,
        "verify_profile_id", profileId.toString(), "timeout_secs", lifetimeSeconds), requestTimeout);
    try {
      UUID id = UUID.fromString(requiredText(data, "id"));
      if (!requiredText(data, "phone_number").equals(e164)
          || !UUID.fromString(requiredText(data, "verify_profile_id")).equals(profileId)
          || !requiredText(data, "type").equals("sms")) throw invalidResponse();
      String status = requiredText(data, "status");
      if (!(status.equals("pending") || status.equals("accepted"))) throw invalidResponse();
      if (!data.path("timeout_secs").isIntegralNumber() || !data.path("timeout_secs").canConvertToInt()) throw invalidResponse();
      int actualLifetime = data.path("timeout_secs").intValue();
      if (actualLifetime < 1 || actualLifetime > lifetimeSeconds) throw invalidResponse();
      return new Verification(id, e164, actualLifetime);
    } catch (IllegalArgumentException e) {
      throw invalidResponse();
    }
  }

  public boolean verify(final UUID verificationId, final String expectedE164, final String code,
      final Duration requestTimeout) throws TelnyxVerifyException {
    Objects.requireNonNull(verificationId);
    validatePhoneNumber(expectedE164);
    if (code == null || !code.matches("[0-9]{4,10}")) throw new IllegalArgumentException("Invalid verification code format");
    // Do not send the optional 'status' field: that bypasses provider code checking for custom-code verifications.
    JsonNode data = post("verifications/" + verificationId + "/actions/verify", Map.of("code", code), requestTimeout);
    if (!requiredText(data, "phone_number").equals(expectedE164)) throw invalidResponse();
    if (data.has("id")) {
      try {
        if (!UUID.fromString(requiredText(data, "id")).equals(verificationId)) throw invalidResponse();
      } catch (IllegalArgumentException e) { throw invalidResponse(); }
    }
    return switch (requiredText(data, "response_code")) {
      case "accepted" -> true;
      case "rejected" -> false;
      default -> throw invalidResponse();
    };
  }

  private JsonNode post(final String path, final Map<String, ?> body, final Duration timeout) throws TelnyxVerifyException {
    if (timeout == null || timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofMinutes(1)) > 0) {
      throw new IllegalArgumentException("Telnyx request timeout must be positive and at most one minute");
    }
    final String token = apiKey.get();
    validateApiKey(token);
    final byte[] requestBody;
    try { requestBody = SystemMapper.jsonMapper().writeValueAsBytes(body); }
    catch (IOException e) { throw invalidResponse(); }
    final HttpRequest request = HttpRequest.newBuilder(ENDPOINT.resolve(path)).timeout(timeout)
        .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
        .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(requestBody)).build();
    final HttpResponse<byte[]> response;
    try {
      response = client.send(request, boundedBodyHandler());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw failure(TelnyxVerifyException.Reason.TRANSPORT_FAILURE, 0);
    } catch (IOException e) {
      throw failure(TelnyxVerifyException.Reason.TRANSPORT_FAILURE, 0);
    }
    if (response.body() == null || response.body().length > MAX_RESPONSE_BYTES) throw invalidResponse();
    JsonNode json;
    try { json = SystemMapper.jsonMapper().readTree(response.body()); }
    catch (IOException e) { json = null; }
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      TelnyxVerifyException.Reason reason = switch (response.statusCode()) {
        case 400, 422 -> TelnyxVerifyException.Reason.INVALID_REQUEST;
        case 401 -> TelnyxVerifyException.Reason.AUTHENTICATION;
        case 403 -> TelnyxVerifyException.Reason.REJECTED;
        case 404 -> TelnyxVerifyException.Reason.NOT_FOUND;
        case 429 -> TelnyxVerifyException.Reason.RATE_LIMITED;
        default -> response.statusCode() >= 500 ? TelnyxVerifyException.Reason.PROVIDER_UNAVAILABLE
            : TelnyxVerifyException.Reason.INVALID_RESPONSE;
      };
      Optional<String> providerCode = Optional.ofNullable(json).map(root -> root.path("errors").path(0).path("code"))
          .filter(JsonNode::isTextual).map(JsonNode::textValue).filter(value -> value.matches("[0-9]{5,6}"));
      throw new TelnyxVerifyException(reason, response.statusCode(), retryAfter(response), providerCode);
    }
    if (json == null || !json.path("data").isObject() || json.has("errors")) throw invalidResponse();
    return json.path("data");
  }

  private Optional<Duration> retryAfter(final HttpResponse<?> response) {
    return response.headers().firstValue("Retry-After").flatMap(value -> {
      try {
        Duration duration = value.matches("[0-9]{1,9}") ? Duration.ofSeconds(Long.parseLong(value))
            : Duration.between(clock.instant(), ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant());
        return duration.isNegative() ? Optional.of(Duration.ZERO) : Optional.of(duration);
      } catch (RuntimeException e) { return Optional.empty(); }
    });
  }

  private static String requiredText(final JsonNode data, final String key) throws TelnyxVerifyException {
    JsonNode value = data.path(key);
    if (!value.isTextual() || value.textValue().isBlank()) throw invalidResponse();
    return value.textValue();
  }

  private static TelnyxVerifyException invalidResponse() {
    return failure(TelnyxVerifyException.Reason.INVALID_RESPONSE, 0);
  }

  private static TelnyxVerifyException failure(final TelnyxVerifyException.Reason reason, final int status) {
    return new TelnyxVerifyException(reason, status, Optional.empty(), Optional.empty());
  }

  static void validateApiKey(final String key) {
    if (key == null || key.isBlank() || key.chars().anyMatch(character -> character < 33 || character > 126)) {
      throw new IllegalStateException("Telnyx API key environment secret is missing or invalid");
    }
  }

  static void validateVerificationLifetime(final Duration duration) {
    Objects.requireNonNull(duration, "Telnyx verification lifetime is required");
    if (duration.getNano() != 0 || duration.toSeconds() < 1 || duration.toSeconds() > 600) {
      throw new IllegalArgumentException("Telnyx verification lifetime must be a whole number of seconds from 1 to 600");
    }
  }

  private static void validatePhoneNumber(final String e164) {
    if (e164 == null || !e164.matches("\\+[1-9][0-9]{1,14}")) throw new IllegalArgumentException("E164 phone number required");
  }

  @Override
  public void close() {
    client.close();
  }

  static HttpResponse.BodyHandler<byte[]> boundedBodyHandler() {
    return info -> new HttpResponse.BodySubscriber<>() {
      private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
      private Flow.Subscription subscription;
      private long received;
      private boolean terminated;

      @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
      @Override public void onSubscribe(Flow.Subscription subscription) {
        this.subscription = subscription;
        delegate.onSubscribe(subscription);
      }
      @Override public void onNext(List<ByteBuffer> buffers) {
        if (terminated) return;
        for (ByteBuffer buffer : buffers) received += buffer.remaining();
        if (received > MAX_RESPONSE_BYTES) {
          terminated = true;
          subscription.cancel();
          delegate.onError(new IOException("Telnyx response exceeds maximum size"));
        } else delegate.onNext(buffers);
      }
      @Override public void onError(Throwable throwable) {
        if (!terminated) { terminated = true; delegate.onError(throwable); }
      }
      @Override public void onComplete() {
        if (!terminated) { terminated = true; delegate.onComplete(); }
      }
    };
  }
}
