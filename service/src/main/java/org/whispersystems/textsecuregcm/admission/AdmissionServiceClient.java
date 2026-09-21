// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;

/**
 * Private confirmation/current-entitlement transport only. A receipt is not an activation command:
 * callers must separately require the correct local admission ledger state and enforce revocation.
 */
public final class AdmissionServiceClient implements AutoCloseable {
  static final int MAX_RESPONSE_BYTES = 8192;
  private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;
  private static final Set<String> FIELDS =
      Set.of(
          "memberId",
          "approvalEpoch",
          "signalOperationId",
          "jti",
          "aci",
          "requestNonce",
          "status",
          "confirmedAt",
          "checkedAt",
          "validUntil");
  private static final ObjectMapper JSON =
      new ObjectMapper(
              JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final AdmissionServiceConfiguration configuration;
  private final HttpClient http;
  private final TokenProvider credentials;
  private final Clock clock;
  private final LongSupplier monotonic;
  private final SecureRandom random;
  private final ThreadPoolExecutor credentialExecutor;

  @FunctionalInterface
  interface TokenProvider {
    String token() throws IOException;
  }

  public enum ReceiptPurpose {
    CONFIRMATION,
    CURRENT_ENTITLEMENT
  }

  public enum Failure {
    CREDENTIALS,
    TRANSPORT,
    DENIED,
    INVALID_RESPONSE,
    EXPIRED
  }

  public static final class AdmissionServiceException extends RuntimeException {
    private final Failure failure;

    private AdmissionServiceException(Failure failure) {
      super("Private admission unavailable");
      this.failure = failure;
    }

    public Failure failure() {
      return failure;
    }
  }

  public record Binding(
      UUID memberId, long approvalEpoch, UUID signalOperationId, String permitId, UUID aci) {
    public Binding {
      uuid(memberId);
      uuid(signalOperationId);
      uuid(aci);
      if (approvalEpoch < 0 || approvalEpoch > MAX_SAFE_INTEGER)
        throw new IllegalArgumentException("Invalid admission binding");
      try {
        if (AdmissionPermitVerifier.decode(permitId, 32).length != 32)
          throw new IllegalArgumentException();
      } catch (RuntimeException ignored) {
        throw new IllegalArgumentException("Invalid admission binding");
      }
    }

    @Override
    public String toString() {
      return "AdmissionBinding[redacted]";
    }
  }

  /**
   * Private construction and an expiring monotonic lease prevent response-receipt time from
   * renewing freshness.
   */
  public static final class FreshEntitlement {
    private final Binding binding;
    private final ReceiptPurpose purpose;
    private final long confirmedAt, checkedAt, validUntil, startNanos, budgetNanos;
    private final LongSupplier monotonic;
    private final Clock clock;

    private FreshEntitlement(
        Binding binding,
        ReceiptPurpose purpose,
        long confirmedAt,
        long checkedAt,
        long validUntil,
        long startNanos,
        long budgetNanos,
        LongSupplier monotonic,
        Clock clock) {
      this.binding = binding;
      this.purpose = purpose;
      this.confirmedAt = confirmedAt;
      this.checkedAt = checkedAt;
      this.validUntil = validUntil;
      this.startNanos = startNanos;
      this.budgetNanos = budgetNanos;
      this.monotonic = monotonic;
      this.clock = clock;
    }

    public Binding binding() {
      return binding;
    }

    public ReceiptPurpose purpose() {
      return purpose;
    }

    /** A current-entitlement read never substitutes for pending-account confirmation. */
    public void requireFreshConfirmation() {
      if (purpose != ReceiptPurpose.CONFIRMATION) throw failure(Failure.DENIED);
      requireFresh();
    }

    public long confirmedAtMillis() {
      return confirmedAt;
    }

    public long checkedAtMillis() {
      return checkedAt;
    }

    public long validUntilMillis() {
      return validUntil;
    }

    public boolean isFresh() {
      long elapsed = monotonic.getAsLong() - startNanos;
      return elapsed >= 0 && elapsed < budgetNanos && clock.millis() < validUntil;
    }

    public void requireFresh() {
      if (!isFresh()) throw failure(Failure.EXPIRED);
    }

    @Override
    public String toString() {
      return "FreshEntitlement[redacted]";
    }
  }

  public static AdmissionServiceClient applicationDefault(
      AdmissionServiceConfiguration configuration) {
    try {
      var credentials = AdmissionServiceCredentials.applicationDefault(configuration);
      return new AdmissionServiceClient(
          configuration,
          HttpClient.newBuilder()
              .connectTimeout(configuration.requestTimeout())
              .followRedirects(HttpClient.Redirect.NEVER)
              .build(),
          credentials,
          Clock.systemUTC(),
          System::nanoTime,
          new SecureRandom());
    } catch (IOException ignored) {
      throw failure(Failure.CREDENTIALS);
    }
  }

  AdmissionServiceClient(
      AdmissionServiceConfiguration configuration,
      HttpClient http,
      TokenProvider credentials,
      Clock clock,
      LongSupplier monotonic,
      SecureRandom random) {
    this.configuration = Objects.requireNonNull(configuration);
    this.http = Objects.requireNonNull(http);
    if (http.followRedirects() != HttpClient.Redirect.NEVER || http.cookieHandler().isPresent())
      throw new IllegalArgumentException(
          "Private admission HTTP client must disable redirects and cookies");
    this.credentials = Objects.requireNonNull(credentials);
    this.clock = Objects.requireNonNull(clock);
    this.monotonic = Objects.requireNonNull(monotonic);
    this.random = Objects.requireNonNull(random);
    credentialExecutor =
        new ThreadPoolExecutor(
            0,
            4,
            15,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(16),
            Thread.ofPlatform().daemon().name("admission-id-token-", 0).factory(),
            new ThreadPoolExecutor.AbortPolicy());
  }

  public FreshEntitlement confirm(Binding binding) {
    return request("confirmations", ReceiptPurpose.CONFIRMATION, binding);
  }

  public FreshEntitlement currentEntitlement(Binding binding) {
    return request("entitlements", ReceiptPurpose.CURRENT_ENTITLEMENT, binding);
  }

  private FreshEntitlement request(String path, ReceiptPurpose purpose, Binding binding) {
    Objects.requireNonNull(binding);
    // Include credential lookup/refresh in the maximum freshness budget, never just HTTP body time.
    long startNanos = monotonic.getAsLong(), startMillis = clock.millis();
    long timeoutNanos = configuration.requestTimeout().toNanos();
    byte[] nonceBytes = new byte[32];
    random.nextBytes(nonceBytes);
    String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    Future<String> tokenFuture = null;
    CompletableFuture<HttpResponse<byte[]>> responseFuture = null;
    try {
      try {
        tokenFuture = credentialExecutor.submit(credentials::token);
      } catch (RuntimeException ignored) {
        throw failure(Failure.CREDENTIALS);
      }
      final String token;
      try {
        token = tokenFuture.get(remaining(startNanos, timeoutNanos), TimeUnit.NANOSECONDS);
      } catch (ExecutionException ignored) {
        throw failure(Failure.CREDENTIALS);
      }
      if (token == null
          || token.length() > 4096
          || !token.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"))
        throw failure(Failure.CREDENTIALS);
      byte[] body =
          JSON.writeValueAsBytes(
              Map.of(
                  "memberId",
                  binding.memberId.toString(),
                  "approvalEpoch",
                  binding.approvalEpoch,
                  "signalOperationId",
                  binding.signalOperationId.toString(),
                  "jti",
                  binding.permitId,
                  "aci",
                  binding.aci.toString(),
                  "requestNonce",
                  nonce));
      var uri = configuration.origin().resolve("/internal/v1/admission/" + path);
      var request =
          HttpRequest.newBuilder(uri)
              .timeout(Duration.ofNanos(remaining(startNanos, timeoutNanos)))
              .header("Authorization", "Bearer " + token)
              .header("Content-Type", "application/json")
              .header("Accept", "application/json")
              .POST(HttpRequest.BodyPublishers.ofByteArray(body))
              .build();
      responseFuture = http.sendAsync(request, boundedBodyHandler());
      HttpResponse<byte[]> response =
          responseFuture.get(remaining(startNanos, timeoutNanos), TimeUnit.NANOSECONDS);
      remaining(startNanos, timeoutNanos);
      if (response.statusCode() != 200)
        throw failure(
            Set.of(400, 401, 403, 404, 409, 429).contains(response.statusCode())
                ? Failure.DENIED
                : Failure.TRANSPORT);
      if (!uri.equals(response.uri())
          || response.previousResponse().isPresent()
          || response.body() == null
          || response.body().length > MAX_RESPONSE_BYTES
          || response.headers().firstValue("Content-Encoding").isPresent()
          || !response
              .headers()
              .firstValue("Content-Type")
              .orElse("")
              .matches("(?i)application/json(?:\\s*;\\s*charset=utf-8)?"))
        throw failure(Failure.INVALID_RESPONSE);
      String text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(response.body()))
              .toString();
      JsonNode json = JSON.readTree(text);
      exact(json);
      if (!text(json, "memberId").equals(binding.memberId.toString())
          || integer(json, "approvalEpoch") != binding.approvalEpoch
          || !text(json, "signalOperationId").equals(binding.signalOperationId.toString())
          || !text(json, "jti").equals(binding.permitId)
          || !text(json, "aci").equals(binding.aci.toString())
          || !text(json, "requestNonce").equals(nonce)
          || !text(json, "status").equals("confirmed")) throw failure(Failure.INVALID_RESPONSE);
      long confirmed = integer(json, "confirmedAt"),
          checked = integer(json, "checkedAt"),
          valid = integer(json, "validUntil"),
          now = clock.millis();
      if (confirmed > checked || valid <= checked || valid - checked > 4000 || checked > now + 5000)
        throw failure(Failure.INVALID_RESPONSE);
      if (valid <= now || valid <= startMillis) throw failure(Failure.EXPIRED);
      long budget =
          TimeUnit.MILLISECONDS.toNanos(
              Math.min(4000, Math.min(valid - checked, valid - startMillis)));
      var receipt =
          new FreshEntitlement(
              binding, purpose, confirmed, checked, valid, startNanos, budget, monotonic, clock);
      receipt.requireFresh();
      return receipt;
    } catch (AdmissionServiceException failure) {
      throw failure;
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
      throw failure(Failure.TRANSPORT);
    } catch (TimeoutException ignored) {
      throw failure(Failure.EXPIRED);
    } catch (ExecutionException ignored) {
      throw failure(Failure.TRANSPORT);
    } catch (IOException | RuntimeException ignored) {
      throw failure(Failure.INVALID_RESPONSE);
    } finally {
      if (tokenFuture != null && !tokenFuture.isDone()) tokenFuture.cancel(true);
      if (responseFuture != null && !responseFuture.isDone()) responseFuture.cancel(true);
    }
  }

  private long remaining(long start, long budget) {
    long elapsed = monotonic.getAsLong() - start;
    if (elapsed < 0 || elapsed >= budget) throw failure(Failure.EXPIRED);
    return budget - elapsed;
  }

  private static void exact(JsonNode value) {
    if (value == null || !value.isObject()) throw failure(Failure.INVALID_RESPONSE);
    var fields = new HashSet<String>();
    value.fieldNames().forEachRemaining(fields::add);
    if (!fields.equals(FIELDS)) throw failure(Failure.INVALID_RESPONSE);
  }

  private static String text(JsonNode object, String field) {
    var value = object.get(field);
    if (value == null || !value.isTextual()) throw failure(Failure.INVALID_RESPONSE);
    return value.textValue();
  }

  private static long integer(JsonNode object, String field) {
    var value = object.get(field);
    if (value == null
        || !value.isIntegralNumber()
        || !value.canConvertToLong()
        || value.longValue() < 0
        || value.longValue() > MAX_SAFE_INTEGER) throw failure(Failure.INVALID_RESPONSE);
    return value.longValue();
  }

  private static void uuid(UUID id) {
    if (id == null || id.equals(new UUID(0, 0)))
      throw new IllegalArgumentException("Invalid admission binding");
  }

  private static AdmissionServiceException failure(Failure kind) {
    return new AdmissionServiceException(kind);
  }

  @Override
  public void close() {
    credentialExecutor.shutdownNow();
    http.shutdownNow();
  }

  @Override
  public String toString() {
    return "AdmissionServiceClient[redacted]";
  }

  static HttpResponse.BodyHandler<byte[]> boundedBodyHandler() {
    return info ->
        new HttpResponse.BodySubscriber<>() {
          private final HttpResponse.BodySubscriber<byte[]> delegate =
              HttpResponse.BodySubscribers.ofByteArray();
          private Flow.Subscription subscription;
          private long received;
          private boolean done;

          @Override
          public CompletionStage<byte[]> getBody() {
            return delegate.getBody();
          }

          @Override
          public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            delegate.onSubscribe(value);
          }

          @Override
          public void onNext(List<ByteBuffer> buffers) {
            if (done) return;
            for (var value : buffers) received += value.remaining();
            if (received > MAX_RESPONSE_BYTES) {
              done = true;
              subscription.cancel();
              delegate.onError(new IOException("Admission response exceeds limit"));
            } else delegate.onNext(buffers);
          }

          @Override
          public void onError(Throwable error) {
            if (!done) {
              done = true;
              delegate.onError(error);
            }
          }

          @Override
          public void onComplete() {
            if (!done) {
              done = true;
              delegate.onComplete();
            }
          }
        };
  }
}
