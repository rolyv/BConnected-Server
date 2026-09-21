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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
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

    /** Confirmation can activate a pending account, but cannot grant current membership. */
    public void requireFreshCurrentEntitlement() {
      if (purpose != ReceiptPurpose.CURRENT_ENTITLEMENT) throw failure(Failure.DENIED);
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

  /** Eligibility for one immutable operation, not permission to create or activate an account. */
  public static final class FreshClaim {
    private final UUID memberId, operationId;
    private final long approvalEpoch, expiresAt, startNanos;
    private final LongSupplier monotonic;
    private final Clock clock;

    private FreshClaim(
        UUID memberId,
        UUID operationId,
        long approvalEpoch,
        long expiresAt,
        long startNanos,
        LongSupplier monotonic,
        Clock clock) {
      this.memberId = memberId;
      this.operationId = operationId;
      this.approvalEpoch = approvalEpoch;
      this.expiresAt = expiresAt;
      this.startNanos = startNanos;
      this.monotonic = monotonic;
      this.clock = clock;
    }

    public UUID memberId() {
      return memberId;
    }

    public UUID operationId() {
      return operationId;
    }

    public long approvalEpoch() {
      return approvalEpoch;
    }

    public long expiresAtMillis() {
      return expiresAt;
    }

    public void requireFresh() {
      long elapsed = monotonic.getAsLong() - startNanos;
      if (elapsed < 0 || elapsed >= TimeUnit.SECONDS.toNanos(4) || clock.millis() >= expiresAt)
        throw failure(Failure.EXPIRED);
    }

    void requireOperation(RegistrationOperations.AuthenticatedOperation operation) {
      if (!memberId.equals(operation.memberId()) || !operationId.equals(operation.operationId()))
        throw failure(Failure.INVALID_RESPONSE);
      requireFresh();
    }

    @Override
    public String toString() {
      return "FreshClaim[redacted]";
    }
  }

  public FreshClaim claim(
      RegistrationOperations.AuthenticatedOperation operation, String challenge) {
    Objects.requireNonNull(operation);
    try {
      if (AdmissionPermitVerifier.decode(challenge, 32).length != 32
          || !HexFormat.of()
              .formatHex(
                  MessageDigest.getInstance("SHA-256")
                      .digest(challenge.getBytes(StandardCharsets.US_ASCII)))
              .equals(operation.challengeHash())) throw failure(Failure.DENIED);
      var response =
          exchange(
              "claims",
              Map.of(
                  "memberId",
                  operation.memberId().toString(),
                  "signalOperationId",
                  operation.operationId().toString(),
                  "bindingChallenge",
                  challenge,
                  "registrationAttemptHash",
                  operation.registrationAttemptHash(),
                  "deviceKeyCommitment",
                  operation.deviceKeyCommitment(),
                  "serverRequestCommitment",
                  operation.serverRequestCommitment()));
      JsonNode json = response.json();
      exact(
          json,
          Set.of(
              "signalOperationId",
              "memberId",
              "approvalEpoch",
              "expiresAt",
              "status",
              "registrationAuthorized"));
      if (!text(json, "signalOperationId").equals(operation.operationId().toString())
          || !text(json, "memberId").equals(operation.memberId().toString())
          || !text(json, "status").equals("claimed")
          || !json.get("registrationAuthorized").isBoolean()
          || json.get("registrationAuthorized").booleanValue())
        throw failure(Failure.INVALID_RESPONSE);
      long expires = integer(json, "expiresAt");
      if (expires > operation.expiresAtMillis()) throw failure(Failure.INVALID_RESPONSE);
      var claim =
          new FreshClaim(
              operation.memberId(),
              operation.operationId(),
              integer(json, "approvalEpoch"),
              expires,
              response.startNanos(),
              monotonic,
              clock);
      claim.requireFresh();
      return claim;
    } catch (AdmissionServiceException e) {
      throw e;
    } catch (Exception ignored) {
      throw failure(Failure.INVALID_RESPONSE);
    }
  }

  public AdmissionPermitVerifier.VerifiedPermit attest(
      RegistrationOperations.AuthenticatedOperation operation,
      FreshClaim claim,
      RegistrationOperations.VerifiedPhone phone,
      String phoneBinding,
      AdmissionPermitVerifier verifier) {
    Objects.requireNonNull(operation);
    Objects.requireNonNull(claim);
    Objects.requireNonNull(phone);
    claim.requireOperation(operation);
    if (!operation.operationId().equals(phone.operationId())
        || !operation.requestedNumber().equals(phone.canonicalNumber())
        || phone.observedAtMillis() < clock.millis() - 30000
        || phone.observedAtMillis() > clock.millis() + 5000
        || phone.sessionExpiresAtMillis() <= clock.millis()) throw failure(Failure.DENIED);
    var expected =
        new AdmissionPermitVerifier.ExpectedBinding(
            operation.memberId(),
            claim.approvalEpoch(),
            operation.operationId(),
            operation.registrationAttemptHash(),
            phone.serverVerificationSessionHash(),
            operation.deviceKeyCommitment(),
            phoneBinding,
            operation.serverRequestCommitment(),
            phone.canonicalNumber());
    var response =
        exchange(
            "attestations",
            Map.of(
                "memberId",
                operation.memberId().toString(),
                "signalOperationId",
                operation.operationId().toString(),
                "registrationAttemptHash",
                operation.registrationAttemptHash(),
                "deviceKeyCommitment",
                operation.deviceKeyCommitment(),
                "serverRequestCommitment",
                operation.serverRequestCommitment(),
                "serverVerificationSessionHash",
                phone.serverVerificationSessionHash(),
                "phoneBinding",
                phoneBinding,
                "sessionExpiresAt",
                phone.sessionExpiresAtMillis(),
                "observedAt",
                phone.observedAtMillis()));
    exact(response.json(), Set.of("assertion", "permitId", "expiresAt"));
    var permit = verifier.verify(text(response.json(), "assertion"), expected);
    long expires = integer(response.json(), "expiresAt");
    if (!text(response.json(), "permitId").equals(permit.permitId())
        || expires != Math.multiplyExact(permit.expiresAt(), 1000)
        || expires > claim.expiresAtMillis()
        || expires > phone.sessionExpiresAtMillis()) throw failure(Failure.INVALID_RESPONSE);
    return permit;
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
    byte[] nonceBytes = new byte[32];
    random.nextBytes(nonceBytes);
    String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    var response =
        exchange(
            path,
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
    JsonNode json = response.json();
    exact(json, FIELDS);
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
    if (valid <= now || valid <= response.startMillis()) throw failure(Failure.EXPIRED);
    long budget =
        TimeUnit.MILLISECONDS.toNanos(
            Math.min(4000, Math.min(valid - checked, valid - response.startMillis())));
    var receipt =
        new FreshEntitlement(
            binding,
            purpose,
            confirmed,
            checked,
            valid,
            response.startNanos(),
            budget,
            monotonic,
            clock);
    receipt.requireFresh();
    return receipt;
  }

  private record Exchange(JsonNode json, long startNanos, long startMillis) {
    @Override
    public String toString() {
      return "AdmissionExchange[redacted]";
    }
  }

  private Exchange exchange(String path, Map<String, Object> requestBody) {
    long startNanos = monotonic.getAsLong(), startMillis = clock.millis();
    long timeoutNanos = configuration.requestTimeout().toNanos();
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
      byte[] body = JSON.writeValueAsBytes(requestBody);
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
      return new Exchange(json, startNanos, startMillis);
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

  private static void exact(JsonNode value, Set<String> expected) {
    if (value == null || !value.isObject()) throw failure(Failure.INVALID_RESPONSE);
    var fields = new HashSet<String>();
    value.fieldNames().forEachRemaining(fields::add);
    if (!fields.equals(expected)) throw failure(Failure.INVALID_RESPONSE);
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
