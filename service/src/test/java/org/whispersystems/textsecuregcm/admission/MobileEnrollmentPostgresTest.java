// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;
import org.whispersystems.textsecuregcm.admission.enrollment.*;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxVerifyException;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.VirtualExecutorServiceProvider;

/** Actual unregistered REST adapter, native SQL operations/accounts and synthetic phone/issuer IO. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class MobileEnrollmentPostgresTest {
  AdmissionAccountCreatorPostgresTest accounts;
  AdmissionRegistrationCoordinatorPostgresTest flow;
  AdmissionServiceClient entitlementClient;
  MobileEnrollmentBodyReader bodies;
  ApplicationHandler jersey;
  ObjectNode envelope;
  AtomicInteger entitlementReads = new AtomicInteger();
  Runnable duringEntitlement = () -> {};
  int entitlementStatus = 200;
  String password = AdmissionRegistrationCoordinatorPostgresTest.PASSWORD;
  String currentUserAgent = "BConnected/current-upgrade";
  Set<UUID> allowedMembers;

  @BeforeEach void setup() throws Exception {
    accounts = new AdmissionAccountCreatorPostgresTest();
    accounts.setup();
    flow = accounts.flow;
    try (var input = getClass().getResourceAsStream("/admission/mobile-enrollment-v1.json")) {
      envelope = (ObjectNode) SystemMapper.jsonMapper().readTree(input);
    }
    var http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    when(http.cookieHandler()).thenReturn(Optional.empty());
    when(http.sendAsync(any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenAnswer(call -> {
          HttpRequest request = call.getArgument(0);
          entitlementReads.incrementAndGet();
          var json = (ObjectNode) AdmissionProtocolFixture.body(request);
          json.put("status", "confirmed").put("confirmedAt", flow.http.clock.millis() - 1000)
              .put("checkedAt", flow.http.clock.millis()).put("validUntil", flow.http.clock.millis() + 4000);
          duringEntitlement.run();
          HttpResponse<byte[]> response = mock(HttpResponse.class);
          when(response.statusCode()).thenReturn(entitlementStatus);
          when(response.uri()).thenReturn(request.uri());
          when(response.previousResponse()).thenReturn(Optional.empty());
          when(response.headers()).thenReturn(HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (_, _) -> true));
          when(response.body()).thenReturn(SystemMapper.jsonMapper().writeValueAsBytes(json));
          return CompletableFuture.completedFuture(response);
        });
    entitlementClient = new AdmissionServiceClient(AdmissionServiceConfiguration.pilot(), http,
        () -> "synthetic.header.signature", flow.http.clock, flow.http.nanos::get, new SecureRandom());
    bodies = new MobileEnrollmentBodyReader(Duration.ofSeconds(2), 4);
    install();
  }

  void install() {
    var service = new MobileEnrollmentService(flow.operations, flow.coordinator, accounts.creator,
        new AdmissionEntitlementGate(flow.ds, entitlementClient), Duration.ofSeconds(3), allowedMembers);
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new org.whispersystems.textsecuregcm.filters.DmAlphaRequestPolicy(true))
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new VirtualExecutorServiceProvider("enrollment-rest-test", 4))
        .register(new MobileEnrollmentController(service, bodies, request -> "192.0.2.1")));
  }

  @AfterEach void close() throws Exception {
    if (jersey != null) jersey.onShutdown(null);
    if (bodies != null) bodies.close();
    if (entitlementClient != null) entitlementClient.close();
    // Unlike creator-only tests, this fixture deliberately calls the mock phone provider.
    if (flow != null) flow.close();
  }

  record Reply(int status, JsonNode body, String retryAfter) {}

  Reply request(String path) throws Exception { return request(path, envelope); }
  Reply request(String path, ObjectNode body) throws Exception {
    return request(path, SystemMapper.jsonMapper().writeValueAsBytes(body));
  }
  Reply request(String path, byte[] body) throws Exception {
    return request(path, body, HeaderUtils.basicAuthHeader("+13055550123", password), "application/json");
  }
  Reply request(String path, byte[] body, String authorization, String contentType) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"),
        URI.create("http://localhost/v1/bconnected/enrollment/" + path), "POST", null,
        new MapPropertiesDelegate(), null);
    if (authorization != null) request.header("Authorization", authorization);
    if (contentType != null) request.header("Content-Type", contentType);
    request.header("User-Agent", currentUserAgent);
    request.header("X-Forwarded-For", "198.51.100.254"); // Never the trusted resolver's value.
    request.setProperty(org.whispersystems.textsecuregcm.filters.RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME, "192.0.2.1");
    request.setEntityStream(new ByteArrayInputStream(body));
    var output = new ByteArrayOutputStream();
    var response = jersey.apply(request, output).get(10, TimeUnit.SECONDS);
    assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
    return new Reply(response.getStatus(), SystemMapper.jsonMapper().readTree(output.toByteArray()),
        response.getHeaderString("Retry-After"));
  }

  UUID begin() throws Exception {
    var reply = request("begin");
    assertThat(reply.status()).isEqualTo(200);
    assertThat(reply.body().path("state").asText()).isEqualTo("verification");
    assertThat(reply.body().path("registrationAuthorized").asBoolean()).isFalse();
    return UUID.fromString(reply.body().path("operationId").asText());
  }

  UUID pending() throws Exception {
    UUID id = begin();
    flow.sql("UPDATE signal.registration_sessions SET verified=true");
    var reply = request(id + "/complete");
    assertThat(reply.status()).isEqualTo(202);
    assertThat(reply.body().path("state").asText()).isEqualTo("pending_confirmation");
    assertThat(reply.body().has("account")).isFalse();
    return id;
  }

  void activate() throws Exception {
    flow.sql("UPDATE signal.admissions SET status='ACTIVE',activated_at=clock_timestamp()");
    flow.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=clock_timestamp()");
  }

  void error(Reply reply, int status, String code) {
    assertThat(reply.status()).isEqualTo(status);
    assertThat(reply.body().path("code").asText()).isEqualTo(code);
    assertThat(reply.body().fieldNames()).toIterable().containsExactly("code");
    assertThat(reply.retryAfter()).isNull();
  }

  @Test void beginAndStatusAreReadOnlyTowardProviderAndStatusNeverReclaims() throws Exception {
    UUID id = begin();
    int claims = flow.http.claims.size();
    var status = request(id + "/status");
    assertThat(status.status()).isEqualTo(200);
    assertThat(status.body().path("expiresInSeconds").asLong()).isLessThanOrEqualTo(300);
    assertThat(flow.http.claims).hasSize(claims);
    assertThat(flow.http.attestations).isEmpty();
    verifyNoInteractions(flow.provider);
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
  }

  @Test void alphaCohortRejectsBeforeClaimsSessionsOrProviderAndAllowsItsOriginalMember() throws Exception {
    jersey.onShutdown(null);
    allowedMembers = Set.of(UUID.randomUUID(), UUID.randomUUID()); install();
    error(request("begin"), 404, "ENROLLMENT_UNAVAILABLE");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isZero();
    assertThat(flow.http.claims).isEmpty(); verifyNoInteractions(flow.provider);
    jersey.onShutdown(null);
    allowedMembers = Set.of(UUID.fromString(envelope.path("memberId").asText()), UUID.randomUUID()); install();
    begin();
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isEqualTo(1);
    verifyNoInteractions(flow.provider);
  }

  @Test void composedAlphaConfirmsPendingAccountThroughManagedWorkerAndReturnsFreshActiveIdentity() throws Exception {
    byte[] phoneKey = new byte[32]; Arrays.fill(phoneKey, (byte) 1);
    var config = new org.whispersystems.textsecuregcm.configuration.DmAlphaConfiguration(
        Set.of(UUID.fromString(envelope.path("memberId").asText()), UUID.randomUUID()),
        new org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes(new byte[32]),
        new org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes(phoneKey),
        Map.of("test-key", Base64.getEncoder().encodeToString(flow.http.key.getPublic().getEncoded())));
    var composed = new DmAlphaEnrollment(config, flow.ds, flow.http.clock, Duration.ofDays(1),
        flow.http.client, new AdmissionEntitlementGate(flow.ds, flow.http.client), flow.nativeSessions);
    try {
      jersey.onShutdown(null);
      jersey = new ApplicationHandler(new ResourceConfig()
          .register(new org.whispersystems.textsecuregcm.filters.DmAlphaRequestPolicy(true))
          .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
          .register(new VirtualExecutorServiceProvider("alpha-composed-test", 4))
          .register(composed.controller()));
      UUID id = pending();
      assertThat(request(id + "/status").body().path("registrationAuthorized").asBoolean()).isFalse();
      composed.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (flow.count("SELECT count(*) FROM signal.admissions WHERE status='ACTIVE'") == 0
          && System.nanoTime() < deadline) Thread.sleep(10);
      var result = request(id + "/status");
      assertThat(result.status()).isEqualTo(200);
      assertThat(result.body().path("state").asText()).isEqualTo("active");
      assertThat(result.body().path("registrationAuthorized").asBoolean()).isTrue();
      assertThat(result.body().path("account").path("deviceId").asInt()).isEqualTo(1);
      verifyNoInteractions(flow.provider);
    } finally { composed.stop(); }
  }

  @ParameterizedTest @ValueSource(strings = {"send-code", "check-code", "complete", "status"})
  void missingOperationCannotInsertClaimSendOrCreate(String action) throws Exception {
    var body = envelope.deepCopy();
    if (action.equals("check-code")) body.put("code", "123456");
    error(request(UUID.randomUUID() + "/" + action, body), 404, "ENROLLMENT_UNAVAILABLE");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isZero();
    assertThat(flow.count("SELECT count(*) FROM signal.registration_sessions")).isZero();
    assertThat(flow.http.claims).isEmpty();
    verifyNoInteractions(flow.provider);
  }

  @ParameterizedTest @ValueSource(strings = {"send-code", "check-code", "complete", "status"})
  void wrongPathCannotSelectOrMutateAnotherOperation(String action) throws Exception {
    begin();
    int claims = flow.http.claims.size();
    var body = envelope.deepCopy();
    if (action.equals("check-code")) body.put("code", "123456");
    error(request(UUID.randomUUID() + "/" + action, body), 404, "ENROLLMENT_UNAVAILABLE");
    assertThat(flow.http.claims).hasSize(claims);
    assertThat(flow.http.attestations).isEmpty();
    verifyNoInteractions(flow.provider);
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
  }

  @Test void wrongPasswordAndImmutableConflictHaveDistinctAuthenticatedErrors() throws Exception {
    UUID id = begin();
    password = "synthetic-wrong-password";
    error(request(id + "/send-code"), 401, "INVALID_CREDENTIALS");
    password = AdmissionRegistrationCoordinatorPostgresTest.PASSWORD;
    envelope.put("originalUserAgent", "changed frozen value");
    error(request(id + "/send-code"), 409, "ENROLLMENT_CONFLICT");
    verifyNoInteractions(flow.provider);
    assertThat(flow.http.claims).hasSize(1);
  }

  @Test void expiredUncommittedAttemptCannotSendOrRestartThroughStatus() throws Exception {
    UUID id = begin();
    flow.http.advance(300000);
    error(request(id + "/status"), 410, "ENROLLMENT_EXPIRED");
    error(request(id + "/send-code"), 410, "ENROLLMENT_EXPIRED");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isEqualTo(1);
    verifyNoInteractions(flow.provider);
  }

  @Test void nativeSessionExpiryCapsRemainingOperationLifetime() throws Exception {
    UUID id = begin();
    long expires = flow.http.clock.millis() + 4500;
    flow.sql("UPDATE signal.registration_sessions SET expires_ms=" + expires);
    flow.sql("UPDATE signal.registration_operations SET verification_session_expires_ms=" + expires);
    assertThat(request(id + "/status").body().path("expiresInSeconds").asLong()).isEqualTo(5);
    flow.http.advance(4500);
    // Native absence lacks typed expiry evidence in the transport; it cannot authorize restart.
    error(request(id + "/status"), 503, "TEMPORARILY_UNAVAILABLE");
    verifyNoInteractions(flow.provider);
  }

  @Test void expiredClaimCannotKeepReportingPreviouslyVerifiedPhone() throws Exception {
    UUID id = begin();
    flow.sql("UPDATE signal.registration_sessions SET verified=true");
    flow.http.advance(120000);
    error(request(id + "/status"), 410, "ENROLLMENT_EXPIRED");
    verifyNoInteractions(flow.provider);
  }

  @Test void sendCheckAndPendingCreationNeverPrematurelyAuthorizeRegistration() throws Exception {
    UUID id = begin();
    var sent = request(id + "/send-code");
    assertThat(sent.status()).isEqualTo(200);
    assertThat(sent.body().path("phoneVerified").asBoolean()).isFalse();
    var code = envelope.deepCopy().put("code", "12345");
    error(request(id + "/check-code", code), 422, "CODE_NOT_ACCEPTED");
    flow.http.advance(1000);
    when(flow.provider.verify(any(), eq("+13055550123"), eq("12345"), any())).thenReturn(true);
    var verified = request(id + "/check-code", code);
    assertThat(verified.status()).isEqualTo(200);
    assertThat(verified.body().path("phoneVerified").asBoolean()).isTrue();
    assertThat(verified.body().path("registrationAuthorized").asBoolean()).isFalse();
    assertThat(request(id + "/complete").status()).isEqualTo(202);
    assertThat(request(id + "/complete").status()).isEqualTo(202);
    assertThat(request(id + "/status").status()).isEqualTo(200);
    assertThat(entitlementReads.get()).isZero();
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isEqualTo(1);
    verify(flow.provider, times(1)).sendSms(anyString(), any());
  }

  @Test void unknownSendOutcomeIsNeverAutomaticallyRepeatedByStatusOrRestart() throws Exception {
    UUID id = begin();
    doThrow(new TelnyxVerifyException(TelnyxVerifyException.Reason.TRANSPORT_FAILURE, 0,
        Optional.empty(), Optional.empty())).when(flow.provider).sendSms(anyString(), any());
    error(request(id + "/send-code"), 503, "TEMPORARILY_UNAVAILABLE");
    jersey.onShutdown(null);
    install();
    currentUserAgent = "BConnected/new-app-version";
    for (int i = 0; i < 3; i++) assertThat(request(id + "/status").status()).isEqualTo(200);
    verify(flow.provider, times(1)).sendSms(anyString(), any());
    assertThat(flow.count("SELECT count(*) FROM signal.registration_sessions")).isEqualTo(1);
  }

  @Test void definitiveQuotaDelayIsReturnedWithoutGuessingOtherRetryTimes() throws Exception {
    UUID id = begin();
    request(id + "/send-code");
    var limited = request(id + "/send-code");
    assertThat(limited.status()).isEqualTo(429);
    assertThat(limited.body().path("code").asText()).isEqualTo("RATE_LIMITED");
    assertThat(limited.body().path("retryAfterSeconds").asLong()).isEqualTo(1);
    assertThat(limited.retryAfter()).isEqualTo("1");
    verify(flow.provider, times(1)).sendSms(anyString(), any());
  }

  @ParameterizedTest @ValueSource(ints = {401, 403, 429, 503})
  void privateClaimTransportErrorsNeverBecomeUserCredentialRejection(int status) throws Exception {
    flow.http.claimStatus = status;
    error(request("begin"), 503, "TEMPORARILY_UNAVAILABLE");
    verifyNoInteractions(flow.provider);
    assertThat(flow.count("SELECT count(*) FROM signal.registration_sessions")).isZero();
  }

  @Test void activeProjectionIsFromSameProofAndExactRetrySurvivesEnrollmentExpiry() throws Exception {
    UUID id = pending();
    activate();
    flow.http.advance(300001);
    int claims = flow.http.claims.size(), attestations = flow.http.attestations.size();
    var active = request(id + "/complete");
    assertThat(active.status()).isEqualTo(200);
    assertThat(active.body().path("registrationAuthorized").asBoolean()).isTrue();
    assertThat(active.body().path("state").asText()).isEqualTo("active");
    var account = active.body().path("account");
    assertThat(account.fieldNames()).toIterable().containsExactlyInAnyOrder("aci", "pni", "number", "deviceId");
    assertThat(account.path("number").asText()).isEqualTo("+13055550123");
    assertThat(account.path("deviceId").asInt()).isEqualTo(1);
    assertThat(entitlementReads.get()).isEqualTo(1);
    assertThat(flow.http.claims).hasSize(claims);
    assertThat(flow.http.attestations).hasSize(attestations);
    verifyNoInteractions(flow.provider);
  }

  @Test void staleProjectionDuringEntitlementReadCannotReportActive() throws Exception {
    UUID id = pending();
    activate();
    duringEntitlement = () -> {
      try { flow.sql("UPDATE signal.accounts SET version=version+1"); }
      catch (Exception e) { throw new AssertionError(e); }
    };
    error(request(id + "/status"), 503, "TEMPORARILY_UNAVAILABLE");
    assertThat(entitlementReads.get()).isEqualTo(1);
  }

  @Test void delayedPendingAndSuspendedStatusesNeverIncludeAccountOrAuthorization() throws Exception {
    UUID id = pending();
    flow.http.advance(300001);
    var pending = request(id + "/status");
    assertThat(pending.status()).isEqualTo(200);
    assertThat(pending.body().path("state").asText()).isEqualTo("pending_confirmation");
    assertThat(pending.body().has("account")).isFalse();
    flow.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    var suspended = request(id + "/status");
    assertThat(suspended.body().path("state").asText()).isEqualTo("suspended");
    assertThat(suspended.body().path("registrationAuthorized").asBoolean()).isFalse();
    assertThat(entitlementReads.get()).isZero();
  }

  @Test void deletedCommittedAccountCannotBeRecreatedOrReattested() throws Exception {
    UUID id = pending();
    int attestations = flow.http.attestations.size();
    flow.sql("DELETE FROM signal.accounts");
    error(request(id + "/complete"), 404, "ENROLLMENT_UNAVAILABLE");
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
    assertThat(flow.http.attestations).hasSize(attestations);
  }

  @Test void malformedAndOversizedWireInputsFailBeforeOperationInsertion() throws Exception {
    var invalid = envelope.deepCopy().put("clientProof", "not-authority");
    error(request("begin", invalid), 400, "INVALID_REQUEST");
    error(request("begin", new byte[65_537]), 400, "INVALID_REQUEST");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isZero();
    verifyNoInteractions(flow.provider);
    assertThat(flow.http.claims).isEmpty();
  }

  @Test void missingOrUnsupportedMediaTypeIsSanitized400BeforeAnyWrites() throws Exception {
    byte[] body = SystemMapper.jsonMapper().writeValueAsBytes(envelope);
    String auth = HeaderUtils.basicAuthHeader("+13055550123", password);
    error(request("begin", body, auth, null), 400, "INVALID_REQUEST");
    error(request("begin", body, auth, "text/plain"), 400, "INVALID_REQUEST");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isZero();
    assertThat(flow.http.claims).isEmpty();
    verifyNoInteractions(flow.provider);
  }

  @Test void missingOrMalformedBasicAuthIsSanitized401BeforeAnyWrites() throws Exception {
    byte[] body = SystemMapper.jsonMapper().writeValueAsBytes(envelope);
    for (String auth : Arrays.asList(null, "Bearer not-enrollment", "Basic ???"))
      error(request("begin", body, auth, "application/json"), 401, "INVALID_CREDENTIALS");
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isZero();
    assertThat(flow.http.claims).isEmpty();
    verifyNoInteractions(flow.provider);
  }
}
