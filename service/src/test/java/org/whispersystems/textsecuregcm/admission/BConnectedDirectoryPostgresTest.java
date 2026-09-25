// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.controllers.BConnectedDirectoryController;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Real device auth, ACTIVE/cohort SQL and HTTP dispatch. No messages, SMS, keys or push sent. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class BConnectedDirectoryPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  ApplicationHandler jersey;
  UUID recipient;
  Map<String, Object> recipientRow;
  RateLimiter limiter;
  RateLimiters rates;
  AuthenticatedDevice original;
  boolean retainOriginal;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    var pair = new AdmissionSendPostgresTest();
    pair.fixture = fixture; pair.recipientAci = recipient = UUID.randomUUID(); pair.cloneRecipient();
    try (var connection = fixture.flow.ds.getConnection();
         var statement = connection.prepareStatement("SELECT * FROM signal.admissions WHERE aci=?")) {
      statement.setObject(1, recipient);
      try (var row = statement.executeQuery()) {
        row.next(); recipientRow = new LinkedHashMap<>();
        recipientRow.put("memberId", row.getObject("member_id").toString());
        recipientRow.put("signalOperationId", row.getObject("signal_operation_id").toString());
        recipientRow.put("approvalEpoch", row.getLong("approval_epoch"));
        recipientRow.put("jti", Base64.getUrlEncoder().withoutPadding().encodeToString(row.getBytes("permit_id")));
        recipientRow.put("aci", recipient.toString());
        recipientRow.put("confirmedAt", fixture.flow.http.clock.millis() - 1000);
        recipientRow.put("fullName", "Synthetic Alumni"); recipientRow.put("graduationYear", 2005);
      }
    }
    fixture.responseMutation = response -> {
      if (!response.containsKey("query") && !response.containsKey("targetAci")) return;
      var caller = new LinkedHashMap<String, Object>();
      for (var field : List.of("memberId", "signalOperationId", "approvalEpoch", "jti", "aci")) caller.put(field, response.get(field));
      Object nonce = response.get("requestNonce"), target = response.get("targetAci");
      response.clear(); response.put("caller", caller); response.put("requestNonce", nonce);
      response.put("status", "confirmed"); response.put("checkedAt", fixture.flow.http.clock.millis());
      response.put("validUntil", fixture.flow.http.clock.millis() + 4000);
      response.put("members", target == null || target.equals(recipient.toString()) ? List.of(recipientRow) : List.of());
      response.put("nextOffset", null);
    };
    rebuildJersey();
  }

  void rebuildJersey() {
    if (jersey != null) jersey.onShutdown(null);
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    original = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    rates = mock(RateLimiters.class); limiter = mock(RateLimiter.class);
    when(rates.getBConnectedDirectoryLimiter()).thenReturn(limiter);
    var live = AccountAuthenticator.withAdmission(fixture.gate);
    var auth = mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call -> retainOriginal ? Optional.of(original) : live.authenticate(call.getArgument(0)));
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new org.whispersystems.textsecuregcm.filters.DmAlphaRequestPolicy(false))
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new RateLimitExceededExceptionMapper())
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
            .setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .register(new BConnectedDirectoryController(fixture.gate, rates)));
  }

  @AfterEach void close() throws Exception {
    if (jersey != null) jersey.onShutdown(null);
    if (fixture != null) fixture.close();
  }

  ContainerResponse request(String action, String body, boolean authenticated) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"),
        URI.create("http://localhost/v1/bconnected/directory/" + action), "POST",
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), jersey.getConfiguration());
    if (authenticated) request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    request.header("Content-Type", "application/json");
    request.setEntityStream(new java.io.ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }
  ContainerResponse search() throws Exception { return request("search", "{\"query\":\"\",\"offset\":0}", true); }
  String json(ContainerResponse response) throws Exception { return SystemMapper.jsonMapper().writeValueAsString(response.getEntity()); }

  @Test void directoryExposesOnlyApprovedPublicLabelsWithOnePrivateBatch() throws Exception {
    retainOriginal = true; int before = fixture.requests.get();
    var response = search();
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
    assertThat(json(response)).isEqualTo("{\"members\":[{\"aci\":\"" + recipient
        + "\",\"deviceId\":1,\"fullName\":\"Synthetic Alumni\",\"graduationYear\":2005}],\"nextOffset\":null}");
    assertThat(fixture.requests.get() - before).isEqualTo(1);
    verify(limiter).validate(fixture.aci);
  }

  @Test void resolveReturnsExactMemberOr404WithoutPhoneOrAdmissionFields() throws Exception {
    var response = request("resolve", "{\"aci\":\"" + recipient + "\"}", true);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(json(response)).isEqualTo("{\"aci\":\"" + recipient
        + "\",\"deviceId\":1,\"fullName\":\"Synthetic Alumni\",\"graduationYear\":2005}");
    assertThat(request("resolve", "{\"aci\":\"" + UUID.randomUUID() + "\"}", true).getStatus()).isEqualTo(404);
  }

  @Test void searchAndResolveShareDirectoryBudgetWithoutConsumingPreKeys() throws Exception {
    for (int i = 0; i < 8; i++) {
      var response = i % 2 == 0 ? search() : request("resolve", "{\"aci\":\"" + recipient + "\"}", true);
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(limiter, times(8)).validate(fixture.aci);
    verify(rates, never()).getPreKeysLimiter();
  }

  @Test void exhaustedDirectoryBudgetRejectsBeforePrivateLookup() throws Exception {
    retainOriginal = true;
    doThrow(new RateLimitExceededException(Duration.ofSeconds(1))).when(limiter).validate(fixture.aci);
    int before = fixture.requests.get();
    for (String action : List.of("search", "resolve")) {
      var response = action.equals("search") ? search()
          : request(action, "{\"aci\":\"" + recipient + "\"}", true);
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("1");
    }
    assertThat(fixture.requests.get()).isEqualTo(before);
    verify(rates, never()).getPreKeysLimiter();
  }

  @Test void anonymousRequestHasNoDirectoryOrLimiterSideEffects() throws Exception {
    int before = fixture.requests.get();
    assertThat(request("search", "{\"query\":\"\",\"offset\":0}", false).getStatus()).isEqualTo(401);
    assertThat(fixture.requests.get()).isEqualTo(before); verifyNoInteractions(limiter);
  }

  @ParameterizedTest @ValueSource(strings = {
      "{}", "{\"query\":\"\",\"offset\":0,\"phone\":\"x\"}", "{\"query\":\"x\",\"query\":\"y\",\"offset\":0}",
      "{\"query\":\"x\\n\",\"offset\":0}", "{\"query\":true,\"offset\":0}", "{\"query\":\"\",\"offset\":-1}",
      "{\"query\":\"\",\"offset\":10001}", "{\"query\":\"\",\"offset\":0.0}", "{\"query\":\"\",\"offset\":\"0\"}",
      "{\"query\":\"\",\"offset\":0} {}"})
  void malformedSearchNeverReachesPrivateDirectory(String body) throws Exception {
    retainOriginal = true; int before = fixture.requests.get();
    assertThat(request("search", body, true).getStatus()).isEqualTo(400);
    assertThat(fixture.requests.get()).isEqualTo(before); verifyNoInteractions(limiter);
  }

  @Test void unknownNonCanonicalAndOversizedRequestsFailClosed() throws Exception {
    assertThat(request("resolve", "{\"aci\":\"1-1-1-1-1\"}", true).getStatus()).isEqualTo(400);
    assertThat(request("search", "{\"query\":\"" + "x".repeat(101) + "\",\"offset\":0}", true).getStatus()).isEqualTo(400);
    assertThat(request("search", " ".repeat(2049), true).getStatus()).isEqualTo(400);
    assertThat(request("export", "{}", true).getStatus()).isEqualTo(503);
  }

  @Test void locallySuspendedAndOutsideCohortTargetsAreOmitted() throws Exception {
    fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + recipient + "'");
    assertThat(json(search())).isEqualTo("{\"members\":[],\"nextOffset\":null}");
    fixture.sql("UPDATE signal.admissions SET suspended_at=NULL WHERE aci='" + recipient + "'");
    fixture.gate = new AdmissionEntitlementGate(fixture.flow.ds, fixture.client, Set.of(fixture.flow.input.memberId()));
    rebuildJersey();
    assertThat(json(search())).isEqualTo("{\"members\":[],\"nextOffset\":null}");
    assertThat(request("resolve", "{\"aci\":\"" + recipient + "\"}", true).getStatus()).isEqualTo(404);
  }

  @Test void wrongBindingMetadataAndPrivateFailureNeverBecomeEmptySuccess() throws Exception {
    retainOriginal = true; recipientRow.put("approvalEpoch", 999L);
    assertThat(search().getStatus()).isEqualTo(503);
    fixture.httpStatus = 503;
    assertThat(search().getStatus()).isEqualTo(503);
  }

  @Test void expiryDuringPrivateCallDoesNotRenewCallerOrDirectoryReceipt() throws Exception {
    retainOriginal = true; fixture.duringHttp = () -> fixture.flow.http.advance(4000);
    assertThat(search().getStatus()).isEqualTo(503);
  }

  @Test void suspendedCallerDuringPrivateSearchCannotReadLabels() throws Exception {
    retainOriginal = true;
    fixture.duringHttp = () -> fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + fixture.aci + "'");
    assertThat(search().getStatus()).isEqualTo(401);
  }

  @Test void changedDeviceCredentialsDuringPrivateSearchCannotReadLabels() throws Exception {
    retainOriginal = true;
    fixture.duringHttp = () -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"disabled\"') WHERE aci='" + fixture.aci + "'");
    assertThat(search().getStatus()).isEqualTo(503);
  }

  @Test void originalDeviceAndTargetProofsAreRecheckedAfterResponseConstruction() {
    var result = fixture.gate.directory(original.admissionAuthorization(), fixture.aci, (byte) 1, "", 0, null);
    assertThat(result.page().members()).hasSize(1);
    fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"disabled\"') WHERE aci='" + fixture.aci + "'");
    assertThrows(AdmissionEntitlementGate.UnavailableException.class, result::requireCurrent);
  }

  @Test void targetSuspensionAfterResponseConstructionNeverExposesStaleLabel() {
    var result = fixture.gate.directory(original.admissionAuthorization(), fixture.aci, (byte) 1, "", 0, null);
    assertThat(result.page().members()).hasSize(1);
    fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + recipient + "'");
    assertThrows(AdmissionEntitlementGate.UnavailableException.class, result::requireCurrent);
  }

  @Test void limiterWaitCannotExtendOriginalCallerProof() throws Exception {
    retainOriginal = true; int before = fixture.requests.get();
    doAnswer(_ -> { fixture.flow.http.advance(4000); return null; }).when(limiter).validate(any(UUID.class));
    assertThat(search().getStatus()).isEqualTo(503);
    assertThat(fixture.requests.get()).isEqualTo(before);
  }
}
