// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.basic.BasicCredentials;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.AuthenticationUnavailableException;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticationUtil;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Native fixture only; the inherited phone-verification fixture asserts zero provider calls. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionAccountAuthenticatorPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  AccountAuthenticator authenticator;

  @BeforeEach
  void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest();
    fixture.setup();
    authenticator = AccountAuthenticator.withAdmission(fixture.gate);
  }

  @AfterEach
  void close() throws Exception {
    if (fixture != null) fixture.close();
  }

  BasicCredentials credentials() {
    return new BasicCredentials(fixture.aci.toString(), fixture.flow.input.password());
  }

  String accountRow() throws Exception {
    try (var c = fixture.flow.ds.getConnection();
         var q = c.createStatement();
         var r = q.executeQuery("SELECT to_jsonb(a)::text FROM signal.accounts a")) {
      assertThat(r.next()).isTrue();
      return r.getString(1);
    }
  }

  @Test
  void currentPrimaryDeviceReturnsLiveProofWithoutActivityMutationOrLeaseRenewal() throws Exception {
    fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,lastSeen}','1000')");
    String before = accountRow();
    var principal = authenticator.authenticate(credentials()).orElseThrow();
    assertThat(principal.accountIdentifier()).isEqualTo(fixture.aci);
    assertThat(principal.deviceId()).isEqualTo((byte) 1);
    assertThat(principal.primaryDeviceLastSeen()).isEqualTo(Instant.ofEpochMilli(1000));
    assertThat(principal.admissionAuthorization()).isNotNull();
    principal.requireCurrentEntitlement();
    assertThat(accountRow()).isEqualTo(before);
    assertThat(fixture.requests.get()).isEqualTo(1);
    fixture.flow.http.advance(4000);
    var expired = assertThrows(AdmissionServiceClient.AdmissionServiceException.class,
        principal::requireCurrentEntitlement);
    assertThat(expired.failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThat(accountRow()).isEqualTo(before);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "DELETE FROM signal.accounts",
      "UPDATE signal.admissions SET status='PENDING'",
      "UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()",
      "DELETE FROM signal.admission_confirmation_outbox",
      "UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL",
      "UPDATE signal.accounts SET data=jsonb_set(data,'{devices}','[]')",
      "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!locked\"')"
  })
  void ineligibleOrLockedDeviceDeniesBeforeRemoteRequest(String mutation) {
    fixture.sql(mutation);
    assertThat(authenticator.authenticate(credentials())).isEmpty();
    assertThat(fixture.requests.get()).isZero();
  }

  @Test
  void replacedCredentialsCannotAuthenticateEvenWhenOldPasswordPreviouslyWorked() {
    assertThat(authenticator.authenticate(credentials())).isPresent();
    SaltedTokenHash next = SaltedTokenHash.generateFor("replacement fixture password");
    fixture.sql("UPDATE signal.accounts SET data=jsonb_set(jsonb_set(data,'{devices,0,authToken}',"
        + "to_jsonb('" + next.hash() + "'::text)),'{devices,0,salt}',to_jsonb('" + next.salt() + "'::text))");
    assertThat(authenticator.authenticate(credentials())).isEmpty();
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThat(authenticator.authenticate(new BasicCredentials(fixture.aci.toString(),
        "replacement fixture password"))).isPresent();
    assertThat(fixture.requests.get()).isEqualTo(2);
  }

  @Test
  void validLinkedDeviceIsStillUnavailableInTheSingleIphonePilot() {
    fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices}',"
        + "(data->'devices') || jsonb_build_array(jsonb_set(data->'devices'->0,'{id}','2')))");
    assertThat(authenticator.authenticate(new BasicCredentials(fixture.aci + ".2",
        fixture.flow.input.password()))).isEmpty();
    assertThat(fixture.requests.get()).isZero();
    // The same live credential is valid at the lower-level membership gate; policy is in auth.
    fixture.gate.authorizeDevice(fixture.aci, (byte) 2, fixture.flow.input.password())
        .requireCurrent(fixture.aci, (byte) 2);
  }

  @Test
  void wrongPasswordCannotReachRemoteEntitlement() {
    assertThat(authenticator.authenticate(new BasicCredentials(fixture.aci.toString(), "wrong")))
        .isEmpty();
    assertThat(fixture.requests.get()).isZero();
  }

  @ParameterizedTest
  @ValueSource(ints = {400, 401, 403, 404, 409, 429, 503})
  void issuerDenialAndUnknownStateNeverReturnAPrincipal(int status) throws Exception {
    String before = accountRow();
    fixture.httpStatus = status;
    var unavailable = assertThrows(AuthenticationUnavailableException.class,
        () -> authenticator.authenticate(credentials()));
    assertThat(unavailable.getResponse().getStatus()).isEqualTo(503);
    assertThat(unavailable).hasNoCause();
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThat(accountRow()).isEqualTo(before);
  }

  @Test
  void concurrentRevocationDuringHttpCannotAuthenticate() throws Exception {
    fixture.duringHttp = () -> fixture.sql(
        "UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    assertThat(authenticator.authenticate(credentials())).isEmpty();
    assertThat(fixture.flow.count("SELECT count(*) FROM signal.admissions WHERE status='SUSPENDED'"))
        .isEqualTo(1);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void expiryBetweenGateReturnAndPrincipalReturnDeniesWithoutSecondHttp() throws Exception {
    var ds = mock(DataSource.class);
    var connections = new AtomicInteger();
    when(ds.getConnection()).thenAnswer(call -> {
      // Initial snapshot, post-HTTP snapshot, then AccountAuthenticator's final use-time check.
      if (connections.incrementAndGet() == 3) fixture.flow.http.advance(4000);
      return fixture.flow.ds.getConnection();
    });
    var delayed = AccountAuthenticator.withAdmission(new AdmissionEntitlementGate(ds, fixture.client));
    assertThrows(AuthenticationUnavailableException.class, () -> delayed.authenticate(credentials()));
    assertThat(connections.get()).isEqualTo(3);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void deviceLockBetweenGateReturnAndPrincipalReturnDenies() throws Exception {
    var ds = mock(DataSource.class);
    var connections = new AtomicInteger();
    when(ds.getConnection()).thenAnswer(call -> {
      if (connections.incrementAndGet() == 3) fixture.sql(
          "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!locked\"')");
      return fixture.flow.ds.getConnection();
    });
    var delayed = AccountAuthenticator.withAdmission(new AdmissionEntitlementGate(ds, fixture.client));
    assertThrows(AuthenticationUnavailableException.class, () -> delayed.authenticate(credentials()));
    assertThat(connections.get()).isEqualTo(3);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void retainedProofCannotCrossAccountOrDeviceOrSurviveLocalMutation() {
    var principal = authenticator.authenticate(credentials()).orElseThrow();
    var wrongAccount = new AuthenticatedDevice(UUID.randomUUID(), (byte) 1,
        principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    var wrongDevice = new AuthenticatedDevice(fixture.aci, (byte) 2,
        principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    assertThrows(AdmissionEntitlementGate.DeniedException.class, wrongAccount::requireCurrentEntitlement);
    assertThrows(AdmissionEntitlementGate.DeniedException.class, wrongDevice::requireCurrentEntitlement);
    fixture.sql("UPDATE signal.accounts SET version=version+1");
    assertThrows(AdmissionEntitlementGate.UnavailableException.class, principal::requireCurrentEntitlement);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void grpcConversionRetainsExactProofAndDoesNotRenewIt() {
    var principal = authenticator.authenticate(credentials()).orElseThrow();
    var mockAuthenticator = mock(AccountAuthenticator.class);
    when(mockAuthenticator.authenticate(credentials())).thenReturn(Optional.of(principal));
    var headers = new Metadata();
    headers.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY, "Basic "
        + Base64.getEncoder().encodeToString((credentials().getUsername() + ":"
        + credentials().getPassword()).getBytes(StandardCharsets.UTF_8)));
    @SuppressWarnings("unchecked") ServerCall<Object, Object> call = mock(ServerCall.class);
    var captured = new AtomicReference<org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice>();
    new RequireAuthenticationInterceptor(mockAuthenticator).interceptCall(call, headers, (c, h) -> {
      captured.set(AuthenticationUtil.requireAuthenticatedDevice());
      captured.get().requireCurrentEntitlement();
      return new ServerCall.Listener<>() {};
    });
    assertThat(captured.get().admissionAuthorization()).isSameAs(principal.admissionAuthorization());
    fixture.flow.http.advance(4000);
    var expired = assertThrows(AdmissionServiceClient.AdmissionServiceException.class,
        captured.get()::requireCurrentEntitlement);
    assertThat(expired.failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void principalSerializationNeverExportsLocalEvidence() throws Exception {
    var principal = authenticator.authenticate(credentials()).orElseThrow();
    var json = SystemMapper.jsonMapper().writeValueAsString(principal);
    assertThat(json).doesNotContain("admissionAuthorization", "authToken", "salt", "receipt", "snapshot");
  }

  @Test
  void pilotCannotFallBackToMissingGateOrUnguardedActivityWrites() {
    assertThrows(NullPointerException.class, () -> AccountAuthenticator.withAdmission(null));
    assertThrows(IllegalStateException.class, () -> authenticator.updateLastSeen(null, null));
    assertThat(fixture.requests.get()).isZero();
  }

  @Test
  void legacyPrincipalsCannotSatisfyOwnedEntitlementBoundary() {
    var http = new AuthenticatedDevice(fixture.aci, (byte) 1, Instant.EPOCH);
    var grpc = new org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice(fixture.aci, (byte) 1);
    assertThrows(IllegalStateException.class, http::requireCurrentEntitlement);
    assertThrows(IllegalStateException.class, grpc::requireCurrentEntitlement);
  }

  @Test
  void sqlFailureAndMalformedStoredCredentialsAreUnavailableNotWrongPassword() throws Exception {
    var ds = mock(DataSource.class);
    when(ds.getConnection()).thenThrow(new java.sql.SQLException("private storage fixture"));
    var noStorage = AccountAuthenticator.withAdmission(new AdmissionEntitlementGate(ds, fixture.client));
    var failure = assertThrows(AuthenticationUnavailableException.class,
        () -> noStorage.authenticate(credentials()));
    assertThat(failure).hasNoCause().hasMessage("Current authentication unavailable");
    fixture.sql("UPDATE signal.accounts SET data='[]'");
    assertThrows(AuthenticationUnavailableException.class, () -> authenticator.authenticate(credentials()));
    assertThat(fixture.requests.get()).isZero();
  }

  @Test
  void malformedStoredAdmissionIsUnavailableNotAnInvalidAuthorizationHeader() {
    fixture.sql("UPDATE signal.admissions SET member_id='00000000-0000-0000-0000-000000000000'");
    var failure = assertThrows(AuthenticationUnavailableException.class,
        () -> authenticator.authenticate(credentials()));
    assertThat(failure.getResponse().getStatus()).isEqualTo(503);
    assertThat(failure).hasNoCause();
    assertThat(fixture.requests.get()).isZero();
  }
}
