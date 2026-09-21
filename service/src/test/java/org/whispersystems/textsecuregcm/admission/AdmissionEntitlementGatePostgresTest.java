// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.net.http.*;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionEntitlementGatePostgresTest {
  AdmissionAccountCreatorPostgresTest enrollment;
  AdmissionRegistrationCoordinatorPostgresTest flow;
  AdmissionServiceClient client;
  AdmissionEntitlementGate gate;
  UUID aci;
  AtomicInteger requests = new AtomicInteger();
  Runnable duringHttp = () -> {};
  Consumer<Map<String, Object>> responseMutation = b -> {};
  int httpStatus = 200;

  @BeforeEach
  void setup() throws Exception {
    enrollment = new AdmissionAccountCreatorPostgresTest();
    enrollment.setup();
    flow = enrollment.flow;
    aci = enrollment.creator.createOrResumePending(flow.input, enrollment.attest()).aci();
    sql("UPDATE signal.admissions SET status='ACTIVE',activated_at=clock_timestamp()");
    sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=clock_timestamp()");
    var http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    when(http.cookieHandler()).thenReturn(Optional.empty());
    when(http.sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenAnswer(
            call -> {
              HttpRequest request = call.getArgument(0);
              requests.incrementAndGet();
              var body = AdmissionProtocolFixture.body(request);
              var response = new LinkedHashMap<String, Object>();
              body.fields()
                  .forEachRemaining(
                      e ->
                          response.put(
                              e.getKey(),
                              e.getValue().isNumber()
                                  ? e.getValue().longValue()
                                  : e.getValue().textValue()));
              response.put("status", "confirmed");
              response.put("confirmedAt", flow.http.clock.millis() - 1000);
              response.put("checkedAt", flow.http.clock.millis());
              response.put("validUntil", flow.http.clock.millis() + 4000);
              responseMutation.accept(response);
              duringHttp.run();
              @SuppressWarnings("unchecked")
              HttpResponse<byte[]> result = mock(HttpResponse.class);
              when(result.statusCode()).thenReturn(httpStatus);
              when(result.uri()).thenReturn(request.uri());
              when(result.previousResponse()).thenReturn(Optional.empty());
              when(result.headers())
                  .thenReturn(
                      HttpHeaders.of(
                          Map.of("Content-Type", List.of("application/json")), (a, b) -> true));
              when(result.body()).thenReturn(AdmissionTestData.JSON.writeValueAsBytes(response));
              return CompletableFuture.completedFuture(result);
            });
    client =
        new AdmissionServiceClient(
            AdmissionServiceConfiguration.pilot(),
            http,
            () -> "fixture.header.signature",
            flow.http.clock,
            flow.http.nanos::get,
            new SecureRandom());
    gate = new AdmissionEntitlementGate(flow.ds, client);
  }

  @AfterEach
  void close() throws Exception {
    if (client != null) client.close();
    if (enrollment != null)
      enrollment.close(); // Includes no Telnyx-provider interaction assertion.
  }

  void sql(String statement) {
    try (var c = flow.ds.getConnection();
        var s = c.createStatement()) {
      s.execute("SET statement_timeout='500ms'");
      s.execute(statement);
    } catch (SQLException error) {
      throw new RuntimeException(error);
    }
  }

  private static void assertExpired(org.junit.jupiter.api.function.Executable operation) {
    var error = assertThrows(AdmissionServiceClient.AdmissionServiceException.class, operation);
    assertThat(error.failure()).isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
  }

  @Test
  void activeConfirmedMembershipCanBeRecheckedWithoutHttpRenewal() throws Exception {
    var authorization = gate.authorize(aci);
    authorization.requireCurrent(aci);
    assertThat(requests.get()).isEqualTo(1);
    flow.http.advance(3999);
    authorization.requireCurrent(aci);
    flow.http.advance(1);
    assertExpired(() -> authorization.requireCurrent(aci));
    assertThat(requests.get()).isEqualTo(1);
    assertThat(flow.count("SELECT count(*) FROM signal.admissions WHERE status='ACTIVE'"))
        .isEqualTo(1);
    assertThat(authorization.toString()).isEqualTo("AdmissionAuthorization[redacted]");
  }

  @Test
  void deviceCredentialsAreVerifiedFromTheLiveSnapshot() {
    var auth = gate.authorizeDevice(aci, (byte) 1, flow.input.password());
    auth.requireCurrent(aci, (byte) 1);
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(aci, (byte) 2));
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(UUID.randomUUID(), (byte) 1));
    sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!disabled\"')");
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(aci, (byte) 1));
    assertThat(requests.get()).isEqualTo(1);
    assertThat(auth.toString()).isEqualTo("AdmissionDeviceAuthorization[redacted]");
  }

  @Test
  void wrongPasswordAndMissingDeviceDenyBeforeRemoteRequest() {
    assertThrows(RuntimeException.class, () -> gate.authorizeDevice(aci, (byte) 1, "wrong"));
    assertThrows(
        RuntimeException.class, () -> gate.authorizeDevice(aci, (byte) 2, flow.input.password()));
    assertThrows(
        RuntimeException.class, () -> gate.authorizeDevice(aci, (byte) 0, flow.input.password()));
    assertThat(requests.get()).isZero();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!disabled\"')",
        "UPDATE signal.accounts SET data=jsonb_set(data,'{devices}','[]')",
        "UPDATE signal.accounts SET data='[]'",
        "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,salt}','\"changed-salt\"')"
      })
  void invalidLiveDeviceDeniesBeforeHttp(String mutation) {
    sql(mutation);
    assertThrows(
        RuntimeException.class, () -> gate.authorizeDevice(aci, (byte) 1, flow.input.password()));
    assertThat(requests.get()).isZero();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "DELETE FROM signal.accounts",
        "UPDATE signal.admissions SET status='PENDING'",
        "UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()",
        "UPDATE signal.admissions SET activated_at=NULL",
        "UPDATE signal.admissions SET suspended_at=clock_timestamp()",
        "UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL",
        "DELETE FROM signal.admission_confirmation_outbox"
      })
  void localIneligibilityDeniesBeforeHttp(String mutation) {
    sql(mutation);
    assertThrows(RuntimeException.class, () -> gate.authorize(aci));
    assertThat(requests.get()).isZero();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "DELETE FROM signal.accounts",
        "UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()",
        "UPDATE signal.admissions SET approval_epoch=approval_epoch+1",
        "UPDATE signal.admissions SET phone_binding=decode(repeat('a',64),'hex')",
        "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!disabled\"')",
        "UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL"
      })
  void concurrentMutationDuringHttpRejectsAndProvesNoSqlLockHeld(String mutation) {
    var completed = new java.util.concurrent.atomic.AtomicBoolean();
    duringHttp =
        () -> {
          sql(mutation); // 500ms statement timeout: would fail if initial locks leaked.
          completed.set(true);
        };
    assertThrows(
        RuntimeException.class, () -> gate.authorizeDevice(aci, (byte) 1, flow.input.password()));
    assertThat(completed.get()).isTrue(); // An HTTP failure caused by blocked SQL is not proof.
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void retainedAuthorizationCannotCrossAccountsGatesOrLocalEpochs() {
    var auth = gate.authorize(aci);
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(UUID.randomUUID()));
    var another = new AdmissionEntitlementGate(flow.ds, client);
    assertThrows(RuntimeException.class, () -> another.requireCurrent(auth, aci));
    sql("UPDATE signal.admissions SET approval_epoch=approval_epoch+1");
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(aci));
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void conservativeAccountVersionChangeRequiresNewAuthorization() {
    var auth = gate.authorize(aci);
    sql("UPDATE signal.accounts SET version=version+1");
    assertThrows(RuntimeException.class, () -> auth.requireCurrent(aci));
    gate.authorize(aci).requireCurrent(aci);
    assertThat(requests.get()).isEqualTo(2);
  }

  @Test
  void monotonicExpiryCannotBeExtendedByWallClockRollback() {
    var auth = gate.authorize(aci);
    flow.http.clock.incrementMillis(-100000);
    flow.http.nanos.addAndGet(TimeUnit.SECONDS.toNanos(4));
    assertExpired(() -> auth.requireCurrent(aci));
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void staleHttpResponseNeverGrantsMembership() {
    duringHttp = () -> flow.http.advance(4000);
    assertExpired(() -> gate.authorize(aci));
  }

  @ParameterizedTest
  @ValueSource(ints = {403, 404, 500})
  void issuerDenialOrUnavailableNeverGrantsMembership(int status) {
    httpStatus = status;
    assertThrows(RuntimeException.class, () -> gate.authorize(aci));
  }

  @Test
  void changedResponseBindingNeverGrantsMembership() {
    responseMutation = b -> b.put("approvalEpoch", 8);
    assertThrows(RuntimeException.class, () -> gate.authorize(aci));
  }

  @Test
  void confirmationReceiptCannotSubstituteForCurrentEntitlement() {
    var wrong = mock(AdmissionServiceClient.class);
    when(wrong.currentEntitlement(any())).thenAnswer(call -> client.confirm(call.getArgument(0)));
    var wrongGate = new AdmissionEntitlementGate(flow.ds, wrong);
    assertThrows(RuntimeException.class, () -> wrongGate.authorize(aci));
  }

  @Test
  void validCurrentReceiptForAnotherBindingCannotBeSubstituted() {
    var wrong = mock(AdmissionServiceClient.class);
    when(wrong.currentEntitlement(any()))
        .thenAnswer(
            call -> {
              AdmissionServiceClient.Binding expected = call.getArgument(0);
              var other =
                  new AdmissionServiceClient.Binding(
                      expected.memberId(),
                      expected.approvalEpoch(),
                      expected.signalOperationId(),
                      expected.permitId(),
                      UUID.randomUUID());
              return client.currentEntitlement(other);
            });
    assertThrows(
        RuntimeException.class, () -> new AdmissionEntitlementGate(flow.ds, wrong).authorize(aci));
  }

  @ParameterizedTest
  @ValueSource(strings = {"accounts", "admissions", "admission_confirmation_outbox"})
  void expiryDuringRowLockWaitRejectsOriginalAuthorization(String table) throws Exception {
    var auth = gate.authorize(aci);
    try (var c = flow.ds.getConnection();
        var s = c.createStatement()) {
      c.setAutoCommit(false);
      s.execute("SELECT * FROM signal." + table + " FOR UPDATE");
      var task = flow.executor.submit(() -> auth.requireCurrent(aci));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      while (flow.count(
              "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND"
                  + " wait_event_type='Lock' AND query LIKE '%signal."
                  + table
                  + "%' AND query LIKE '%FOR SHARE%'")
          == 0) {
        if (System.nanoTime() > deadline)
          throw new AssertionError("Gate did not reach expected row lock");
        Thread.sleep(10);
      }
      flow.http.advance(4000);
      c.commit();
      var error = assertThrows(ExecutionException.class, () -> task.get(5, TimeUnit.SECONDS));
      assertThat(error.getCause())
          .isInstanceOf(AdmissionServiceClient.AdmissionServiceException.class);
      assertThat(((AdmissionServiceClient.AdmissionServiceException) error.getCause()).failure())
          .isEqualTo(AdmissionServiceClient.Failure.EXPIRED);
    }
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void poolAcquisitionConsumesReceiptBudget() throws Exception {
    var ds = mock(DataSource.class);
    var count = new AtomicInteger();
    when(ds.getConnection())
        .thenAnswer(
            call -> {
              if (count.incrementAndGet() == 2) flow.http.advance(4000);
              return flow.ds.getConnection();
            });
    var delayed = new AdmissionEntitlementGate(ds, client);
    assertExpired(() -> delayed.authorize(aci));
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void slowFinalCommitConsumesReceiptBudget() throws Exception {
    var ds = mock(DataSource.class);
    var count = new AtomicInteger();
    when(ds.getConnection())
        .thenAnswer(
            call -> {
              var c = spy(flow.ds.getConnection());
              if (count.incrementAndGet() == 2)
                doAnswer(
                        commit -> {
                          commit.callRealMethod();
                          flow.http.advance(4000);
                          return null;
                        })
                    .when(c)
                    .commit();
              return c;
            });
    assertExpired(() -> new AdmissionEntitlementGate(ds, client).authorize(aci));
  }

  @Test
  void storageFailureIsRedactedAndMakesNoRemoteRequest() throws Exception {
    var ds = mock(DataSource.class);
    when(ds.getConnection()).thenThrow(new SQLException("sensitive fixture detail"));
    var failure =
        assertThrows(
            AdmissionEntitlementGate.UnavailableException.class,
            () -> new AdmissionEntitlementGate(ds, client).authorize(aci));
    assertThat(failure).hasMessage("Current alumni entitlement unavailable").hasNoCause();
    assertThat(requests.get()).isZero();
  }
}
