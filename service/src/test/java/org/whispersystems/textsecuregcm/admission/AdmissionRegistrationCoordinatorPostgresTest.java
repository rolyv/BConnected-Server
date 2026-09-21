// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.registration.telnyx.*;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionRegistrationCoordinatorPostgresTest {
  static final String NUMBER = "+13055550123", PASSWORD = "synthetic-original-password";
  static final Duration TIMEOUT = Duration.ofSeconds(3);
  PGSimpleDataSource ds;
  AdmissionProtocolFixture http;
  RegistrationOperations operations;
  TelnyxVerifyClient provider;
  TelnyxRegistrationService nativeSessions;
  AdmissionRegistrationCoordinator coordinator;
  RegistrationOperationFixture keys;
  AdmissionRegistrationCoordinator.Input input;
  ExecutorService executor;

  @BeforeEach
  void setup() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test"))
      throw new IllegalArgumentException("Isolated local test database required");
    ds = new PGSimpleDataSource();
    ds.setURL(url);
    ds.setUser("postgres");
    ds.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      for (String migration :
          List.of(
              "003-accounts",
              "011-telnyx-registration",
              "013-registration-operations",
              "014-registration-claims"))
        s.execute(Files.readString(Path.of("../bconnected/migrations/" + migration + ".sql")));
      s.execute(
          "TRUNCATE"
              + " signal.registration_operations,signal.registration_sessions,signal.registration_quotas,signal.accounts");
    }
    http = new AdmissionProtocolFixture();
    operations =
        new RegistrationOperations(ds, http.clock, new RegistrationRequestCommitment(new byte[32]));
    provider = mock(TelnyxVerifyClient.class);
    nativeSessions =
        new TelnyxRegistrationService(
            ds,
            provider,
            new TelnyxRegistrationPolicy(
                Duration.ofMinutes(10),
                Duration.ofHours(1),
                20,
                20,
                20,
                5,
                20,
                5,
                Duration.ofSeconds(1),
                Duration.ofSeconds(1)),
            new byte[32],
            http.clock);
    coordinator =
        new AdmissionRegistrationCoordinator(
            operations, http.client, nativeSessions, http.verifier, new byte[32]);
    keys = new RegistrationOperationFixture();
    input =
        new AdmissionRegistrationCoordinator.Input(
            UUID.randomUUID(),
            AdmissionTestData.id(),
            AdmissionTestData.id(),
            NUMBER,
            PASSWORD,
            keys.request(),
            "iOS",
            "Signal-iOS/1");
    executor = Executors.newFixedThreadPool(8);
    when(provider.sendSms(eq(NUMBER), any()))
        .thenAnswer(
            call -> {
              assertThat(
                      count(
                          "SELECT count(*) FROM"
                              + " signal.registration_operations WHERE"
                              + " verification_session_id IS NOT NULL AND"
                              + " claim_approval_epoch=7"))
                  .isEqualTo(1);
              return new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 300);
            });
  }

  @AfterEach
  void close() throws Exception {
    if (executor != null) {
      executor.shutdownNow();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }
    if (http != null) http.close();
  }

  int count(String sql) throws Exception {
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var r = s.executeQuery(sql)) {
      r.next();
      return r.getInt(1);
    }
  }

  void sql(String sql) throws Exception {
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      s.execute(sql);
    }
  }

  RegistrationOperations.AuthenticatedOperation operation() {
    return operations.prepareOrAuthenticateRetry(
        input.memberId(),
        input.attemptNonce(),
        input.bindingChallenge(),
        NUMBER,
        PASSWORD,
        input.request(),
        input.signalAgent(),
        input.userAgent());
  }

  AdmissionRegistrationCoordinator.SessionStatus begin() throws Exception {
    return coordinator.begin(input, "192.0.2.1", TIMEOUT);
  }

  void send() throws Exception {
    coordinator.sendCode(input, "en", TIMEOUT);
  }

  void check() throws Exception {
    coordinator.checkCode(input, "123456", TIMEOUT);
  }

  @Test
  void rejectedPrivateClaimNeverCreatesSessionQuotaOrProviderCall() throws Exception {
    http.claimStatus = 403;
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::begin);
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isZero();
    assertThat(count("SELECT count(*) FROM signal.registration_quotas")).isZero();
    verifyNoInteractions(provider);
  }

  @Test
  void concurrentExactBeginCreatesOneNativeSessionAndOneQuotaAttempt() throws Exception {
    List<Future<AdmissionRegistrationCoordinator.SessionStatus>> futures = new ArrayList<>();
    for (int i = 0; i < 8; i++) futures.add(executor.submit(this::begin));
    var first = futures.getFirst().get(10, TimeUnit.SECONDS);
    for (var future : futures)
      assertThat(future.get(10, TimeUnit.SECONDS).operationId()).isEqualTo(first.operationId());
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isEqualTo(1);
    assertThat(
            count(
                "SELECT sum(attempts) FROM signal.registration_quotas WHERE"
                    + " scope='create:number'"))
        .isEqualTo(1);
    assertThat(
            count(
                "SELECT count(*) FROM signal.registration_operations WHERE"
                    + " claim_approval_epoch=7 AND verification_session_id IS NOT"
                    + " NULL"))
        .isEqualTo(1);
    verifyNoInteractions(provider);
    assertThat(first.toString()).isEqualTo("RegistrationSessionStatus[redacted]");
  }

  @Test
  void missingAssociationSendCheckAndAttestationNeverCreateSessionOrTouchProvider()
      throws Exception {
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::send);
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::check);
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.attestVerifiedPhone(input));
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isZero();
    verifyNoInteractions(provider);
  }

  @Test
  void everyResendAndCheckReclaimsAndSuspensionBlocksProvider() throws Exception {
    begin();
    send();
    assertThat(http.claims).hasSize(2);
    http.claimStatus = 403;
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::send);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::check);
    verify(provider, times(1)).sendSms(eq(NUMBER), any());
    verify(provider, never()).verify(any(), anyString(), anyString(), any());
  }

  @Test
  void explicitAcceptedNativeVerificationRequiredBeforeSignedPermit() throws Exception {
    begin();
    send();
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.attestVerifiedPhone(input));
    when(provider.verify(any(), eq(NUMBER), eq("123456"), any())).thenReturn(false, true);
    assertThat(coordinator.checkCode(input, "123456", TIMEOUT).verified()).isFalse();
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.attestVerifiedPhone(input));
    http.advance(1000);
    assertThat(coordinator.checkCode(input, "123456", TIMEOUT).verified()).isTrue();
    var first = coordinator.attestVerifiedPhone(input);
    var retry = coordinator.attestVerifiedPhone(input);
    assertThat(first.permit().permitId()).isEqualTo(retry.permit().permitId());
    assertThat(first.permit().binding().canonicalVerifiedNumber()).isEqualTo(NUMBER);
    // Independently generated with Python HMAC-SHA256 over the documented framing.
    assertThat(first.permit().binding().phoneBinding())
        .isEqualTo("3a45319842b4f609f11afcb46339911c933fe9b1a57d9ba81d6da5ed97d52f0f");
    assertThat(http.attestations.getFirst().toString())
        .doesNotContain(NUMBER)
        .doesNotContain(PASSWORD)
        .doesNotContain("123456");
    assertThat(count("SELECT count(*) FROM signal.accounts")).isZero();
  }

  @Test
  void changedPasswordRequestAndClientSessionFailBeforePrivateOrProviderCalls() throws Exception {
    begin();
    int claims = http.claims.size();
    var changed =
        new AdmissionRegistrationCoordinator.Input(
            input.memberId(),
            input.attemptNonce(),
            input.bindingChallenge(),
            NUMBER,
            "changed",
            input.request(),
            input.signalAgent(),
            input.userAgent());
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.sendCode(changed, "en", TIMEOUT));
    keys.session = AdmissionTestData.id();
    var imported =
        new AdmissionRegistrationCoordinator.Input(
            input.memberId(),
            input.attemptNonce(),
            input.bindingChallenge(),
            NUMBER,
            PASSWORD,
            keys.request(),
            input.signalAgent(),
            input.userAgent());
    assertThrows(
        CanonicalRegistrationRequest.InvalidRequestException.class,
        () -> coordinator.begin(imported, "192.0.2.1", TIMEOUT));
    keys.session = null;
    keys.recovery = new byte[32];
    var recovery =
        new AdmissionRegistrationCoordinator.Input(
            input.memberId(),
            input.attemptNonce(),
            input.bindingChallenge(),
            NUMBER,
            PASSWORD,
            keys.request(),
            input.signalAgent(),
            input.userAgent());
    assertThrows(
        CanonicalRegistrationRequest.InvalidRequestException.class,
        () -> coordinator.begin(recovery, "192.0.2.1", TIMEOUT));
    assertThat(http.claims).hasSize(claims);
    verifyNoInteractions(provider);
  }

  @Test
  void changedClaimEpochOrDeadlineCannotReplacePersistedAssociation() throws Exception {
    begin();
    http.epoch++;
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::send);
    http.epoch--;
    http.expires -= 1000;
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::check);
    assertThat(count("SELECT claim_approval_epoch FROM signal.registration_operations"))
        .isEqualTo(7);
    verifyNoInteractions(provider);
  }

  @Test
  void nativeSessionQuotaAndAssociationRollbackTogetherIfClaimExpiresAfterCreation()
      throws Exception {
    var op = operation();
    var claim = http.client.claim(op, input.bindingChallenge());
    var number = PhoneNumberUtil.getInstance().parse(NUMBER, null);
    assertThrows(
        AdmissionServiceClient.AdmissionServiceException.class,
        () ->
            operations.getOrCreateClaimedSession(
                op,
                claim,
                connection -> {
                  var created =
                      nativeSessions.createRegistrationSessionInTransaction(
                          connection, number, "192.0.2.1", TIMEOUT, claim::requireFresh);
                  http.advance(4000);
                  return created;
                }));
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isZero();
    assertThat(count("SELECT count(*) FROM signal.registration_quotas")).isZero();
    assertThat(
            count(
                "SELECT count(*) FROM signal.registration_operations WHERE"
                    + " claim_approval_epoch IS NOT NULL OR verification_session_id"
                    + " IS NOT NULL"))
        .isZero();
  }

  @Test
  void explicitTransactionRequiredAndCallerRollbackDoesNotLeaveSession() throws Exception {
    var number = PhoneNumberUtil.getInstance().parse(NUMBER, null);
    try (var connection = ds.getConnection()) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              nativeSessions.createRegistrationSessionInTransaction(
                  connection, number, "192.0.2.1", TIMEOUT, () -> {}));
      connection.setAutoCommit(false);
      nativeSessions.createRegistrationSessionInTransaction(
          connection, number, "192.0.2.1", TIMEOUT, () -> {});
      connection.rollback();
    }
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isZero();
  }

  @Test
  void operationLockWaitConsumesClaimFreshnessAndNeverCreatesSession() throws Exception {
    var op = operation();
    var claim = http.client.claim(op, input.bindingChallenge());
    try (var connection = ds.getConnection()) {
      connection.setAutoCommit(false);
      try (var statement = connection.createStatement()) {
        statement.execute("SELECT operation_id FROM signal.registration_operations FOR UPDATE");
      }
      var future =
          executor.submit(
              () ->
                  operations.getOrCreateClaimedSession(
                      op,
                      claim,
                      c -> {
                        throw new AssertionError("Must not create");
                      }));
      awaitLock("registration_operations");
      http.advance(4000);
      connection.commit();
      assertThat(
              assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS))
                  .getCause())
          .isInstanceOf(AdmissionServiceClient.AdmissionServiceException.class);
    }
    assertThat(count("SELECT count(*) FROM signal.registration_sessions")).isZero();
  }

  @Test
  void sendQuotaLockWaitExpiresApprovalAfterReservationWithoutRefundOrProviderCall()
      throws Exception {
    begin();
    send();
    http.advance(1000);
    blockedReservation("send:number", this::send);
    verify(provider, times(1)).sendSms(eq(NUMBER), any());
    assertThat(count("SELECT sms_count FROM signal.registration_sessions")).isEqualTo(2);
    assertThat(
            count("SELECT attempts FROM signal.registration_quotas WHERE" + " scope='send:number'"))
        .isEqualTo(2);
  }

  @Test
  void checkQuotaLockWaitExpiresApprovalAfterReservationWithoutProviderCall() throws Exception {
    begin();
    send();
    when(provider.verify(any(), eq(NUMBER), eq("123456"), any())).thenReturn(false);
    check();
    http.advance(1000);
    blockedReservation("check:number", this::check);
    verify(provider, times(1)).verify(any(), eq(NUMBER), eq("123456"), any());
    assertThat(count("SELECT check_count FROM signal.registration_sessions")).isEqualTo(2);
  }

  @Test
  void verifiedSessionExpiryOrChangedDestinationBlocksAttestation() throws Exception {
    begin();
    send();
    when(provider.verify(any(), eq(NUMBER), eq("123456"), any())).thenReturn(true);
    check();
    sql("UPDATE signal.registration_sessions SET number='+13055550124'");
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.attestVerifiedPhone(input));
    sql(
        "UPDATE signal.registration_sessions SET number='"
            + NUMBER
            + "',expires_ms="
            + http.clock.millis());
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> coordinator.attestVerifiedPhone(input));
    assertThat(http.attestations).isEmpty();
  }

  @Test
  void malformedCodeAndMissingTrustedAddressRejectBeforeAnyPreparationOrPrivateCall()
      throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> coordinator.checkCode(input, "123abc", TIMEOUT));
    assertThrows(IllegalArgumentException.class, () -> coordinator.begin(input, " ", TIMEOUT));
    assertThat(http.claims).isEmpty();
    assertThat(count("SELECT count(*) FROM signal.registration_operations")).isZero();
    verifyNoInteractions(provider);
  }

  interface ThrowingRunnable {
    void run() throws Exception;
  }

  void blockedReservation(String scope, ThrowingRunnable action) throws Exception {
    try (var connection = ds.getConnection()) {
      connection.setAutoCommit(false);
      try (var statement =
          connection.prepareStatement(
              "SELECT * FROM signal.registration_quotas WHERE scope=? FOR UPDATE")) {
        statement.setString(1, scope);
        statement.executeQuery().close();
      }
      var future =
          executor.submit(
              () -> {
                action.run();
                return null;
              });
      awaitLock("registration_quotas");
      http.advance(4000);
      connection.commit();
      assertThat(
              assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS))
                  .getCause())
          .isInstanceOf(AdmissionServiceClient.AdmissionServiceException.class);
    }
  }

  void awaitLock(String table) throws Exception {
    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < until) {
      if (count(
              "SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND"
                  + " datname=current_database() AND wait_event_type='Lock' AND query"
                  + " LIKE '%"
                  + table
                  + "%'")
          > 0) return;
      Thread.sleep(10);
    }
    throw new AssertionError("Expected blocked SQL operation");
  }
}
