// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.Error;
import org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.Verification;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationPolicy;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxVerifyClient;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxVerifyException;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class PhoneSignupServicePostgresTest {
  private static final String NUMBER = "+13055550123";
  private static final String SOURCE = "192.0.2.10";
  private static final Duration TIMEOUT = Duration.ofSeconds(15);
  private PGSimpleDataSource ds;
  private MutableClock clock;
  private TelnyxVerifyClient provider;
  private AdmissionServiceClient admission;
  private PhoneSignupService signup;
  private ExecutorService executor;
  private UUID applicationId;
  private String nonce;

  @BeforeEach
  void setup() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test"))
      throw new IllegalArgumentException("Isolated local _test database required");
    ds = new PGSimpleDataSource();
    ds.setURL(url);
    ds.setUser("postgres");
    ds.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var connection = ds.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/011-telnyx-registration.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/013-registration-operations.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/016-phone-signup.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/017-signup-supersession.sql")));
      statement.execute("TRUNCATE signal.phone_signup_supersessions,signal.accounts,signal.phone_signup_operations,signal.registration_operations,"
          + "signal.registration_sessions,signal.registration_quotas");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-23T12:00:00Z"));
    provider = mock(TelnyxVerifyClient.class);
    admission = mock(AdmissionServiceClient.class);
    var claim = mock(AdmissionServiceClient.SignupClaim.class);
    when(claim.expiresAtMillis()).thenReturn(clock.millis() + Duration.ofMinutes(30).toMillis());
    when(admission.signupClaim(any(), anyString(), anyString())).thenReturn(claim);
    when(admission.supersedeSignup(any(), anyString(), anyString(), anyString(), any(), any(), anyString(), anyString()))
        .thenAnswer(_ -> clock.millis() + Duration.ofMinutes(30).toMillis());
    var policy = new TelnyxRegistrationPolicy(Duration.ofMinutes(10), Duration.ofHours(1),
        10, 10, 10, 3, 10, 3, Duration.ofSeconds(30), Duration.ofSeconds(1));
    var nativeRegistration = new TelnyxRegistrationService(ds, provider, policy, new byte[32], clock);
    signup = new PhoneSignupService(ds, clock, nativeRegistration, admission, new byte[32]);
    when(provider.sendSms(eq(NUMBER), eq(TIMEOUT))).thenAnswer(invocation ->
        new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 300));
    applicationId = UUID.randomUUID();
    byte[] bytes = new byte[32];
    Arrays.fill(bytes, (byte) 7);
    nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    executor = Executors.newFixedThreadPool(8);
  }

  @AfterEach
  void close() throws Exception {
    executor.shutdownNow();
    assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
  }

  private MobileEnrollmentResponse.Result call(MobileEnrollmentParser.Operation action, String suppliedNonce,
      String suppliedNumber, String code) {
    return signup.execute(action, applicationId, suppliedNonce, suppliedNumber, code, SOURCE, "en-US");
  }

  private MobileEnrollmentResponse.Result call(MobileEnrollmentParser.Operation action) {
    return call(action, nonce, NUMBER, null);
  }

  private int count(String table) throws Exception {
    try (var connection = ds.getConnection(); var statement = connection.createStatement();
         var rows = statement.executeQuery("SELECT count(*) FROM signal." + table)) {
      rows.next();
      return rows.getInt(1);
    }
  }

  @Test
  void concurrentBeginAllocatesOneDurableNativeSessionAndNoSms() throws Exception {
    CountDownLatch start = new CountDownLatch(1);
    List<CompletableFuture<MobileEnrollmentResponse.Result>> tasks = new ArrayList<>();
    for (int i = 0; i < 12; i++) tasks.add(CompletableFuture.supplyAsync(() -> {
      try { start.await(); } catch (InterruptedException e) { throw new RuntimeException(e); }
      return call(MobileEnrollmentParser.Operation.BEGIN);
    }, executor));
    start.countDown();
    CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).get(20, TimeUnit.SECONDS);
    assertThat(tasks).allSatisfy(task -> {
      assertThat(task.join().status()).isEqualTo(200);
      assertThat(((Verification) task.join().body()).phoneVerified()).isFalse();
    });
    assertThat(count("phone_signup_operations")).isEqualTo(1);
    assertThat(count("registration_sessions")).isEqualTo(1);
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(200);
    verifyNoInteractions(provider);
  }

  @Test
  void credentialsAreBoundBeforeAnyProviderOperationAndOnlySendSendsSms() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(404);
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    byte[] other = new byte[32];
    Arrays.fill(other, (byte) 8);
    String wrongNonce = Base64.getUrlEncoder().withoutPadding().encodeToString(other);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE, wrongNonce, NUMBER, null).status()).isEqualTo(401);
    assertThat(call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, "+13055550124", "123456").status())
        .isEqualTo(401);
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(200);
    verifyNoInteractions(provider);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(200);
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
  }

  @Test
  void rejectedCodeCannotConfirmAndAcceptedCodePersistsOneRetryableProof() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenReturn(false);
    var rejected = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(rejected.status()).isEqualTo(422);
    assertThat(((Error) rejected.body()).code()).isEqualTo("CODE_NOT_ACCEPTED");
    verifyNoConfirmation();

    clock.incrementSeconds(1);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenReturn(true);
    doThrow(new IllegalStateException("synthetic callback failure"))
        .doNothing().when(admission).confirmSignupPhone(eq(applicationId), anyString(), anyString(),
            anyString(), anyLong(), anyLong());
    assertThat(call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456").status())
        .isEqualTo(503);
    try (var connection = ds.getConnection(); var statement = connection.createStatement();
         var rows = statement.executeQuery("SELECT verified_at_ms,proof_expires_ms,community_confirmed "
             + "FROM signal.phone_signup_operations")) {
      rows.next();
      assertThat(rows.getLong(1)).isPositive();
      assertThat(rows.getLong(2) - rows.getLong(1)).isEqualTo(Duration.ofDays(30).toMillis());
      assertThat(rows.getBoolean(3)).isFalse();
    }
    var recovered = call(MobileEnrollmentParser.Operation.STATUS);
    assertThat(recovered.status()).isEqualTo(200);
    assertThat(((Verification) recovered.body()).phoneVerified()).isTrue();
    assertThat(((Verification) recovered.body()).registrationAuthorized()).isFalse();
    verify(admission, times(2)).confirmSignupPhone(eq(applicationId), anyString(), anyString(),
        anyString(), anyLong(), anyLong());
    verify(provider, times(2)).verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT));
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(200);
    verify(admission, times(2)).confirmSignupPhone(eq(applicationId), anyString(), anyString(),
        anyString(), anyLong(), anyLong());
  }

  @Test
  void beginRetryRecoversLostConfirmationResponseWithoutAnotherClaimSessionOrSms() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenReturn(true);
    doThrow(new IllegalStateException("synthetic lost response"))
        .doNothing().when(admission).confirmSignupPhone(eq(applicationId), anyString(), anyString(),
            anyString(), anyLong(), anyLong());
    assertThat(call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456").status())
        .isEqualTo(503);
    var retry = call(MobileEnrollmentParser.Operation.BEGIN);
    assertThat(retry.status()).isEqualTo(200);
    assertThat(((Verification) retry.body()).phoneVerified()).isTrue();
    assertThat(((Verification) retry.body()).registrationAuthorized()).isFalse();
    assertThat(count("phone_signup_operations")).isEqualTo(1);
    assertThat(count("registration_sessions")).isEqualTo(1);
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
    verify(admission, times(3)).signupClaim(eq(applicationId), anyString(), anyString());
    verify(admission, times(2)).confirmSignupPhone(eq(applicationId), anyString(), anyString(),
        anyString(), anyLong(), anyLong());
  }

  @Test
  void expiryEndsUnverifiedApplicationWithoutProviderCalls() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    clock.incrementSeconds(601);
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(410);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(410);
    verifyNoInteractions(provider);
  }

  @Test
  void codeExpiryIsDistinctFromSessionExpiryAndDoesNotAuthorizeOrSendAnotherSms() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    clock.incrementSeconds(300);
    var expired = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(expired.status()).isEqualTo(422);
    assertThat(expired.body()).isEqualTo(new Error("CODE_EXPIRED", null));
    var status = (Verification) call(MobileEnrollmentParser.Operation.STATUS).body();
    assertThat(status.phoneVerified()).isFalse();
    assertThat(status.registrationAuthorized()).isFalse();
    assertThat(status.nextCheckSeconds()).isNull();
    assertThat(status.nextSmsSeconds()).isZero();
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
    verify(provider, times(0)).verify(any(), anyString(), anyString(), any());
    verifyNoConfirmation();
    clock.incrementSeconds(300);
    var sessionExpired = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(sessionExpired.status()).isEqualTo(410);
    assertThat(sessionExpired.body()).isEqualTo(new Error("ENROLLMENT_EXPIRED", null));
  }

  @Test
  void codeExpiryDuringAcceptedProviderCheckStillReturnsExpiredWithoutProof() throws Exception {
    when(provider.sendSms(eq(NUMBER), eq(TIMEOUT))).thenReturn(
        new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 5));
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenAnswer(_ -> {
      clock.incrementSeconds(5);
      return true;
    });
    var expired = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(expired.status()).isEqualTo(422);
    assertThat(expired.body()).isEqualTo(new Error("CODE_EXPIRED", null));
    var status = (Verification) call(MobileEnrollmentParser.Operation.STATUS).body();
    assertThat(status.phoneVerified()).isFalse();
    assertThat(status.nextSmsSeconds()).isPositive();
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
    verifyNoConfirmation();
  }

  @Test
  void absentCodeAndGenericProviderErrorsAreNotInventedExpiryEvidence() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    var unsent = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(unsent.body()).isEqualTo(new Error("CODE_NOT_ACCEPTED", null));
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenThrow(
        new TelnyxVerifyException(TelnyxVerifyException.Reason.NOT_FOUND, 404,
            java.util.Optional.empty(), java.util.Optional.empty()));
    var missing = call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456");
    assertThat(missing.body()).isEqualTo(new Error("CODE_NOT_ACCEPTED", null));
    verifyNoConfirmation();
  }

  private PhoneSignupSupersessionRequest correction(String replacement) {
    byte[] bytes = new byte[32]; Arrays.fill(bytes, (byte) 9);
    return new PhoneSignupSupersessionRequest(applicationId, nonce, NUMBER, UUID.randomUUID(), replacement,
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
  }
  private void sql(String text) throws Exception {
    try (var connection = ds.getConnection(); var statement = connection.createStatement()) { statement.execute(text); }
  }

  @Test void correctionBeforeBeginLeavesPermanentTombstoneAndStableReceiptWithoutSms() throws Exception {
    var request = correction("+13055550124");
    assertThat(signup.supersede(request, true).status()).isEqualTo(404);
    assertThat(count("phone_signup_supersessions")).isZero();
    var first = signup.supersede(request, false);
    assertThat(first.status()).isEqualTo(200);
    var receipt = (MobileEnrollmentResponse.Supersession) first.body();
    assertThat(receipt.state()).isEqualTo("replacement_ready");
    assertThat(receipt.originalApplicationId()).isEqualTo(applicationId);
    assertThat(receipt.replacementApplicationId()).isNotEqualTo(applicationId).isNotEqualTo(request.correctionId());
    assertThat(receipt.registrationAuthorized()).isFalse();
    clock.incrementSeconds(3600);
    assertThat(signup.supersede(request, true)).isEqualTo(first);
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(409);
    assertThat(count("phone_signup_operations")).isZero();
    assertThat(count("registration_sessions")).isZero();
    verifyNoInteractions(provider);
  }

  @Test void correctionAuthenticatesExactOriginalAndFreezesEveryReplacementField() throws Exception {
    var request = correction(NUMBER);
    assertThat(signup.supersede(request, false).status()).isEqualTo(200);
    var changed = new PhoneSignupSupersessionRequest(applicationId, nonce, NUMBER, request.correctionId(),
        "+13055550124", request.replacementEnrollmentNonce());
    assertThat(signup.supersede(changed, true).status()).isEqualTo(409);
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(409);
    var wrong = new PhoneSignupSupersessionRequest(applicationId, request.replacementEnrollmentNonce(), NUMBER,
        request.correctionId(), NUMBER, nonce);
    assertThat(signup.supersede(wrong, true).status()).isEqualTo(401);
    assertThat(count("phone_signup_supersessions")).isEqualTo(1);
  }

  @Test void beginClaimIssuedBeforeCorrectionCannotAllocateAfterAbsenceFence() throws Exception {
    CountDownLatch claimIssued = new CountDownLatch(1), continueBegin = new CountDownLatch(1);
    var claim = mock(AdmissionServiceClient.SignupClaim.class);
    when(claim.expiresAtMillis()).thenReturn(clock.millis() + 1800000);
    when(admission.signupClaim(any(), anyString(), anyString())).thenAnswer(_ -> {
      claimIssued.countDown(); assertThat(continueBegin.await(10, TimeUnit.SECONDS)).isTrue(); return claim;
    });
    var begin = CompletableFuture.supplyAsync(() -> call(MobileEnrollmentParser.Operation.BEGIN), executor);
    assertThat(claimIssued.await(10, TimeUnit.SECONDS)).isTrue();
    try { assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(200); }
    finally { continueBegin.countDown(); }
    assertThat(begin.get(10, TimeUnit.SECONDS).status()).isEqualTo(409);
    assertThat(count("registration_sessions")).isZero();
    verifyNoInteractions(provider);
  }

  @Test void concurrentCorrectionsCreateExactlyOneReplacementAndChangedOperationCannotWin() throws Exception {
    var request = correction(NUMBER);
    List<CompletableFuture<MobileEnrollmentResponse.Result>> tasks = new ArrayList<>();
    for (int i = 0; i < 8; i++) tasks.add(CompletableFuture.supplyAsync(() -> signup.supersede(request, false), executor));
    CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    var first = tasks.getFirst().join();
    assertThat(first.status()).isEqualTo(200);
    assertThat(tasks).allSatisfy(t -> assertThat(t.join()).isEqualTo(first));
    assertThat(count("phone_signup_supersessions")).isEqualTo(1);
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(409);
    verifyNoInteractions(provider);
  }

  @Test void privateEligibilityDenialCannotInventUserConflictOrCreateFence() throws Exception {
    var denied = mock(AdmissionServiceClient.AdmissionServiceException.class);
    when(denied.failure()).thenReturn(AdmissionServiceClient.Failure.DENIED);
    doThrow(denied).when(admission).requireSignupSupersessionEligible(any(), anyString(), anyString(), anyString());
    var result = signup.supersede(correction(NUMBER), false);
    assertThat(result.body()).isEqualTo(new Error("TEMPORARILY_UNAVAILABLE", null));
    assertThat(result.status()).isEqualTo(503);
    assertThat(count("phone_signup_supersessions")).isZero();
    assertThat(count("phone_signup_operations")).isZero();
    verifyNoInteractions(provider);
  }

  @Test void overlappingExactRetryRecoversReceiptWhenItsEligibilityCheckNowSeesRetired() throws Exception {
    var request = correction(NUMBER);
    CountDownLatch eligibilityStarted = new CountDownLatch(1), finishEligibility = new CountDownLatch(1);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var denied = mock(AdmissionServiceClient.AdmissionServiceException.class);
    when(denied.failure()).thenReturn(AdmissionServiceClient.Failure.DENIED);
    org.mockito.Mockito.doAnswer(_ -> {
      if (calls.incrementAndGet() == 1) {
        eligibilityStarted.countDown(); assertThat(finishEligibility.await(10, TimeUnit.SECONDS)).isTrue();
        throw denied;
      }
      return null;
    }).when(admission).requireSignupSupersessionEligible(any(), anyString(), anyString(), anyString());
    var first = CompletableFuture.supplyAsync(() -> signup.supersede(request, false), executor);
    assertThat(eligibilityStarted.await(10, TimeUnit.SECONDS)).isTrue();
    MobileEnrollmentResponse.Result second;
    try { second = signup.supersede(request, false); }
    finally { finishEligibility.countDown(); }
    assertThat(second.status()).isEqualTo(200);
    assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo(second);
    assertThat(count("phone_signup_supersessions")).isEqualTo(1);
    verifyNoInteractions(provider);
  }

  @Test void lostPrivateReceiptRemainsRetiringAndRestartReconcilesSameOutboxWithoutSms() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    var request = correction(NUMBER);
    when(admission.supersedeSignup(any(), anyString(), anyString(), anyString(), any(), any(), anyString(), anyString()))
        .thenThrow(new IllegalStateException("synthetic lost response"))
        .thenReturn(clock.millis() + 1800000);
    var pending = signup.supersede(request, false);
    assertThat(pending.status()).isEqualTo(202);
    var provisional = (MobileEnrollmentResponse.Supersession) pending.body();
    assertThat(provisional.expiresAt()).isNull();
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(409);
    signup = new PhoneSignupService(ds, clock, mock(TelnyxRegistrationService.class), admission, new byte[32]);
    var recovered = signup.supersede(request, true);
    assertThat(recovered.status()).isEqualTo(200);
    assertThat(((MobileEnrollmentResponse.Supersession) recovered.body()).replacementApplicationId())
        .isEqualTo(provisional.replacementApplicationId());
    clock.incrementSeconds(3600);
    assertThat(signup.supersede(request, true)).isEqualTo(recovered);
    verify(admission, times(2)).supersedeSignup(eq(applicationId), anyString(), anyString(), anyString(),
        eq(request.correctionId()), eq(provisional.replacementApplicationId()), anyString(), anyString());
    verifyNoInteractions(provider);
  }

  @Test void inFlightAcceptedCheckCannotPersistProofAfterRetirement() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
    CountDownLatch issued = new CountDownLatch(1), finish = new CountDownLatch(1);
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenAnswer(_ -> {
      issued.countDown(); assertThat(finish.await(10, TimeUnit.SECONDS)).isTrue(); return true;
    });
    var check = CompletableFuture.supplyAsync(() -> call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456"), executor);
    assertThat(issued.await(10, TimeUnit.SECONDS)).isTrue();
    try { assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(200); }
    finally { finish.countDown(); }
    assertThat(check.get(10, TimeUnit.SECONDS).status()).isEqualTo(422);
    try (var c = ds.getConnection(); var q = c.createStatement();
        var r = q.executeQuery("SELECT verified_at_ms,retired_ms FROM signal.phone_signup_operations")) {
      assertThat(r.next()).isTrue(); assertThat(r.getObject(1)).isNull(); assertThat(r.getObject(2)).isNotNull();
    }
    assertThat(call(MobileEnrollmentParser.Operation.CHECK_CODE, nonce, NUMBER, "123456").status()).isEqualTo(409);
    verifyNoConfirmation();
  }

  @Test void inFlightSendCannotRestoreProviderStateOrRefundQuotaAfterRetirement() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    CountDownLatch issued = new CountDownLatch(1), finish = new CountDownLatch(1);
    when(provider.sendSms(eq(NUMBER), eq(TIMEOUT))).thenAnswer(_ -> {
      issued.countDown(); assertThat(finish.await(10, TimeUnit.SECONDS)).isTrue();
      return new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 300);
    });
    var send = CompletableFuture.supplyAsync(() -> call(MobileEnrollmentParser.Operation.SEND_CODE), executor);
    assertThat(issued.await(10, TimeUnit.SECONDS)).isTrue();
    try { assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(200); }
    finally { finish.countDown(); }
    assertThat(send.get(10, TimeUnit.SECONDS).status()).isEqualTo(503);
    try (var c = ds.getConnection(); var q = c.createStatement();
        var r = q.executeQuery("SELECT provider_verification_id,sms_count,retired_ms FROM signal.registration_sessions")) {
      assertThat(r.next()).isTrue(); assertThat(r.getObject(1)).isNull();
      assertThat(r.getInt(2)).isEqualTo(1); assertThat(r.getObject(3)).isNotNull();
    }
    assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(409);
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
    verifyNoConfirmation();
  }

  @Test void verifiedNativeSessionOrDurableProofPreventsCorrection() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    sql("UPDATE signal.registration_sessions SET verified=true");
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(409);
    assertThat(count("phone_signup_supersessions")).isZero();
    assertThat(call(MobileEnrollmentParser.Operation.STATUS).status()).isEqualTo(200);
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(409);
    assertThat(count("phone_signup_supersessions")).isZero();
  }

  @Test void existingAccountPreventsCorrectionWithoutModifyingAccount() throws Exception {
    sql("INSERT INTO signal.accounts(aci,number,pni,version,data) VALUES ('" + UUID.randomUUID()
        + "','" + NUMBER + "','" + UUID.randomUUID() + "',1,'{}')");
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(409);
    assertThat(count("phone_signup_supersessions")).isZero();
    assertThat(count("accounts")).isEqualTo(1);
    verifyNoInteractions(provider);
  }

  @Test void retirementStorageConstraintsForbidProofOrNewNativeLease() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    assertThat(signup.supersede(correction(NUMBER), false).status()).isEqualTo(200);
    for (String mutation : List.of("UPDATE signal.registration_sessions SET verified=true",
        "UPDATE signal.registration_sessions SET operation_id='" + UUID.randomUUID() + "',operation_expires_ms=1",
        "UPDATE signal.phone_signup_operations SET verified_at_ms=1,proof_expires_ms=2")) {
      var error = org.junit.jupiter.api.Assertions.assertThrows(java.sql.SQLException.class, () -> sql(mutation));
      assertThat(error.getSQLState()).isEqualTo("23514");
    }
    verifyNoInteractions(provider);
  }

  @Test void missingLiveNativeStateFailsClosedButExpiredUnprovedAttemptCanRenew() throws Exception {
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    sql("DELETE FROM signal.registration_sessions");
    var request = correction(NUMBER);
    assertThat(signup.supersede(request, false).status()).isEqualTo(503);
    assertThat(count("phone_signup_supersessions")).isZero();
    clock.incrementSeconds(1801);
    assertThat(signup.supersede(request, false).status()).isEqualTo(200);
    verifyNoInteractions(provider);
  }

  @Test void correctionDoesNotResetNumberOrSourceQuotas() throws Exception {
    var policy = new TelnyxRegistrationPolicy(Duration.ofMinutes(10), Duration.ofHours(1),
        10, 10, 3, 3, 10, 3, Duration.ofSeconds(30), Duration.ofSeconds(1));
    signup = new PhoneSignupService(ds, clock, new TelnyxRegistrationService(ds, provider, policy, new byte[32], clock),
        admission, new byte[32]);
    assertThat(call(MobileEnrollmentParser.Operation.BEGIN).status()).isEqualTo(200);
    for (int i = 0; i < 3; i++) {
      assertThat(call(MobileEnrollmentParser.Operation.SEND_CODE).status()).isEqualTo(200);
      clock.incrementSeconds(30);
    }
    var request = correction(NUMBER);
    var receipt = (MobileEnrollmentResponse.Supersession) signup.supersede(request, false).body();
    assertThat(signup.execute(MobileEnrollmentParser.Operation.BEGIN, receipt.replacementApplicationId(),
        request.replacementEnrollmentNonce(), NUMBER, null, SOURCE, null).status()).isEqualTo(200);
    assertThat(signup.execute(MobileEnrollmentParser.Operation.SEND_CODE, receipt.replacementApplicationId(),
        request.replacementEnrollmentNonce(), NUMBER, null, SOURCE, null).status()).isEqualTo(429);
    verify(provider, times(3)).sendSms(NUMBER, TIMEOUT);
  }

  private void verifyNoConfirmation() {
    verify(admission, times(0)).confirmSignupPhone(any(), anyString(), anyString(), anyString(),
        anyLong(), anyLong());
  }
}
