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
      statement.execute(Files.readString(Path.of("../bconnected/migrations/011-telnyx-registration.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/013-registration-operations.sql")));
      statement.execute(Files.readString(Path.of("../bconnected/migrations/016-phone-signup.sql")));
      statement.execute("TRUNCATE signal.phone_signup_operations,signal.registration_operations,"
          + "signal.registration_sessions,signal.registration_quotas");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-23T12:00:00Z"));
    provider = mock(TelnyxVerifyClient.class);
    admission = mock(AdmissionServiceClient.class);
    var claim = mock(AdmissionServiceClient.SignupClaim.class);
    when(claim.expiresAtMillis()).thenReturn(clock.millis() + Duration.ofMinutes(30).toMillis());
    when(admission.signupClaim(any(), anyString(), anyString())).thenReturn(claim);
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

  private void verifyNoConfirmation() {
    verify(admission, times(0)).confirmSignupPhone(any(), anyString(), anyString(), anyString(),
        anyLong(), anyLong());
  }
}
