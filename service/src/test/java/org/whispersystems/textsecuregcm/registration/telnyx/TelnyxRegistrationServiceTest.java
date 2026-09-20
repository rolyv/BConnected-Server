// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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
import org.whispersystems.textsecuregcm.auth.InvalidRegistrationSessionException;
import org.whispersystems.textsecuregcm.auth.PhoneVerificationTokenManager;
import org.whispersystems.textsecuregcm.auth.UnverifiedRegistrationSessionException;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.VerificationSessionRateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.ClientType;
import org.whispersystems.textsecuregcm.registration.MessageTransport;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceException;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceSenderException;
import org.whispersystems.textsecuregcm.registration.TransportNotAllowedException;
import org.whispersystems.textsecuregcm.spam.RegistrationRecoveryChecker;
import org.whispersystems.textsecuregcm.storage.PhoneNumberIdentifierStore;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class TelnyxRegistrationServiceTest {
  private static final String NUMBER = "+13055550123";
  private static final Duration TIMEOUT = Duration.ofSeconds(10);
  private static final byte[] COLLATION_KEY = new byte[32];
  private PGSimpleDataSource dataSource;
  private MutableClock clock;
  private TelnyxVerifyClient provider;
  private TelnyxRegistrationPolicy policy;
  private TelnyxRegistrationService service;
  private ExecutorService executor;

  @BeforeEach
  void setUp() throws Exception {
    final String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/011-telnyx-registration.sql")));
      statement.execute("TRUNCATE signal.registration_sessions, signal.registration_quotas");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    provider = mock(TelnyxVerifyClient.class);
    policy = policy(10, 10, 10, 3, 10, 3);
    service = coordinator();
    executor = Executors.newFixedThreadPool(12);
    when(provider.sendSms(anyString(), any())).thenAnswer(invocation ->
        new TelnyxVerifyClient.Verification(UUID.randomUUID(), invocation.getArgument(0), 300));
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdownNow();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }
  }

  @Test
  void sessionCreationIsDurableAndNeverSendsOrVerifies() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    assertThat(created.id()).hasSize(32);
    assertThat(created.number()).isEqualTo(NUMBER);
    assertThat(created.verified()).isFalse();
    assertThat(created.nextSms()).isZero();
    assertThat(created.nextVoiceCall()).isNull();
    assertThat(created.nextVerificationAttempt()).isNull();
    assertThat(created.expiration()).isEqualTo(600);
    assertThat(coordinator().getSession(created.id(), TIMEOUT).orElseThrow().encodedSessionId())
        .isEqualTo(created.encodedSessionId());
    assertThat(service.getSession(new byte[31], TIMEOUT)).isEmpty();
    verifyNoInteractions(provider);
  }

  @Test
  void onlyExplicitAcceptedCodeVerifiesAndExistingTokenChecksRemainEffective() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    final UUID verificationId = UUID.randomUUID();
    when(provider.sendSms(NUMBER, TIMEOUT)).thenReturn(new TelnyxVerifyClient.Verification(verificationId, NUMBER, 300));
    final PhoneVerificationTokenManager tokens = new PhoneVerificationTokenManager(mock(PhoneNumberIdentifierStore.class),
        service, mock(PhoneNumberRecoveryPasswordsManager.class), mock(RegistrationRecoveryChecker.class));
    assertThrows(UnverifiedRegistrationSessionException.class,
        () -> tokens.verify(NUMBER, null, null, null, created.id(), null));
    assertThat(send(created.id()).verified()).isFalse();
    assertThrows(UnverifiedRegistrationSessionException.class,
        () -> tokens.verify(NUMBER, null, null, null, created.id(), null));
    when(provider.verify(verificationId, NUMBER, "123456", TIMEOUT)).thenReturn(false, true);
    assertThat(service.checkVerificationCode(created.id(), "123456", TIMEOUT).verified()).isFalse();
    clock.incrementSeconds(1);
    assertThat(service.checkVerificationCode(created.id(), "123456", TIMEOUT).verified()).isTrue();
    assertThat(coordinator().getSession(created.id(), TIMEOUT).orElseThrow().verified()).isTrue();
    tokens.verify(NUMBER, null, null, null, created.id(), null);
    assertThrows(InvalidRegistrationSessionException.class,
        () -> tokens.verify("+13055550124", null, null, null, created.id(), null));
    assertThrows(RegistrationServiceException.class, () -> send(created.id()));
    clock.incrementSeconds(599);
    assertThat(service.getSession(created.id(), TIMEOUT)).isEmpty();
    assertThrows(UnverifiedRegistrationSessionException.class,
        () -> tokens.verify(NUMBER, null, null, null, created.id(), null));
  }

  @Test
  void sessionCreationQuotasSpanSessionsNumbersAndProcessInstances() throws Exception {
    policy = policy(2, 2, 10, 3, 10, 3);
    service = coordinator();
    create(NUMBER, "192.0.2.1");
    create(NUMBER, "192.0.2.2");
    assertThrows(RateLimitExceededException.class, () -> coordinator().createRegistrationSession(
        PhoneNumberUtil.getInstance().parse(NUMBER, null), "192.0.2.3", false, null, null, TIMEOUT));
    create("+13055550124", "192.0.2.1");
    assertThrows(RateLimitExceededException.class, () -> create("+13055550125", "192.0.2.1"));
    verifyNoInteractions(provider);
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement();
         var rows = statement.executeQuery("SELECT scope, octet_length(key_hash) FROM signal.registration_quotas")) {
      while (rows.next()) assertThat(rows.getInt(2)).isEqualTo(32);
    }
  }

  @Test
  void concurrentSessionCreationCannotOversubscribePhoneQuota() throws Exception {
    policy = policy(2, 30, 10, 3, 10, 3);
    service = coordinator();
    final CountDownLatch start = new CountDownLatch(1);
    final List<CompletableFuture<Boolean>> attempts = new ArrayList<>();
    for (int i = 0; i < 24; i++) {
      final String source = "192.0.2." + (i + 1);
      attempts.add(CompletableFuture.supplyAsync(() -> {
        await(start);
        try { create(NUMBER, source); return true; }
        catch (RateLimitExceededException e) { return false; }
        catch (Exception e) { throw new RuntimeException(e); }
      }, executor));
    }
    start.countDown();
    CompletableFuture.allOf(attempts.toArray(CompletableFuture[]::new)).get(20, TimeUnit.SECONDS);
    assertThat(attempts.stream().filter(CompletableFuture::join).count()).isEqualTo(2);
  }

  @Test
  void concurrentSendHasOneProviderCallAndCommitsReservationBeforeNetwork() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch complete = new CountDownLatch(1);
    when(provider.sendSms(NUMBER, TIMEOUT)).thenAnswer(_ -> {
      entered.countDown(); await(complete);
      return new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 300);
    });
    final CompletableFuture<RegistrationServiceSession> first = CompletableFuture.supplyAsync(() -> {
      try { return send(created.id()); } catch (Exception e) { throw new RuntimeException(e); }
    }, executor);
    try {
      await(entered);
      assertThat(sessionColumn(created.id(), "sms_count")).isEqualTo(1);
      assertThat(coordinator().getSession(created.id(), TIMEOUT).orElseThrow().nextSms()).isGreaterThan(0);
      assertThrows(VerificationSessionRateLimitExceededException.class, () -> send(created.id()));
    } finally { complete.countDown(); }
    assertThat(first.get(15, TimeUnit.SECONDS).verified()).isFalse();
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
  }

  @Test
  void phoneSmsBudgetCannotBeBypassedByStartingAnotherSession() throws Exception {
    policy = policy(10, 10, 1, 3, 10, 3);
    service = coordinator();
    final RegistrationServiceSession first = create(NUMBER, "192.0.2.1");
    final RegistrationServiceSession second = create(NUMBER, "192.0.2.2");
    send(first.id());
    assertThrows(VerificationSessionRateLimitExceededException.class, () -> send(second.id()));
    assertThat(sessionColumn(second.id(), "sms_count")).isZero();
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
  }

  @Test
  void ambiguousSendConsumesBudgetAndDoesNotRetryOrCreateVerifiedState() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    when(provider.sendSms(NUMBER, TIMEOUT)).thenThrow(providerError(TelnyxVerifyException.Reason.TRANSPORT_FAILURE));
    assertThrows(RegistrationServiceSenderException.class, () -> send(created.id()));
    assertThat(sessionColumn(created.id(), "sms_count")).isEqualTo(1);
    final RegistrationServiceSession persisted = coordinator().getSession(created.id(), TIMEOUT).orElseThrow();
    assertThat(persisted.verified()).isFalse();
    assertThat(persisted.nextSms()).isEqualTo(30);
    assertThat(persisted.nextVerificationAttempt()).isNull();
    assertThrows(VerificationSessionRateLimitExceededException.class, () -> send(created.id()));
    assertThrows(RegistrationServiceException.class, () -> service.checkVerificationCode(created.id(), "123456", TIMEOUT));
    verify(provider, times(1)).sendSms(NUMBER, TIMEOUT);
    verify(provider, never()).verify(any(), anyString(), anyString(), any());
  }

  @Test
  void malformedCodesConsumeNeitherCheckBudgetNorOperationLease() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    send(created.id());
    for (String code : List.of("123", "12345678901", "12x456", " 123456", "")) {
      assertThrows(IllegalArgumentException.class, () -> service.checkVerificationCode(created.id(), code, TIMEOUT));
    }
    assertThrows(IllegalArgumentException.class, () -> service.checkVerificationCode(created.id(), null, TIMEOUT));
    assertThat(sessionColumn(created.id(), "check_count")).isZero();
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().nextVerificationAttempt()).isZero();
    verify(provider, never()).verify(any(), anyString(), anyString(), any());
  }

  @Test
  void wrongCodesAreCountedAndChecksAreLimitedAcrossSessions() throws Exception {
    policy = policy(10, 10, 10, 3, 2, 3);
    service = coordinator();
    final RegistrationServiceSession first = create(NUMBER, "192.0.2.1");
    final RegistrationServiceSession second = create(NUMBER, "192.0.2.2");
    send(first.id()); send(second.id());
    assertThat(service.checkVerificationCode(first.id(), "123456", TIMEOUT).verified()).isFalse();
    assertThrows(VerificationSessionRateLimitExceededException.class,
        () -> service.checkVerificationCode(first.id(), "123456", TIMEOUT));
    assertThat(service.checkVerificationCode(second.id(), "123456", TIMEOUT).verified()).isFalse();
    clock.incrementSeconds(1);
    assertThrows(VerificationSessionRateLimitExceededException.class,
        () -> coordinator().checkVerificationCode(first.id(), "123456", TIMEOUT));
    verify(provider, times(2)).verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT));
  }

  @Test
  void sessionCheckBudgetCannotBeResetByResending() throws Exception {
    policy = policy(10, 10, 10, 3, 20, 1);
    service = coordinator();
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    send(created.id());
    service.checkVerificationCode(created.id(), "123456", TIMEOUT);
    clock.incrementSeconds(30);
    send(created.id());
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().nextVerificationAttempt()).isNull();
    assertThrows(VerificationSessionRateLimitExceededException.class,
        () -> service.checkVerificationCode(created.id(), "123456", TIMEOUT));
    verify(provider, times(1)).verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT));
  }

  @Test
  void expiredCodesCannotBeCheckedAndSessionExpiryIsExact() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    send(created.id());
    clock.incrementSeconds(300);
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().nextVerificationAttempt()).isNull();
    assertThrows(RegistrationServiceException.class, () -> service.checkVerificationCode(created.id(), "123456", TIMEOUT));
    clock.incrementSeconds(300);
    assertThat(service.getSession(created.id(), TIMEOUT)).isEmpty();
    assertThrows(RegistrationServiceException.class, () -> send(created.id()));
    verify(provider, never()).verify(any(), anyString(), anyString(), any());
  }

  @Test
  void staleAcceptedCheckCannotVerifyAfterANewerSendReplacesItsOperation() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    final UUID oldProviderId = UUID.randomUUID();
    final UUID newProviderId = UUID.randomUUID();
    when(provider.sendSms(NUMBER, TIMEOUT)).thenReturn(
        new TelnyxVerifyClient.Verification(oldProviderId, NUMBER, 300),
        new TelnyxVerifyClient.Verification(newProviderId, NUMBER, 300));
    send(created.id());
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch complete = new CountDownLatch(1);
    when(provider.verify(oldProviderId, NUMBER, "123456", TIMEOUT)).thenAnswer(_ -> {
      entered.countDown(); await(complete); return true;
    });
    final CompletableFuture<Boolean> oldCheck = CompletableFuture.supplyAsync(() -> {
      try { return service.checkVerificationCode(created.id(), "123456", TIMEOUT).verified(); }
      catch (RegistrationServiceException e) { return false; }
      catch (Exception e) { throw new RuntimeException(e); }
    }, executor);
    try {
      await(entered);
      clock.incrementSeconds(31);
      assertThat(send(created.id()).verified()).isFalse();
    } finally { complete.countDown(); }
    assertThat(oldCheck.get(15, TimeUnit.SECONDS)).isFalse();
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().verified()).isFalse();
    when(provider.verify(newProviderId, NUMBER, "123456", TIMEOUT)).thenReturn(true);
    assertThat(service.checkVerificationCode(created.id(), "123456", TIMEOUT).verified()).isTrue();
    verify(provider).verify(newProviderId, NUMBER, "123456", TIMEOUT);
  }

  @Test
  void acceptedResponseAfterCodeExpiryCannotVerify() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    when(provider.sendSms(NUMBER, TIMEOUT)).thenReturn(new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 5));
    send(created.id());
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT))).thenAnswer(_ -> {
      clock.incrementSeconds(5); return true;
    });
    assertThrows(RegistrationServiceException.class, () -> service.checkVerificationCode(created.id(), "123456", TIMEOUT));
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().verified()).isFalse();
  }

  @Test
  void providerRateLimitPersistsCooldownAndMissingVerificationDisablesChecking() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    when(provider.sendSms(NUMBER, TIMEOUT)).thenThrow(new TelnyxVerifyException(TelnyxVerifyException.Reason.RATE_LIMITED,
        429, Optional.of(Duration.ofSeconds(90)), Optional.empty()));
    assertThrows(VerificationSessionRateLimitExceededException.class, () -> send(created.id()));
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().nextSms()).isEqualTo(90);
    clock.incrementSeconds(90);
    doReturn(new TelnyxVerifyClient.Verification(UUID.randomUUID(), NUMBER, 300)).when(provider).sendSms(NUMBER, TIMEOUT);
    send(created.id());
    when(provider.verify(any(), eq(NUMBER), eq("123456"), eq(TIMEOUT)))
        .thenThrow(providerError(TelnyxVerifyException.Reason.NOT_FOUND));
    assertThrows(RegistrationServiceException.class, () -> service.checkVerificationCode(created.id(), "123456", TIMEOUT));
    assertThat(service.getSession(created.id(), TIMEOUT).orElseThrow().nextVerificationAttempt()).isNull();
  }

  @Test
  void unsupportedTransportAndSenderOverrideNeverSend() throws Exception {
    final RegistrationServiceSession created = create(NUMBER, "192.0.2.1");
    assertThrows(TransportNotAllowedException.class, () -> service.sendVerificationCode(created.id(),
        MessageTransport.VOICE, ClientType.IOS, null, null, TIMEOUT));
    assertThrows(RegistrationServiceSenderException.class, () -> service.sendVerificationCode(created.id(),
        MessageTransport.SMS, ClientType.IOS, null, "different-provider", TIMEOUT));
    assertThat(sessionColumn(created.id(), "sms_count")).isZero();
    verifyNoInteractions(provider);
  }

  @Test
  void cleanupIsBoundedAndCannotResetCurrentWindowQuotas() throws Exception {
    create(NUMBER, "192.0.2.1");
    create(NUMBER, "192.0.2.2");
    clock.incrementSeconds(600);
    assertThat(service.deleteExpired(1)).isEqualTo(1);
    assertThat(service.deleteExpired(1)).isEqualTo(1);
    assertThat(service.deleteExpired(1)).isZero();
    clock.incrementSeconds(3000);
    assertThat(service.deleteExpired(1)).isEqualTo(1);
    assertThrows(IllegalArgumentException.class, () -> service.deleteExpired(0));
  }

  private TelnyxRegistrationService coordinator() {
    return new TelnyxRegistrationService(dataSource, provider, policy, COLLATION_KEY, clock);
  }

  private RegistrationServiceSession create(final String number, final String source) throws Exception {
    return service.createRegistrationSession(PhoneNumberUtil.getInstance().parse(number, null), source,
        false, null, null, TIMEOUT);
  }

  private RegistrationServiceSession send(final byte[] id) throws Exception {
    return service.sendVerificationCode(id, MessageTransport.SMS, ClientType.IOS, null, null, TIMEOUT);
  }

  private long sessionColumn(final byte[] id, final String column) throws Exception {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(
        "SELECT " + column + " FROM signal.registration_sessions WHERE id=?")) {
      statement.setBytes(1, id);
      try (var rows = statement.executeQuery()) { rows.next(); return rows.getLong(1); }
    }
  }

  private static TelnyxRegistrationPolicy policy(final int sessionsNumber, final int sessionsSource, final int smsNumber,
      final int smsSession, final int checksNumber, final int checksSession) {
    return new TelnyxRegistrationPolicy(Duration.ofMinutes(10), Duration.ofHours(1), sessionsNumber, sessionsSource,
        smsNumber, smsSession, checksNumber, checksSession, Duration.ofSeconds(30), Duration.ofSeconds(1));
  }

  private static TelnyxVerifyException providerError(final TelnyxVerifyException.Reason reason) {
    return new TelnyxVerifyException(reason, 503, Optional.empty(), Optional.empty());
  }

  private static void await(final CountDownLatch latch) {
    try {
      if (!latch.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent provider operation timed out");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt(); throw new AssertionError(e);
    }
  }
}
