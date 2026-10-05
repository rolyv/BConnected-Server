// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentParser.Operation.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse;
import org.whispersystems.textsecuregcm.configuration.DmAlphaConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Isolated SQL and synthetic private/provider authority; never sends a real SMS. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AccountRecoveryPostgresTest {
  AdmissionEntitlementGatePostgresTest base;
  AdmissionRegistrationCoordinatorPostgresTest flow;
  AccountRecoveryService service;
  AccountRecoveryService.Input input;
  AtomicInteger cleanups;
  Runnable cleanup = () -> {};
  UUID id;
  String originalAccount, originalBinding;

  @BeforeEach
  void setup() throws Exception {
    base = new AdmissionEntitlementGatePostgresTest();
    base.setup();
    flow = base.flow;
    try (var c = flow.ds.getConnection();
        var s = c.createStatement()) {
      for (String migration :
          List.of(
              "001-postgres",
              "002-ec-prekeys",
              "005-kem-prekeys",
              "006-profiles",
              "015-initial-prekey-publications",
              "019-account-recovery"))
        s.execute(Files.readString(Path.of("../bconnected/migrations/" + migration + ".sql")));
      s.execute(
          "TRUNCATE"
              + " signal.account_recoveries,signal.initial_prekey_publications,signal.single_use_ec_prekeys,signal.single_use_kem_prekeys,signal.messages,signal.profiles_v1,signal.profiles_v2");
    }
    originalAccount = scalar("SELECT to_jsonb(a)::text FROM signal.accounts a");
    originalBinding = scalar("SELECT (to_jsonb(a)-'status')::text FROM signal.admissions a");
    var old = flow.keys;
    var attrs =
        new AccountAttributes(
                true,
                old.attributes.getRegistrationId() + 1,
                10,
                null,
                null,
                false,
                old.attributes.getCapabilities(),
                null)
            .setUnidentifiedAccessKey(new byte[16]);
    // Both fixture identities have valid signatures; swapping them proves changed ACI and PNI keys.
    var activation =
        new DeviceActivationRequest(
            old.activation.pniSignedPreKey().orElseThrow(),
            Optional.of(old.activation.aciSignedPreKey()),
            old.activation.pniPqLastResortPreKey().orElseThrow(),
            Optional.of(old.activation.aciPqLastResortPreKey()),
            Optional.empty(),
            Optional.empty());
    var request =
        new RegistrationRequest(
            null, null, null, null, null, attrs, true, old.pni, old.aci, activation);
    input =
        new AccountRecoveryService.Input(
            AdmissionTestData.id(),
            flow.input.requestedNumber(),
            "new-synthetic-device-password",
            request,
            "iOS",
            "Signal-iOS/8.30");
    var member = flow.input.memberId();
    var other = UUID.randomUUID();
    byte[] requestKey = new byte[32];
    Arrays.fill(requestKey, (byte) 1);
    var config =
        new DmAlphaConfiguration(
            Set.of(member, other),
            Map.of(member, phoneHash(input.number()), other, phoneHash("+13055550999")),
            new SecretBytes(requestKey),
            new SecretBytes(new byte[32]),
            Map.of(
                "test",
                Base64.getEncoder().encodeToString(flow.http.key.getPublic().getEncoded())));
    cleanups = new AtomicInteger();
    service =
        new AccountRecoveryService(
            flow.ds,
            flow.http.clock,
            flow.nativeSessions,
            flow.http.client,
            config,
            account -> {
              cleanups.incrementAndGet();
              cleanup.run();
            });
    id = observation(service.execute(BEGIN, null, input, null, "192.0.2.1", null)).recoveryId();
  }

  @AfterEach
  void close() throws Exception {
    if (base != null) base.close();
  }

  String scalar(String query) throws Exception {
    try (var c = flow.ds.getConnection();
        var s = c.createStatement();
        var r = s.executeQuery(query)) {
      r.next();
      return r.getString(1);
    }
  }

  static String phoneHash(String phone) throws Exception {
    var mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
    return HexFormat.of()
        .formatHex(mac.doFinal(("bconnected.phone.v1\0" + phone).getBytes(StandardCharsets.UTF_8)));
  }

  static AccountRecoveryService.Observation observation(MobileEnrollmentResponse.Result result) {
    assertThat(result.status()).isIn(200, 202);
    assertThat(result.body()).isInstanceOf(AccountRecoveryService.Observation.class);
    return (AccountRecoveryService.Observation) result.body();
  }

  static void error(MobileEnrollmentResponse.Result result, int status, String code) {
    assertThat(result.status()).isEqualTo(status);
    assertThat(((MobileEnrollmentResponse.Error) result.body()).code()).isEqualTo(code);
  }

  MobileEnrollmentResponse.Result status() {
    return service.execute(STATUS, id, input, null, null, null);
  }

  MobileEnrollmentResponse.Result complete() {
    return service.execute(COMPLETE, id, input, null, null, null);
  }

  void verified() throws Exception {
    flow.sql(
        "UPDATE signal.registration_sessions SET verified=true,verified_at_ms="
            + flow.http.clock.millis()
            + " WHERE id=(SELECT session_id FROM signal.account_recoveries)");
    assertThat(observation(status()).state()).isEqualTo("awaiting_authorization");
  }

  void granted() throws Exception {
    verified();
    flow.http.recoveryStatus = "authorized";
  }

  void unchanged() throws Exception {
    assertThat(scalar("SELECT to_jsonb(a)::text FROM signal.accounts a"))
        .isEqualTo(originalAccount);
    assertThat(scalar("SELECT (to_jsonb(a)-'status')::text FROM signal.admissions a"))
        .isEqualTo(originalBinding);
    assertThat(cleanups).hasValue(0);
  }

  @Test
  void beginAndExactRetryAreNonDestructiveAndDoNotRevealAccount() throws Exception {
    var result = observation(service.execute(BEGIN, null, input, null, "192.0.2.1", null));
    assertThat(result.recoveryId()).isEqualTo(id);
    assertThat(result.state()).isEqualTo("verification");
    assertThat(result.memberId()).isNull();
    assertThat(result.account()).isNull();
    assertThat(result.fullName()).isNull();
    assertThat(flow.count("SELECT count(*) FROM signal.account_recoveries")).isEqualTo(1);
    unchanged();
    verifyNoInteractions(flow.provider);
  }

  @Test
  void newPasswordAndCompleteRequestAreBothRequired() throws Exception {
    var bad =
        new AccountRecoveryService.Input(
            input.attempt(),
            input.number(),
            "wrong",
            input.request(),
            input.signalAgent(),
            input.userAgent());
    error(service.execute(STATUS, id, bad, null, null, null), 401, "INVALID_CREDENTIALS");
    var changed =
        new AccountRecoveryService.Input(
            input.attempt(),
            input.number(),
            input.password(),
            input.request(),
            input.signalAgent(),
            "changed");
    error(service.execute(STATUS, id, changed, null, null, null), 409, "RECOVERY_CONFLICT");
    unchanged();
  }

  @Test
  void missingOperationCannotCreateOrSend() throws Exception {
    error(
        service.execute(SEND_CODE, UUID.randomUUID(), input, null, null, null),
        404,
        "RECOVERY_UNAVAILABLE");
    unchanged();
    verifyNoInteractions(flow.provider);
  }

  @Test
  void noProofCannotConsumeGrantOrChangeAccount() throws Exception {
    flow.http.recoveryStatus = "authorized";
    error(complete(), 403, "RECOVERY_NOT_AUTHORIZED");
    unchanged();
  }

  @Test
  void freshProofAloneCannotReplaceEstablishedAccount() throws Exception {
    verified();
    error(complete(), 403, "RECOVERY_NOT_AUTHORIZED");
    unchanged();
  }

  @Test
  void preMigrationVerifiedSessionHasNoUsableRecoveryTime() throws Exception {
    flow.sql(
        "UPDATE signal.registration_sessions SET verified=true WHERE id=(SELECT session_id FROM"
            + " signal.account_recoveries)");
    error(status(), 404, "RECOVERY_UNAVAILABLE");
    unchanged();
  }

  @Test
  void lostCheckResponseUsesOriginalNativeVerificationTime() throws Exception {
    flow.sql(
        "UPDATE signal.registration_sessions SET verified=true,verified_at_ms="
            + flow.http.clock.millis()
            + " WHERE id=(SELECT session_id FROM signal.account_recoveries)");
    flow.http.advance(300_001);
    error(status(), 410, "RECOVERY_EXPIRED");
    unchanged();
  }

  @Test
  void confirmedReceiptCannotStartReplacementAfterPhoneProofExpires() throws Exception {
    granted();
    flow.http.recoveryStatus = "confirmed";
    flow.http.advance(300_001);
    error(complete(), 410, "RECOVERY_EXPIRED");
    unchanged();
  }

  @Test
  void statusNeverStartsDestructivePhase() throws Exception {
    granted();
    var status = observation(status());
    assertThat(status.state()).isEqualTo("authorized");
    assertThat(status.account().aci()).isEqualTo(base.aci);
    assertThat(status.memberId()).isEqualTo(flow.input.memberId());
    assertThat(status.fullName()).isEqualTo("Synthetic Alumni");
    assertThat(status.registrationAuthorized()).isFalse();
    unchanged();
  }

  @Test
  void replacementPreservesIdentityAndAdmissionAndInvalidatesOldCredential() throws Exception {
    granted();
    var old = base.gate.authorizeDevice(base.aci, Device.PRIMARY_ID, flow.input.password());
    var result = observation(complete());
    assertThat(result.state()).isEqualTo("active");
    assertThat(result.registrationAuthorized()).isTrue();
    assertThat(result.account().aci()).isEqualTo(base.aci);
    assertThat(result.account().number()).isEqualTo(input.number());
    assertThat(scalar("SELECT (to_jsonb(a)-'status')::text FROM signal.admissions a"))
        .isEqualTo(originalBinding);
    assertThat(scalar("SELECT pni::text FROM signal.accounts"))
        .isEqualTo(SystemMapper.jsonMapper().readTree(originalAccount).get("pni").asText());
    assertThrows(RuntimeException.class, () -> old.requireCurrent(base.aci, Device.PRIMARY_ID));
    assertThrows(
        RuntimeException.class,
        () -> base.gate.authorizeDevice(base.aci, Device.PRIMARY_ID, flow.input.password()));
    base.gate
        .authorizeDevice(base.aci, Device.PRIMARY_ID, input.password())
        .requireCurrent(base.aci, Device.PRIMARY_ID);
    long previousCreated =
        SystemMapper.jsonMapper()
            .readTree(originalAccount)
            .get("data")
            .get("devices")
            .get(0)
            .get("created")
            .asLong();
    long nextCreated =
        Long.parseLong(scalar("SELECT replacement_generation FROM signal.account_recoveries"));
    assertThat(nextCreated & ~127L).isGreaterThan(previousCreated & ~127L);
    assertThat(cleanups).hasValue(1);
    assertThat(flow.count("SELECT count(*) FROM signal.signed_prekeys")).isEqualTo(4);
  }

  @Test
  void expiredUnconfirmedCompletionIntentCannotConsumeOrReplace() throws Exception {
    granted();
    flow.sql("UPDATE signal.account_recoveries SET completion_requested=true");
    flow.http.advance(300_001);
    error(status(), 410, "RECOVERY_EXPIRED");
    assertThat(flow.http.recoveryStatus).isEqualTo("authorized");
    unchanged();
  }

  @Test
  void consumedGrantLostResponseResumesAfterProofExpiryWithoutAnotherGrant() throws Exception {
    granted();
    flow.http.afterRecovery =
        () -> {
          if (flow.http.recoveryStatus.equals("confirmed"))
            throw new IllegalStateException("lost confirmation response");
        };
    error(complete(), 503, "TEMPORARILY_UNAVAILABLE");
    assertThat(scalar("SELECT state FROM signal.account_recoveries")).isEqualTo("REQUESTED");
    assertThat(scalar("SELECT completion_requested FROM signal.account_recoveries")).isEqualTo("t");
    unchanged();
    flow.http.afterRecovery = () -> {};
    flow.http.advance(600_000);
    assertThat(observation(status()).state()).isEqualTo("active");
    assertThat(cleanups).hasValue(1);
  }

  @Test
  void cleanupFailureKeepsBothCredentialsFencedAndExactStatusResumesAfterExpiry() throws Exception {
    granted();
    cleanup =
        () -> {
          throw new IllegalStateException("synthetic cleanup failure");
        };
    error(complete(), 503, "TEMPORARILY_UNAVAILABLE");
    assertThat(scalar("SELECT status FROM signal.admissions")).isEqualTo("RECOVERING");
    assertThrows(
        RuntimeException.class,
        () -> base.gate.authorizeDevice(base.aci, Device.PRIMARY_ID, input.password()));
    assertThrows(
        RuntimeException.class,
        () -> base.gate.authorizeDevice(base.aci, Device.PRIMARY_ID, flow.input.password()));
    cleanup = () -> {};
    flow.http.advance(600_000);
    assertThat(observation(status()).state()).isEqualTo("active");
    assertThat(cleanups).hasValue(2);
    assertThat(observation(status()).state()).isEqualTo("active");
    assertThat(cleanups).hasValue(2);
  }

  @Test
  void operatorUsesExactSameFrozenExecutionWithoutPassword() throws Exception {
    granted();
    String hash = scalar("SELECT request_hash FROM signal.account_recoveries");
    error(service.completeOperator(id, "0".repeat(64)), 404, "RECOVERY_UNAVAILABLE");
    unchanged();
    assertThat(observation(service.completeOperator(id, hash)).state()).isEqualTo("active");
    assertThat(observation(status()).state()).isEqualTo("active");
    assertThat(cleanups).hasValue(1);
  }

  @Test
  void concurrentCleanupCannotRunAgainAfterOtherRequestActivates() throws Exception {
    granted();
    var entered = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    cleanup =
        () -> {
          entered.countDown();
          try {
            assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          }
        };
    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      var first = executor.submit(this::complete);
      assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
      assertThat(observation(status()).state()).isEqualTo("recovering");
      release.countDown();
      assertThat(observation(first.get(5, TimeUnit.SECONDS)).state()).isEqualTo("active");
      assertThat(observation(status()).state()).isEqualTo("active");
      assertThat(cleanups).hasValue(1);
    } finally {
      release.countDown();
    }
  }

  @Test
  void accountDriftAfterGrantCannotBeAdopted() throws Exception {
    granted();
    flow.sql("UPDATE signal.accounts SET version=version+1");
    error(complete(), 409, "RECOVERY_CONFLICT");
    assertThat(cleanups).hasValue(0);
    assertThat(scalar("SELECT status FROM signal.admissions")).isEqualTo("ACTIVE");
  }

  @ParameterizedTest
  @ValueSource(strings = {"SUSPENDED", "PENDING"})
  void admissionStateChangePreventsReplacement(String state) throws Exception {
    granted();
    flow.sql("UPDATE signal.admissions SET status='" + state + "'");
    error(complete(), 404, "RECOVERY_UNAVAILABLE");
    assertThat(cleanups).hasValue(0);
    assertThat(scalar("SELECT to_jsonb(a)::text FROM signal.accounts a"))
        .isEqualTo(originalAccount);
  }

  @Test
  void stalePrivateProofAfterLockWaitRollsBackReplacement() throws Exception {
    granted();
    flow.http.afterRecovery = () -> flow.http.advance(4001);
    error(complete(), 503, "TEMPORARILY_UNAVAILABLE");
    unchanged();
  }

  @Test
  void changedPrivateTranscriptIsRejected() throws Exception {
    granted();
    flow.http.mutateRecovery = body -> body.put("recovery", Map.of());
    error(complete(), 503, "TEMPORARILY_UNAVAILABLE");
    unchanged();
  }

  @Test
  void cleanupCannotActivateSuspendedAdmission() throws Exception {
    granted();
    cleanup =
        () ->
            base.sql(
                "UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    error(complete(), 404, "RECOVERY_UNAVAILABLE");
    assertThat(scalar("SELECT state FROM signal.account_recoveries")).isEqualTo("RECOVERING");
    assertThat(scalar("SELECT status FROM signal.admissions")).isEqualTo("SUSPENDED");
  }
}
