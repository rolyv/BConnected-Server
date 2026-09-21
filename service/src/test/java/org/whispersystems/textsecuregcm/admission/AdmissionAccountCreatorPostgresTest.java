// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.whispersystems.textsecuregcm.storage.*;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionAccountCreatorPostgresTest {
  // Reuse the existing isolated coordinator/provider fixture, not its JUnit test methods.
  AdmissionRegistrationCoordinatorPostgresTest flow;
  AdmissionAccountCreator creator;

  @BeforeEach
  void setup() throws Exception {
    flow = new AdmissionRegistrationCoordinatorPostgresTest();
    flow.setup();
    try (var c = flow.ds.getConnection();
        var s = c.createStatement()) {
      for (String migration : List.of("004-registration", "012-admission"))
        s.execute(Files.readString(Path.of("../bconnected/migrations/" + migration + ".sql")));
      s.execute(
          "ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT IF EXISTS"
              + " creator_reject_outbox");
      s.execute("ALTER TABLE signal.signed_prekeys DROP CONSTRAINT IF EXISTS creator_reject_kem");
      s.execute(
          "TRUNCATE"
              + " signal.admission_confirmation_outbox,signal.admissions,signal.signed_prekeys,signal.phone_recovery_passwords,signal.deleted_accounts,signal.phone_number_identifiers");
    }
    creator =
        new AdmissionAccountCreator(
            flow.ds, flow.http.clock, flow.operations, Duration.ofDays(300));
  }

  @AfterEach
  void close() throws Exception {
    try {
      if (flow != null) {
        flow.sql(
            "ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT IF EXISTS"
                + " creator_reject_outbox");
        flow.sql("ALTER TABLE signal.signed_prekeys DROP CONSTRAINT IF EXISTS creator_reject_kem");
        verifyNoInteractions(
            flow.provider); // Verification state is synthetic; no SMS/provider request.
      }
    } finally {
      if (flow != null) flow.close();
    }
  }

  AdmissionRegistrationCoordinator.AttestedRegistration attest() throws Exception {
    flow.begin();
    flow.sql("UPDATE signal.registration_sessions SET verified=true");
    return flow.coordinator.attestVerifiedPhone(flow.input);
  }

  AdmissionRegistrationCoordinator.Input input(UUID member, String attempt, String password) {
    return new AdmissionRegistrationCoordinator.Input(
        member,
        attempt,
        flow.input.bindingChallenge(),
        flow.input.requestedNumber(),
        password,
        flow.keys.request(),
        flow.input.signalAgent(),
        flow.input.userAgent());
  }

  void noAccountWrites() throws Exception {
    for (String table :
        List.of(
            "accounts",
            "signed_prekeys",
            "phone_recovery_passwords",
            "admissions",
            "admission_confirmation_outbox"))
      assertThat(flow.count("SELECT count(*) FROM signal." + table)).as(table).isZero();
  }

  @Test
  void accountKeysRecoveryAndPendingOutboxCommitWithOriginalAuthentication() throws Exception {
    var attested = attest();
    var result = creator.createOrResumePending(flow.input, attested);
    assertThat(result.status()).isEqualTo("PENDING");
    assertThat(result.confirmed()).isFalse();
    assertThat(result.registrationAuthorized()).isFalse();
    assertThat(flow.count("SELECT count(*) FROM signal.signed_prekeys")).isEqualTo(4);
    assertThat(flow.count("SELECT count(*) FROM signal.phone_recovery_passwords")).isEqualTo(1);
    assertThat(flow.count("SELECT count(*) FROM signal.admission_confirmation_outbox"))
        .isEqualTo(1);
    var account =
        new AccountsPostgres(flow.ds, flow.http.clock, Runnable::run)
            .getByAccountIdentifier(result.aci())
            .orElseThrow();
    var expected = new Device();
    attested.operation().applyAuthenticationTo(expected);
    assertThat(account.getPrimaryDevice().getAuthTokenHash())
        .isEqualTo(expected.getAuthTokenHash());
    assertThat(account.getAccountIdentityKey()).isEqualTo(flow.keys.aci);
    assertThat(account.getPhoneNumberIdentityKey()).contains(flow.keys.pni);
    assertThat(account.getPrimaryDevice().getAuthTokenHash().verify(flow.input.password()))
        .isTrue();
    assertThat(
            SignedPreKeysPostgres.ec(flow.ds, Runnable::run)
                .find(result.aci(), Device.PRIMARY_ID)
                .join())
        .contains(flow.keys.activation.aciSignedPreKey());
    assertThat(
            SignedPreKeysPostgres.kem(flow.ds, Runnable::run)
                .find(account.getPhoneNumberIdentifier().orElseThrow(), Device.PRIMARY_ID)
                .join())
        .contains(flow.keys.activation.pniPqLastResortPreKey().orElseThrow());
  }

  @Test
  void concurrentExactRetriesConvergeWithoutReclaimOrVerifierChange() throws Exception {
    var attested = attest();
    var results = new ArrayList<Future<AdmissionAccountCreator.Status>>();
    for (int i = 0; i < 8; i++)
      results.add(flow.executor.submit(() -> creator.createOrResumePending(flow.input, attested)));
    var first = results.getFirst().get(15, TimeUnit.SECONDS);
    for (var result : results) assertThat(result.get(15, TimeUnit.SECONDS)).isEqualTo(first);
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isEqualTo(1);
    assertThat(flow.count("SELECT count(*) FROM signal.signed_prekeys")).isEqualTo(4);
    assertThat(flow.count("SELECT count(*) FROM signal.admissions")).isEqualTo(1);
  }

  @Test
  void wrongPasswordAndChangedRequestCannotConsumeAttestation() throws Exception {
    var attested = attest();
    assertThrows(
        RuntimeException.class,
        () ->
            creator.createOrResumePending(
                input(flow.input.memberId(), flow.input.attemptNonce(), "different-password"),
                attested));
    flow.keys.attributes.setDiscoverableByPhoneNumber(true);
    assertThrows(
        RuntimeException.class,
        () ->
            creator.createOrResumePending(
                input(flow.input.memberId(), flow.input.attemptNonce(), flow.input.password()),
                attested));
    noAccountWrites();
  }

  @Test
  void attestationCannotBeSubstitutedForAnotherMember() throws Exception {
    var attested = attest();
    assertThrows(
        RuntimeException.class,
        () ->
            creator.createOrResumePending(
                input(UUID.randomUUID(), AdmissionTestData.id(), flow.input.password()), attested));
    noAccountWrites();
  }

  @Test
  void lateOutboxFailureRollsBackAccountAllKeysRecoveryAndAdmission() throws Exception {
    var attested = attest();
    flow.sql(
        "ALTER TABLE signal.admission_confirmation_outbox ADD CONSTRAINT creator_reject_outbox"
            + " CHECK(false) NOT VALID");
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
  }

  @Test
  void partialKeyFailureRollsBackEverything() throws Exception {
    var attested = attest();
    flow.sql(
        "ALTER TABLE signal.signed_prekeys ADD CONSTRAINT creator_reject_kem CHECK(kind <> 'kem')"
            + " NOT VALID");
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
  }

  @Test
  void expiredPermitCannotCreateAccount() throws Exception {
    var attested = attest();
    flow.http.advance(31000);
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
  }

  @Test
  void expiredUncommittedOperationCannotBeReopened() throws Exception {
    var attested = attest();
    flow.http.advance(301000);
    assertThat(creator.findCommittedStatus(flow.input)).isEmpty();
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
  }

  @Test
  void lostResponseCanResumeAfterExpiryButLocalActiveNeverAuthorizes() throws Exception {
    var attested = attest();
    var original = creator.createOrResumePending(flow.input, attested);
    flow.http.advance(301000);
    assertThat(creator.findCommittedStatus(flow.input)).contains(original);
    assertThat(creator.createOrResumePending(flow.input, attested)).isEqualTo(original);
    flow.sql("UPDATE signal.admissions SET status='ACTIVE'");
    var active = creator.findCommittedStatus(flow.input).orElseThrow();
    assertThat(active.aci()).isEqualTo(original.aci());
    assertThat(active.status()).isEqualTo("ACTIVE");
    assertThat(active.registrationAuthorized()).isFalse();
    assertThrows(
        RuntimeException.class,
        () ->
            creator.findCommittedStatus(
                input(flow.input.memberId(), flow.input.attemptNonce(), "wrong")));
    assertThat(
            creator.findCommittedStatus(
                input(flow.input.memberId(), AdmissionTestData.id(), flow.input.password())))
        .isEmpty();
    assertThat(flow.count("SELECT count(*) FROM signal.registration_operations")).isEqualTo(1);
  }

  @Test
  void nativeVerificationAndClaimBindingAreRecheckedOnAccountTransaction() throws Exception {
    var attested = attest();
    flow.sql("UPDATE signal.registration_sessions SET verified=false");
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
    flow.sql("UPDATE signal.registration_sessions SET verified=true");
    flow.sql("UPDATE signal.registration_operations SET claim_approval_epoch=8");
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
  }

  @Test
  void deletedOriginalAccountCannotBeResurrectedByExactRetry() throws Exception {
    var attested = attest();
    creator.createOrResumePending(flow.input, attested);
    flow.sql("DELETE FROM signal.accounts");
    assertThrows(RuntimeException.class, () -> creator.findCommittedStatus(flow.input));
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
  }

  @Test
  void anotherMemberCannotReassociatePhoneFromDeletedSpentAdmission() throws Exception {
    creator.createOrResumePending(flow.input, attest());
    flow.sql("DELETE FROM signal.accounts");
    flow.input = input(UUID.randomUUID(), AdmissionTestData.id(), flow.input.password());
    var second = attest();
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, second));
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
    assertThat(flow.count("SELECT count(*) FROM signal.admissions")).isEqualTo(1);
    assertThat(flow.count("SELECT count(*) FROM signal.signed_prekeys")).isEqualTo(4);
  }

  @Test
  void retainedPniHistoryRejectsChangedPhoneBindingAndHistoricalNumberAlias() throws Exception {
    creator.createOrResumePending(flow.input, attest());
    // Model a historical normalized-number alias plus a rotated phone-binding HMAC.
    // The permanent PNI mapping is retained even when account and tombstone are absent.
    flow.sql("UPDATE signal.registration_operations SET requested_number='+18005550002'");
    flow.sql(
        "INSERT INTO signal.phone_number_identifiers(e164,pni) SELECT '+18005550002',pni FROM"
            + " signal.accounts");
    flow.sql("UPDATE signal.admissions SET phone_binding=decode(repeat('f',64),'hex')");
    flow.sql("DELETE FROM signal.accounts");
    flow.input = input(UUID.randomUUID(), AdmissionTestData.id(), flow.input.password());
    var second = attest();
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, second));
    assertThat(flow.count("SELECT count(*) FROM signal.accounts")).isZero();
    assertThat(flow.count("SELECT count(*) FROM signal.admissions")).isEqualTo(1);
    assertThat(flow.count("SELECT count(*) FROM signal.signed_prekeys")).isEqualTo(4);
  }

  @Test
  void accountInsertWaitsForDeletionThenRejectsNewTombstone() throws Exception {
    var attested = attest();
    var pni =
        new PhoneNumberIdentifiersPostgres(flow.ds, Runnable::run)
            .getPhoneNumberIdentifier(flow.input.requestedNumber())
            .join();
    var old = new Account();
    old.setAccountIdentifier(UUID.randomUUID());
    old.setNumber(flow.input.requestedNumber(), pni);
    old.addDevice(
        org.whispersystems.textsecuregcm.tests.util.DevicesHelper.createDevice(
            Device.PRIMARY_ID, flow.http.clock.millis(), 100));
    new AccountsPostgres(flow.ds, flow.http.clock, Runnable::run)
        .createWithMutations(old, List.of());
    try (var blocker = flow.ds.getConnection();
        var s = blocker.createStatement()) {
      blocker.setAutoCommit(false);
      s.execute("DELETE FROM signal.accounts");
      try (var tombstone =
          blocker.prepareStatement(
              "INSERT INTO signal.deleted_accounts(pni,aci,expires_at) VALUES(?,?,?)")) {
        tombstone.setObject(1, pni);
        tombstone.setObject(2, old.getAccountIdentifier());
        tombstone.setLong(3, flow.http.clock.instant().plusSeconds(3600).getEpochSecond());
        tombstone.executeUpdate();
      }
      var task = flow.executor.submit(() -> creator.createOrResumePending(flow.input, attested));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (flow.count(
              "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND"
                  + " wait_event_type='Lock' AND query LIKE 'INSERT INTO signal.accounts%'")
          == 0) {
        if (System.nanoTime() > deadline)
          throw new AssertionError("Creator did not reach blocked account insert");
        Thread.sleep(10);
      }
      blocker.commit();
      assertThrows(ExecutionException.class, () -> task.get(10, TimeUnit.SECONDS));
    }
    noAccountWrites();
    assertThat(flow.count("SELECT count(*) FROM signal.deleted_accounts")).isEqualTo(1);
  }

  @Test
  void deletedPhoneTombstoneIsNotConsumedByFreshEnrollment() throws Exception {
    var attested = attest();
    var pni =
        new PhoneNumberIdentifiersPostgres(flow.ds, Runnable::run)
            .getPhoneNumberIdentifier(flow.input.requestedNumber())
            .join();
    try (var c = flow.ds.getConnection();
        var s =
            c.prepareStatement(
                "INSERT INTO signal.deleted_accounts(pni,aci,expires_at) VALUES(?,?,?)")) {
      s.setObject(1, pni);
      s.setObject(2, UUID.randomUUID());
      s.setLong(3, flow.http.clock.instant().plusSeconds(3600).getEpochSecond());
      s.executeUpdate();
    }
    assertThrows(RuntimeException.class, () -> creator.createOrResumePending(flow.input, attested));
    noAccountWrites();
    assertThat(flow.count("SELECT count(*) FROM signal.deleted_accounts")).isEqualTo(1);
  }

  @Test
  void permitExpiryDuringBlockedKeyWriteRollsBackAccountAndKeys() throws Exception {
    var attested = attest();
    try (var blocker = flow.ds.getConnection();
        var s = blocker.createStatement()) {
      blocker.setAutoCommit(false);
      s.execute("LOCK TABLE signal.signed_prekeys IN ACCESS EXCLUSIVE MODE");
      var task = flow.executor.submit(() -> creator.createOrResumePending(flow.input, attested));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (flow.count(
              "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND"
                  + " wait_event_type='Lock' AND query LIKE 'INSERT INTO signal.signed_prekeys%'")
          == 0) {
        if (System.nanoTime() > deadline)
          throw new AssertionError("Creator did not reach blocked key write");
        Thread.sleep(10);
      }
      flow.http.advance(31000);
      blocker.commit();
      assertThrows(ExecutionException.class, () -> task.get(10, TimeUnit.SECONDS));
    }
    noAccountWrites();
  }
}
