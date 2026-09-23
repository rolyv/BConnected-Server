// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class RegistrationOperationsPostgresTest {
  private PGSimpleDataSource ds;
  private MutableClock clock;
  private RegistrationOperations operations;
  private RegistrationOperationFixture fixture;
  private ExecutorService executor;
  private UUID member;
  private String attempt, challenge;
  private static final String NUMBER = "+13055550123",
      PASSWORD = "synthetic-original-authentication";

  @BeforeEach
  void setup() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test"))
      throw new IllegalArgumentException("Isolated local _test database required");
    ds = new PGSimpleDataSource();
    ds.setURL(url);
    ds.setUser("postgres");
    ds.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      s.execute(Files.readString(Path.of("../bconnected/migrations/011-telnyx-registration.sql")));
      s.execute(
          Files.readString(Path.of("../bconnected/migrations/013-registration-operations.sql")));
      s.execute(Files.readString(Path.of("../bconnected/migrations/014-registration-claims.sql")));
      s.execute(Files.readString(Path.of("../bconnected/migrations/016-phone-signup.sql")));
      s.execute(
          "TRUNCATE"
              + " signal.phone_signup_operations,signal.registration_operations,signal.registration_sessions,"
              + "signal.registration_quotas,signal.accounts");
    }
    clock = new MutableClock().setTimeInstant(Instant.parse("2026-09-20T12:00:00Z"));
    operations =
        new RegistrationOperations(ds, clock, new RegistrationRequestCommitment(new byte[32]));
    fixture = new RegistrationOperationFixture();
    member = UUID.randomUUID();
    attempt = nonce(1);
    challenge = nonce(2);
    executor = Executors.newFixedThreadPool(8);
  }

  @AfterEach
  void close() throws Exception {
    executor.shutdown();
    assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
  }

  private static String nonce(int seed) {
    byte[] b = new byte[32];
    Arrays.fill(b, (byte) seed);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private RegistrationOperations.AuthenticatedOperation prepare() {
    return operations.prepareOrAuthenticateRetry(
        member, attempt, challenge, NUMBER, PASSWORD, fixture.request(), "iOS", "Signal-iOS/1");
  }

  private int count() throws Exception {
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var r = s.executeQuery("SELECT count(*) FROM signal.registration_operations")) {
      r.next();
      return r.getInt(1);
    }
  }

  private byte[] session(String number, boolean verified, long expiry) throws Exception {
    byte[] id = Base64.getUrlDecoder().decode(AdmissionTestData.id());
    try (var c = ds.getConnection();
        var s =
            c.prepareStatement(
                "INSERT INTO signal.registration_sessions(id,number,verified,expires_ms)"
                    + " VALUES(?,?,?,?)")) {
      s.setBytes(1, id);
      s.setString(2, number);
      s.setBoolean(3, verified);
      s.setLong(4, expiry);
      s.executeUpdate();
    }
    return id;
  }

  private void setVerified(byte[] session) throws Exception {
    try (var c = ds.getConnection();
        var s =
            c.prepareStatement(
                "UPDATE signal.registration_sessions SET verified=true WHERE id=?")) {
      s.setBytes(1, session);
      s.executeUpdate();
    }
  }

  private static String sha256(String value) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
        .digest(value.getBytes(StandardCharsets.UTF_8)));
  }

  private AdmissionServiceClient.FreshClaim signupClaim(UUID proofId, String nonceHash) {
    var claim = mock(AdmissionServiceClient.FreshClaim.class);
    when(claim.signupProofId()).thenReturn(proofId);
    when(claim.communitySessionHash()).thenReturn(nonceHash);
    when(claim.approvalEpoch()).thenReturn(1L);
    when(claim.expiresAtMillis()).thenReturn(clock.millis() + 240_000);
    return claim;
  }

  private UUID insertSignupProof(String number, String nonceHash, boolean confirmed,
      long verifiedAt, long proofExpires) throws Exception {
    UUID proofId = UUID.randomUUID();
    byte[] nativeSession = new byte[32];
    new java.security.SecureRandom().nextBytes(nativeSession);
    long now = clock.millis();
    try (var connection = ds.getConnection()) {
      try (var insertSession = connection.prepareStatement("""
          INSERT INTO signal.registration_sessions(id,number,expires_ms,verified)
          VALUES(?,?,?,true)
          """)) {
        insertSession.setBytes(1, nativeSession);
        insertSession.setString(2, number);
        insertSession.setLong(3, now + 600_000);
        insertSession.executeUpdate();
      }
      try (var insertProof = connection.prepareStatement("""
          INSERT INTO signal.phone_signup_operations
            (operation_id,nonce_hash,phone_lookup_hash,requested_number,native_session_id,
             native_session_expires_ms,created_ms,application_expires_ms,verified_at_ms,
             proof_expires_ms,community_confirmed)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)
          """)) {
        insertProof.setObject(1, proofId);
        insertProof.setString(2, nonceHash);
        insertProof.setString(3, "a".repeat(64));
        insertProof.setString(4, number);
        insertProof.setBytes(5, nativeSession);
        insertProof.setLong(6, now + 600_000);
        insertProof.setLong(7, now);
        insertProof.setLong(8, now + 1_800_000);
        insertProof.setLong(9, verifiedAt);
        insertProof.setLong(10, proofExpires);
        insertProof.setBoolean(11, confirmed);
        insertProof.executeUpdate();
      }
    }
    return proofId;
  }

  @Test
  void confirmedSignupProofAttachesOnceAndCannotBeConsumedByAnotherOperation() throws Exception {
    var first = prepare();
    String nonceHash = sha256(nonce(7));
    UUID proofId = insertSignupProof(NUMBER, nonceHash, true, clock.millis(),
        clock.millis() + java.time.Duration.ofDays(30).toMillis());
    var claim = signupClaim(proofId, nonceHash);
    operations.attachSignupProof(first, claim);
    assertThat(operations.hasSignupProof(first)).isTrue();
    var verified = operations.readVerifiedPhone(first);
    assertThat(verified.operationId()).isEqualTo(first.operationId());
    assertThat(verified.canonicalNumber()).isEqualTo(NUMBER);
    operations.attachSignupProof(first, claim); // Exact retry must be idempotent.

    attempt = nonce(9);
    challenge = nonce(10);
    var second = prepare();
    assertThrows(RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachSignupProof(second, signupClaim(proofId, nonceHash)));
    try (var connection = ds.getConnection();
         var query = connection.prepareStatement("""
             SELECT consumed_registration_operation_id,consumed_member_id
             FROM signal.phone_signup_operations WHERE operation_id=?
             """)) {
      query.setObject(1, proofId);
      try (var rows = query.executeQuery()) {
        assertThat(rows.next()).isTrue();
        assertThat(rows.getObject(1, UUID.class)).isEqualTo(first.operationId());
        assertThat(rows.getObject(2, UUID.class)).isEqualTo(member);
      }
    }
  }

  @Test
  void signupProofRejectsUnconfirmedExpiredNonceAndPhoneMismatch() throws Exception {
    var operation = prepare();
    String nonceHash = sha256(nonce(7));
    long now = clock.millis();
    UUID proofId = insertSignupProof(NUMBER, nonceHash, false, now, now + 600_000);
    var matching = signupClaim(proofId, nonceHash);
    assertThrows(RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachSignupProof(operation, matching));
    try (var connection = ds.getConnection(); var update = connection.prepareStatement("""
        UPDATE signal.phone_signup_operations SET community_confirmed=true,
          verified_at_ms=?,proof_expires_ms=? WHERE operation_id=?
        """)) {
      update.setLong(1, now - 120_000);
      update.setLong(2, now - 60_000);
      update.setObject(3, proofId);
      update.executeUpdate();
    }
    assertThrows(RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachSignupProof(operation, matching));
    try (var connection = ds.getConnection(); var update = connection.prepareStatement("""
        UPDATE signal.phone_signup_operations SET verified_at_ms=?,proof_expires_ms=?
        WHERE operation_id=?
        """)) {
      update.setLong(1, now);
      update.setLong(2, now + 600_000);
      update.setObject(3, proofId);
      update.executeUpdate();
    }
    assertThrows(RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachSignupProof(operation, signupClaim(proofId, sha256(nonce(8)))));
    try (var connection = ds.getConnection(); var update = connection.prepareStatement("""
        UPDATE signal.phone_signup_operations SET requested_number=? WHERE operation_id=?
        """)) {
      update.setString(1, "+13055550124");
      update.setObject(2, proofId);
      update.executeUpdate();
    }
    assertThrows(RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachSignupProof(operation, matching));
    assertThat(operations.hasSignupProof(operation)).isFalse();
  }

  @Test
  void exactRetryRestoresSameServerOperationVerifierAndCommitmentWithoutSecrets() throws Exception {
    var first = prepare();
    var repeat = prepare();
    assertThat(repeat.operationId()).isEqualTo(first.operationId());
    assertThat(repeat.serverRequestCommitment()).isEqualTo(first.serverRequestCommitment());
    assertThat(first.challengeHash())
        .isEqualTo(
            java.util.HexFormat.of()
                .formatHex(
                    java.security.MessageDigest.getInstance("SHA-256")
                        .digest(challenge.getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
    assertThat(count()).isEqualTo(1);
    var device = new Device();
    first.applyAuthenticationTo(device);
    assertThat(device.getAuthTokenHash().verify(PASSWORD)).isTrue();
    assertThat(first.toString()).isEqualTo("AuthenticatedOperation[redacted]");
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var r =
            s.executeQuery("SELECT row_to_json(o)::text FROM signal.registration_operations o")) {
      r.next();
      assertThat(r.getString(1))
          .doesNotContain(PASSWORD)
          .doesNotContain(attempt)
          .doesNotContain(challenge)
          .doesNotContain("canonical_request");
    }
  }

  @Test
  void changedPasswordRequestChallengeDestinationAndAgentAreRejectedWithoutChangingRow()
      throws Exception {
    var first = prepare();
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () ->
            operations.prepareOrAuthenticateRetry(
                member,
                attempt,
                challenge,
                NUMBER,
                "different",
                fixture.request(),
                "iOS",
                "Signal-iOS/1"));
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () ->
            operations.prepareOrAuthenticateRetry(
                member,
                attempt,
                nonce(3),
                NUMBER,
                PASSWORD,
                fixture.request(),
                "iOS",
                "Signal-iOS/1"));
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () ->
            operations.prepareOrAuthenticateRetry(
                member,
                attempt,
                challenge,
                "+13055550124",
                PASSWORD,
                fixture.request(),
                "iOS",
                "Signal-iOS/1"));
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () ->
            operations.prepareOrAuthenticateRetry(
                member,
                attempt,
                challenge,
                NUMBER,
                PASSWORD,
                fixture.request(),
                "Android",
                "Signal-iOS/1"));
    fixture.attributes.setDiscoverableByPhoneNumber(true);
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::prepare);
    fixture.attributes.setDiscoverableByPhoneNumber(false);
    assertThat(prepare().operationId()).isEqualTo(first.operationId());
    assertThat(count()).isEqualTo(1);
  }

  @Test
  void simultaneousIdenticalRetriesConvergeOnOneServerId() throws Exception {
    var futures = new ArrayList<CompletableFuture<UUID>>();
    for (int i = 0; i < 8; i++)
      futures.add(CompletableFuture.supplyAsync(() -> prepare().operationId(), executor));
    assertThat(futures.stream().map(CompletableFuture::join).distinct().count()).isEqualTo(1);
    assertThat(count()).isEqualTo(1);
  }

  @Test
  void competingPasswordsCannotReplaceTheWinningVerifier() throws Exception {
    var futures = new ArrayList<CompletableFuture<String>>();
    for (int i = 0; i < 8; i++) {
      String password = "contender-" + i;
      futures.add(
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  operations.prepareOrAuthenticateRetry(
                      member,
                      attempt,
                      challenge,
                      NUMBER,
                      password,
                      fixture.request(),
                      "iOS",
                      "Signal-iOS/1");
                  return password;
                } catch (RegistrationOperations.OperationRejectedException rejected) {
                  return null;
                }
              },
              executor));
    }
    var winners =
        futures.stream().map(CompletableFuture::join).filter(java.util.Objects::nonNull).toList();
    assertThat(winners).hasSize(1);
    var result =
        operations.prepareOrAuthenticateRetry(
            member,
            attempt,
            challenge,
            NUMBER,
            winners.getFirst(),
            fixture.request(),
            "iOS",
            "Signal-iOS/1");
    var device = new Device();
    result.applyAuthenticationTo(device);
    assertThat(device.getAuthTokenHash().verify(winners.getFirst())).isTrue();
    assertThat(count()).isEqualTo(1);
  }

  @Test
  void strictExpiryDoesNotMintReplacementOrExtendDeadline() throws Exception {
    var first = prepare();
    clock.setTimeMillis(first.expiresAtMillis());
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::prepare);
    assertThat(count()).isEqualTo(1);
  }

  private void existingAccount() throws Exception {
    try (var c = ds.getConnection();
        var statement =
            c.prepareStatement(
                "INSERT INTO signal.accounts(aci,pni,number,version,data)"
                    + " VALUES(?,?,?,0,'{}'::jsonb)")) {
      statement.setObject(1, UUID.randomUUID());
      statement.setObject(2, UUID.randomUUID());
      statement.setString(3, NUMBER);
      statement.executeUpdate();
    }
  }

  @Test
  void preexistingAccountCannotStartRecoveryButKnownOperationStillAuthenticatesExactRetry()
      throws Exception {
    existingAccount();
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::prepare);
    assertThat(count()).isZero();
    try (var c = ds.getConnection();
        var statement = c.createStatement()) {
      statement.execute("DELETE FROM signal.accounts");
    }
    var original = prepare();
    existingAccount();
    assertThat(prepare().operationId()).isEqualTo(original.operationId());
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () ->
            operations.prepareOrAuthenticateRetry(
                UUID.randomUUID(),
                nonce(8),
                nonce(9),
                NUMBER,
                PASSWORD,
                fixture.request(),
                "iOS",
                "Signal-iOS/1"));
  }

  @Test
  void changedRequestKeyCannotSilentlyRebindExistingOperation() throws Exception {
    prepare();
    byte[] rotated = new byte[32];
    rotated[0] = 1;
    operations = new RegistrationOperations(ds, clock, new RegistrationRequestCommitment(rotated));
    assertThrows(RegistrationOperations.OperationRejectedException.class, this::prepare);
    assertThat(count()).isEqualTo(1);
  }

  @Test
  void canonicalNoncesRequiredAndCapabilitiesAreNotPubliclyConstructible() throws Exception {
    for (String invalid : List.of(attempt + "=", "x", "A".repeat(42) + "B"))
      assertThrows(
          RegistrationOperations.OperationRejectedException.class,
          () ->
              operations.prepareOrAuthenticateRetry(
                  member, invalid, challenge, NUMBER, PASSWORD, fixture.request(), null, null));
    assertThat(RegistrationOperations.AuthenticatedOperation.class.getDeclaredConstructors())
        .allMatch(c -> Modifier.isPrivate(c.getModifiers()));
    assertThat(RegistrationOperations.VerifiedPhone.class.getDeclaredConstructors())
        .allMatch(c -> Modifier.isPrivate(c.getModifiers()));
    assertThat(
            Arrays.stream(RegistrationOperations.class.getDeclaredMethods())
                .filter(m -> m.getName().equals("attachServerCreatedSession")))
        .allMatch(m -> !Modifier.isPublic(m.getModifiers()));
    assertThat(count()).isZero();
  }

  @Test
  void authoritativeUnexpiredAssignedPhoneStateIsRequiredOnEveryRead() throws Exception {
    var operation = prepare();
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.readVerifiedPhone(operation));
    assertThat(operations.assignedSessionId(operation)).isEmpty();
    byte[] id = session(NUMBER, false, clock.millis() + 600000);
    operations.attachServerCreatedSession(operation, id);
    byte[] copy = operations.assignedSessionId(operation).orElseThrow();
    copy[0] ^= 1;
    assertThat(operations.assignedSessionId(operation).orElseThrow()).isEqualTo(id);
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.readVerifiedPhone(operation));
    setVerified(id);
    var verified = operations.readVerifiedPhone(operation);
    assertThat(verified.canonicalNumber()).isEqualTo(NUMBER);
    assertThat(verified.operationId()).isEqualTo(operation.operationId());
    assertThat(verified.sessionExpiresAtMillis()).isEqualTo(clock.millis() + 600000);
    assertThat(verified.toString()).isEqualTo("VerifiedPhone[redacted]");
    operations.attachServerCreatedSession(
        operation, id); // exact assignment retry also works after provider verification
    try (var c = ds.getConnection();
        var s = c.prepareStatement("UPDATE signal.registration_sessions SET number=? WHERE id=?")) {
      s.setString(1, "+13055550124");
      s.setBytes(2, id);
      s.executeUpdate();
    }
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.readVerifiedPhone(operation));
  }

  @Test
  void cannotAttachUnknownExpiredAlreadyVerifiedWrongPhoneOrReplacementSession() throws Exception {
    var operation = prepare();
    for (byte[] id :
        List.of(
            new byte[32],
            session(NUMBER, true, clock.millis() + 600000),
            session(NUMBER, false, clock.millis()),
            session("+13055550124", false, clock.millis() + 600000)))
      assertThrows(
          RegistrationOperations.OperationRejectedException.class,
          () -> operations.attachServerCreatedSession(operation, id));
    byte[] first = session(NUMBER, false, clock.millis() + 600000);
    operations.attachServerCreatedSession(operation, first);
    byte[] other = session(NUMBER, false, clock.millis() + 600000);
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.attachServerCreatedSession(operation, other));
    var second =
        operations.prepareOrAuthenticateRetry(
            UUID.randomUUID(),
            nonce(4),
            nonce(5),
            NUMBER,
            PASSWORD,
            fixture.request(),
            "iOS",
            "Signal-iOS/1");
    assertThrows(
        RuntimeException.class, () -> operations.attachServerCreatedSession(second, first));
  }

  @Test
  void expiredOrRemovedAuthoritativeSessionCannotProvePhone() throws Exception {
    var operation = prepare();
    byte[] id = session(NUMBER, false, clock.millis() + 1000);
    operations.attachServerCreatedSession(operation, id);
    setVerified(id);
    clock.incrementMillis(1000);
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.readVerifiedPhone(operation));
    try (var c = ds.getConnection();
        var s = c.prepareStatement("DELETE FROM signal.registration_sessions WHERE id=?")) {
      s.setBytes(1, id);
      s.executeUpdate();
    }
    assertThrows(
        RegistrationOperations.OperationRejectedException.class,
        () -> operations.readVerifiedPhone(operation));
  }

  @Test
  void expiryDuringRowLockWaitIsRechecked() throws Exception {
    var operation = prepare();
    try (var holding = ds.getConnection()) {
      holding.setAutoCommit(false);
      int blocker;
      try (var s = holding.createStatement();
          var r = s.executeQuery("SELECT pg_backend_pid()")) {
        r.next();
        blocker = r.getInt(1);
      }
      try (var s =
          holding.prepareStatement(
              "SELECT operation_id FROM signal.registration_operations WHERE operation_id=? FOR"
                  + " UPDATE")) {
        s.setObject(1, operation.operationId());
        s.executeQuery().close();
      }
      var waiting =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  prepare();
                  return true;
                } catch (RegistrationOperations.OperationRejectedException e) {
                  return false;
                }
              },
              executor);
      try {
        boolean blocked = false;
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!blocked && System.nanoTime() < end) {
          try (var c = ds.getConnection();
              var s =
                  c.prepareStatement(
                      "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE"
                          + " ?=ANY(pg_blocking_pids(pid)))")) {
            s.setInt(1, blocker);
            try (var r = s.executeQuery()) {
              r.next();
              blocked = r.getBoolean(1);
            }
          }
          if (!blocked) Thread.sleep(20);
        }
        assertThat(blocked).isTrue();
        clock.setTimeMillis(operation.expiresAtMillis());
      } finally {
        holding.rollback();
      }
      assertThat(waiting.get(5, TimeUnit.SECONDS)).isFalse();
    }
  }
}
