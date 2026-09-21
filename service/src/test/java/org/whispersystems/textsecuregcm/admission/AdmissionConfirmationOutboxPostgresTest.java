// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mockito.ArgumentMatchers;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionConfirmationOutbox.Outcome;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.Binding;
import org.whispersystems.textsecuregcm.util.MutableClock;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionConfirmationOutboxPostgresTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private PGSimpleDataSource db;
  private AdmissionServiceClient client;
  private AdmissionConfirmationOutbox outbox;
  private Binding binding;
  private MutableClock clock;
  private AtomicLong nanos;
  private int httpStatus;
  private List<JsonNode> requests;

  @BeforeEach
  void setup() throws Exception {
    String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test"))
      throw new IllegalArgumentException("Isolated loopback test database required");
    db = new PGSimpleDataSource();
    db.setURL(url);
    db.setUser("postgres");
    db.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    db.setApplicationName("bconnected-outbox-test");
    try (var c = db.getConnection();
        var s = c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/003-accounts.sql")));
      s.execute(Files.readString(Path.of("../bconnected/migrations/012-admission.sql")));
      s.execute(
          "ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT IF EXISTS"
              + " test_reject_confirmation");
      s.execute(
          "ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT IF EXISTS"
              + " test_reject_completed");
      s.execute("TRUNCATE signal.admission_confirmation_outbox,signal.admissions,signal.accounts");
    }
    clock = new MutableClock().setTimeInstant(Instant.now());
    nanos = new AtomicLong();
    httpStatus = 200;
    requests = new ArrayList<>();
    binding =
        new Binding(
            UUID.randomUUID(), 1, UUID.randomUUID(), AdmissionTestData.id(), UUID.randomUUID());
    var http = mock(HttpClient.class);
    when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
    when(http.cookieHandler()).thenReturn(Optional.empty());
    when(http.sendAsync(
            any(HttpRequest.class), ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any()))
        .thenAnswer(
            call -> {
              HttpRequest req = call.getArgument(0);
              JsonNode body = body(req);
              requests.add(body);
              var result = new LinkedHashMap<String, Object>();
              body.fields()
                  .forEachRemaining(
                      e ->
                          result.put(
                              e.getKey(),
                              e.getValue().isNumber()
                                  ? e.getValue().longValue()
                                  : e.getValue().textValue()));
              result.put("status", "confirmed");
              result.put("confirmedAt", clock.millis() - 1000);
              result.put("checkedAt", clock.millis());
              result.put("validUntil", clock.millis() + 4000);
              @SuppressWarnings("unchecked")
              HttpResponse<byte[]> response = mock(HttpResponse.class);
              when(response.statusCode()).thenReturn(httpStatus);
              when(response.uri()).thenReturn(req.uri());
              when(response.previousResponse()).thenReturn(Optional.empty());
              when(response.headers())
                  .thenReturn(
                      HttpHeaders.of(
                          Map.of("Content-Type", List.of("application/json")), (k, v) -> true));
              when(response.body()).thenReturn(JSON.writeValueAsBytes(result));
              return CompletableFuture.completedFuture(response);
            });
    client =
        new AdmissionServiceClient(
            AdmissionServiceConfiguration.pilot(),
            http,
            () -> "fixture.header.signature",
            clock,
            nanos::get,
            new SecureRandom());
    outbox = new AdmissionConfirmationOutbox(db, client);
    try (var c = db.getConnection()) {
      try (var s =
          c.prepareStatement(
              "INSERT INTO signal.accounts(aci,number,pni,version,data) VALUES(?,?,?,0,'{}')")) {
        s.setObject(1, binding.aci());
        s.setString(2, "+12025550199");
        s.setObject(3, UUID.randomUUID());
        s.executeUpdate();
      }
      try (var s =
          c.prepareStatement(
              """
              INSERT INTO signal.admissions(permit_id,member_id,aci,signal_operation_id,registration_attempt_hash,
                server_verification_session_hash,device_key_commitment,phone_binding,server_request_commitment,
                approval_epoch,issued_at_seconds,expires_at_seconds) VALUES(?,?,?,?,?,?,?,?,?,1,1,2)
              """)) {
        s.setBytes(1, permit());
        s.setObject(2, binding.memberId());
        s.setObject(3, binding.aci());
        s.setObject(4, binding.signalOperationId());
        for (int i = 5; i <= 9; i++) s.setBytes(i, new byte[32]);
        s.executeUpdate();
      }
      try (var s =
          c.prepareStatement(
              "INSERT INTO signal.admission_confirmation_outbox(permit_id) VALUES(?)")) {
        s.setBytes(1, permit());
        s.executeUpdate();
      }
    }
  }

  @AfterEach
  void close() {
    if (client != null) client.close();
  }

  private byte[] permit() {
    return AdmissionPermitVerifier.decode(binding.permitId(), 32);
  }

  private void sql(String sql) throws Exception {
    try (var c = db.getConnection();
        var s = c.createStatement()) {
      s.execute(sql);
    }
  }

  private String status() throws Exception {
    try (var c = db.getConnection();
        var s = c.createStatement();
        var rows = s.executeQuery("SELECT status FROM signal.admissions")) {
      rows.next();
      return rows.getString(1);
    }
  }

  private boolean confirmed() throws Exception {
    try (var c = db.getConnection();
        var s = c.createStatement();
        var rows =
            s.executeQuery(
                "SELECT confirmed_at IS NOT NULL FROM signal.admission_confirmation_outbox")) {
      rows.next();
      return rows.getBoolean(1);
    }
  }

  private void expireLease() throws Exception {
    sql(
        "UPDATE signal.admission_confirmation_outbox SET"
            + " lease_expires_at=clock_timestamp()-interval '1 second'");
  }

  @Test
  void confirmationAndActivationCommitTogetherAndDoNotRepeat() throws Exception {
    assertThat(outbox.runOne()).isEqualTo(Outcome.ACTIVATED);
    assertThat(status()).isEqualTo("ACTIVE");
    assertThat(confirmed()).isTrue();
    assertThat(outbox.runOne()).isEqualTo(Outcome.IDLE);
    assertThat(requests).hasSize(1);
  }

  @Test
  void deniedOrUnknownResultLeavesPendingAndSchedulesBoundedRetry() throws Exception {
    for (int code : List.of(403, 503)) {
      httpStatus = code;
      assertThat(outbox.runOne()).isEqualTo(Outcome.RETRY);
      assertThat(status()).isEqualTo("PENDING");
      assertThat(confirmed()).isFalse();
      assertThat(outbox.runOne()).isEqualTo(Outcome.IDLE);
      sql(
          "UPDATE signal.admission_confirmation_outbox SET"
              + " next_attempt_at=clock_timestamp()-interval '1 second'");
    }
    httpStatus = 200;
    assertThat(outbox.runOne()).isEqualTo(Outcome.ACTIVATED);
    assertThat(requests).hasSize(3);
    for (var req : requests) {
      assertThat(req.get("jti").asText()).isEqualTo(binding.permitId());
      assertThat(req.get("signalOperationId").asText())
          .isEqualTo(binding.signalOperationId().toString());
    }
    assertThat(requests.stream().map(r -> r.get("requestNonce").asText()).distinct().count())
        .isEqualTo(3);
  }

  @Test
  void concurrentWorkersClaimOnlyOneLease() throws Exception {
    try (var threads = Executors.newFixedThreadPool(8)) {
      var results =
          new ArrayList<java.util.concurrent.Future<Optional<AdmissionConfirmationOutbox.Lease>>>();
      for (int i = 0; i < 12; i++) results.add(threads.submit(outbox::claim));
      int found = 0;
      for (var result : results) if (result.get(5, TimeUnit.SECONDS).isPresent()) found++;
      assertThat(found).isEqualTo(1);
    }
  }

  @Test
  void crashedWorkerLeaseCanBeReclaimedAndOldWorkerIsFenced() throws Exception {
    var old = outbox.claim().orElseThrow();
    expireLease();
    var replacement = outbox.claim().orElseThrow();
    var receipt = client.confirm(binding);
    assertThat(outbox.complete(old, receipt)).isFalse();
    assertThat(outbox.retry(old)).isFalse();
    assertThat(outbox.complete(replacement, receipt)).isTrue();
    assertThat(status()).isEqualTo("ACTIVE");
  }

  @Test
  void expiredLeaseCannotActivateEvenWithFreshConfirmation() throws Exception {
    var lease = outbox.claim().orElseThrow();
    expireLease();
    assertThat(outbox.complete(lease, client.confirm(binding))).isFalse();
    assertThat(status()).isEqualTo("PENDING");
    assertThat(confirmed()).isFalse();
  }

  @Test
  void suspensionAndEpochChangeCannotBeOverriddenByReceipt() throws Exception {
    var lease = outbox.claim().orElseThrow();
    var receipt = client.confirm(binding);
    sql("UPDATE signal.admissions SET status='SUSPENDED'");
    assertThat(outbox.complete(lease, receipt)).isFalse();
    sql("UPDATE signal.admissions SET status='PENDING',approval_epoch=2");
    assertThat(outbox.complete(lease, receipt)).isFalse();
    assertThat(confirmed()).isFalse();
  }

  @Test
  void deletedAccountAndChangedBindingDoNotActivateSpentPermit() throws Exception {
    var lease = outbox.claim().orElseThrow();
    var wrong =
        new Binding(
            binding.memberId(),
            1,
            binding.signalOperationId(),
            binding.permitId(),
            UUID.randomUUID());
    assertThat(outbox.complete(lease, client.confirm(wrong))).isFalse();
    sql("DELETE FROM signal.accounts");
    assertThat(outbox.complete(lease, client.confirm(binding))).isFalse();
    assertThat(confirmed()).isFalse();
  }

  @Test
  void currentEntitlementCannotSubstituteForConfirmation() throws Exception {
    var lease = outbox.claim().orElseThrow();
    assertThrows(
        AdmissionServiceClient.AdmissionServiceException.class,
        () -> outbox.complete(lease, client.currentEntitlement(binding)));
    assertThat(status()).isEqualTo("PENDING");
    assertThat(confirmed()).isFalse();
  }

  @Test
  void failureAfterActiveWriteRollsBackBothStateChanges() throws Exception {
    var lease = outbox.claim().orElseThrow();
    var receipt = client.confirm(binding);
    sql(
        "ALTER TABLE signal.admission_confirmation_outbox ADD CONSTRAINT test_reject_completed"
            + " CHECK(confirmed_at IS NULL) NOT VALID");
    assertThrows(
        AdmissionConfirmationOutbox.OutboxUnavailableException.class,
        () -> outbox.complete(lease, receipt));
    assertThat(status()).isEqualTo("PENDING");
    assertThat(confirmed()).isFalse();
    sql("ALTER TABLE signal.admission_confirmation_outbox DROP CONSTRAINT test_reject_completed");
  }

  @Test
  void lockWaitConsumesReceiptFreshnessRatherThanRefreshingIt() throws Exception {
    var lease = outbox.claim().orElseThrow();
    var receipt = client.confirm(binding);
    try (var blocker = db.getConnection();
        var threads = Executors.newSingleThreadExecutor()) {
      blocker.setAutoCommit(false);
      try (var s = blocker.createStatement()) {
        s.execute("SELECT 1 FROM signal.admissions FOR UPDATE");
      }
      var result = threads.submit(() -> outbox.complete(lease, receipt));
      waitForLock("SELECT * FROM signal.admissions%");
      nanos.set(TimeUnit.MILLISECONDS.toNanos(4000));
      blocker.rollback();
      assertThrows(
          java.util.concurrent.ExecutionException.class, () -> result.get(5, TimeUnit.SECONDS));
      assertThat(status()).isEqualTo("PENDING");
      assertThat(confirmed()).isFalse();
    }
  }

  @Test
  void outboxLeaseDeadlineIsReadAfterWaitingForItsLock() throws Exception {
    var lease = outbox.claim().orElseThrow();
    var receipt = client.confirm(binding);
    try (var blocker = db.getConnection();
        var threads = Executors.newSingleThreadExecutor()) {
      blocker.setAutoCommit(false);
      try (var s = blocker.createStatement()) {
        s.execute(
            "UPDATE signal.admission_confirmation_outbox SET"
                + " lease_expires_at=clock_timestamp()-interval '1 second'");
      }
      var result = threads.submit(() -> outbox.complete(lease, receipt));
      waitForLock("SELECT lease_id,confirmed_at%");
      blocker.commit();
      assertThat(result.get(5, TimeUnit.SECONDS)).isFalse();
      assertThat(status()).isEqualTo("PENDING");
    }
  }

  private void waitForLock(String query) throws Exception {
    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    while (System.nanoTime() < end) {
      try (var c = db.getConnection();
          var s =
              c.prepareStatement(
                  "SELECT count(*) FROM pg_stat_activity WHERE"
                      + " application_name='bconnected-outbox-test' AND wait_event_type='Lock' AND"
                      + " query LIKE ?")) {
        s.setString(1, query);
        try (var rows = s.executeQuery()) {
          rows.next();
          if (rows.getInt(1) > 0) return;
        }
      }
      Thread.sleep(10);
    }
    throw new AssertionError("Outbox did not reach expected lock wait");
  }

  private static JsonNode body(HttpRequest request) throws Exception {
    var bytes = new ByteArrayOutputStream();
    var done = new CompletableFuture<Void>();
    request
        .bodyPublisher()
        .orElseThrow()
        .subscribe(
            new Flow.Subscriber<ByteBuffer>() {
              public void onSubscribe(Flow.Subscription s) {
                s.request(Long.MAX_VALUE);
              }

              public void onNext(ByteBuffer b) {
                byte[] part = new byte[b.remaining()];
                b.get(part);
                bytes.writeBytes(part);
              }

              public void onError(Throwable t) {
                done.completeExceptionally(t);
              }

              public void onComplete() {
                done.complete(null);
              }
            });
    done.get(1, TimeUnit.SECONDS);
    return JSON.readTree(bytes.toString(StandardCharsets.UTF_8));
  }
}
