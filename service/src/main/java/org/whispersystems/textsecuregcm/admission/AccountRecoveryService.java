// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.RecoveryBinding;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.RecoveryReceipt;
import org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentParser.Operation;
import org.whispersystems.textsecuregcm.configuration.DmAlphaConfiguration;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.ClientType;
import org.whispersystems.textsecuregcm.registration.MessageTransport;
import org.whispersystems.textsecuregcm.registration.VerificationCodeExpiredException;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Dedicated, operator-authorized device replacement. Never reuses or edits ordinary signup proof.
 */
public final class AccountRecoveryService {
  private static final Duration TIMEOUT = Duration.ofSeconds(15);
  private static final long PROOF_MS = 300_000;
  private final DataSource dataSource;
  private final Clock clock;
  private final TelnyxRegistrationService registration;
  private final AdmissionServiceClient admission;
  private final DmAlphaConfiguration configuration;
  private final RegistrationRequestCommitment commitments;
  private final Cleanup cleanup;

  /**
   * Must return only after all old cache/connection cleanup has completed. Failure leaves the
   * fence.
   */
  @FunctionalInterface
  public interface Cleanup {
    void clean(Account replacement);
  }

  public record Input(
      String attempt,
      String number,
      String password,
      RegistrationRequest request,
      String signalAgent,
      String userAgent) {
    @Override
    public String toString() {
      return "RecoveryInput[redacted]";
    }
  }

  @JsonInclude(JsonInclude.Include.ALWAYS)
  public record Observation(
      UUID recoveryId,
      String state,
      boolean phoneVerified,
      Long nextSmsSeconds,
      Long nextCheckSeconds,
      long expiresInSeconds,
      boolean registrationAuthorized,
      UUID memberId,
      AdmissionEntitlementGate.AccountProjection account,
      String fullName,
      Integer graduationYear) {
    @Override
    public String toString() {
      return "RecoveryObservation[redacted]";
    }
  }

  private static final class Rejected extends RuntimeException {
    final Code code;

    Rejected(Code code) {
      super("Recovery unavailable");
      this.code = code;
    }
  }

  private record Row(
      UUID id,
      String attempt,
      String number,
      RegistrationAuthentication auth,
      String requestHash,
      String keyHash,
      RegistrationRequest request,
      String signalAgent,
      String userAgent,
      byte[] session,
      long expires,
      Long verified,
      Long proofExpires,
      RecoveryBinding binding,
      UUID aci,
      UUID pni,
      String state,
      Long generation,
      boolean completionRequested) {
    @Override
    public String toString() {
      return "RecoveryRow[redacted]";
    }
  }

  public AccountRecoveryService(
      DataSource dataSource,
      Clock clock,
      TelnyxRegistrationService registration,
      AdmissionServiceClient admission,
      DmAlphaConfiguration configuration,
      Cleanup cleanup) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
    this.registration = Objects.requireNonNull(registration);
    this.admission = Objects.requireNonNull(admission);
    this.configuration = Objects.requireNonNull(configuration);
    this.cleanup = Objects.requireNonNull(cleanup);
    this.commitments =
        new RegistrationRequestCommitment(configuration.requestCommitmentKey().value());
  }

  public Result execute(
      Operation action, UUID id, Input input, String code, String source, String language) {
    try {
      validate(input);
      Row row = action == Operation.BEGIN ? prepare(input, source) : authenticate(id, input);
      if (row.state.equals("RECOVERING")) return reconcile(row);
      if (row.state.equals("ACTIVE")) return active(row);
      if (row.verified != null) {
        if (row.completionRequested) return complete(row);
        requireUnexpiredProof(row);
        row = attachBinding(row);
        if (action == Operation.COMPLETE) return complete(row);
        return authorized(row, admission.recovery("authorizations", row.binding));
      }
      if (clock.millis() >= row.expires) throw new Rejected(Code.RECOVERY_EXPIRED);
      UUID sessionOwner = row.id;
      RegistrationServiceSession session;
      switch (action) {
        case SEND_CODE ->
            session =
                registration.sendVerificationCode(
                    row.session,
                    MessageTransport.SMS,
                    ClientType.IOS,
                    language,
                    null,
                    TIMEOUT,
                    () -> requireSessionUsable(sessionOwner));
        case CHECK_CODE -> {
          if (code == null || !code.matches("[0-9]{4,10}")) throw new IllegalArgumentException();
          session =
              registration.checkVerificationCode(
                  row.session, code, TIMEOUT, () -> requireSessionUsable(sessionOwner));
          if (!session.verified()) return error(Code.CODE_NOT_ACCEPTED);
        }
        case COMPLETE -> {
          return error(Code.RECOVERY_NOT_AUTHORIZED);
        }
        default ->
            session =
                registration
                    .getSession(row.session, TIMEOUT)
                    .orElseThrow(() -> new Rejected(Code.RECOVERY_EXPIRED));
      }
      if (session.verified()) {
        row = recordVerified(row);
        requireUnexpiredProof(row);
        row = attachBinding(row);
        return authorized(row, admission.recovery("authorizations", row.binding));
      }
      return new Result(
          200,
          new Observation(
              row.id,
              "verification",
              false,
              session.nextSms(),
              session.nextVerificationAttempt(),
              session.expiration(),
              false,
              null,
              null,
              null,
              null));
    } catch (Rejected rejected) {
      return error(rejected.code);
    } catch (VerificationCodeExpiredException expired) {
      return error(Code.CODE_EXPIRED);
    } catch (RateLimitExceededException limited) {
      return error(
          Code.RATE_LIMITED,
          limited
              .getRetryDuration()
              .map(d -> Math.max(0, d.toSeconds() + (d.getNano() == 0 ? 0 : 1)))
              .orElse(null));
    } catch (IllegalArgumentException malformed) {
      return error(Code.INVALID_REQUEST);
    } catch (Exception unavailable) {
      return error(Code.TEMPORARILY_UNAVAILABLE);
    }
  }

  /**
   * Loopback operator task: exact frozen commitment, same completion logic, no password extraction.
   */
  public Result completeOperator(UUID id, String requestHash) {
    try {
      if (id == null || requestHash == null || !requestHash.matches("[0-9a-f]{64}"))
        return error(Code.INVALID_REQUEST);
      Row row = transaction(c -> load(c, id, false));
      if (row == null || !constant(row.requestHash, requestHash))
        return error(Code.RECOVERY_UNAVAILABLE);
      validateStored(row);
      if (row.state.equals("ACTIVE")) return active(row);
      if (row.state.equals("RECOVERING")) return reconcile(row);
      if (row.verified == null || row.binding == null) return error(Code.RECOVERY_NOT_AUTHORIZED);
      return complete(row);
    } catch (Rejected rejected) {
      return error(rejected.code);
    } catch (Exception unavailable) {
      return error(Code.TEMPORARILY_UNAVAILABLE);
    }
  }

  private void validate(Input input) {
    Objects.requireNonNull(input);
    nonceHash(input.attempt);
    if (input.password == null
        || input.password.isBlank()
        || input.password.getBytes(StandardCharsets.UTF_8).length > 256
        || input.password.codePoints().anyMatch(Character::isISOControl))
      throw new IllegalArgumentException();
    if (configuration.memberIds().stream()
        .noneMatch(member -> configuration.allowsPhone(member, input.number)))
      throw new Rejected(Code.RECOVERY_UNAVAILABLE);
    try (var request =
        CanonicalRegistrationRequest.beforeVerification(
            input.request, input.number, input.signalAgent, input.userAgent)) {
      var attributes = request.frozenRequest().accountAttributes();
      if (!input.request.skipDeviceTransfer()
          || attributes.getRegistrationLock() != null
          || attributes.recoveryPassword().isPresent()
          || attributes.getName() != null) throw new IllegalArgumentException();
    }
  }

  private Row prepare(Input input, String source) throws Exception {
    if (source == null || source.isBlank()) throw new IllegalArgumentException();
    String attempt = nonceHash(input.attempt);
    try (var canonical =
            CanonicalRegistrationRequest.beforeVerification(
                input.request, input.number, input.signalAgent, input.userAgent);
        var c = dataSource.getConnection()) {
      c.setAutoCommit(false);
      try {
        limits(c);
        try (var lock = c.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?)::bigint)")) {
          lock.setString(1, "recovery-attempt:" + attempt);
          lock.execute();
        }
        Row existing;
        try (var query =
            c.prepareStatement(
                "SELECT * FROM signal.account_recoveries WHERE attempt_hash=? FOR UPDATE")) {
          query.setString(1, attempt);
          try (var r = query.executeQuery()) {
            existing = r.next() ? row(r) : null;
          }
        }
        if (existing != null) {
          authenticate(existing, input);
          c.commit();
          return existing;
        }
        var auth = RegistrationAuthentication.create(input.password);
        var session =
            registration.createRegistrationSessionInTransaction(
                c,
                PhoneNumberUtil.getInstance().parse(input.number, null),
                source,
                TIMEOUT,
                () -> {});
        UUID id = UUID.randomUUID();
        try (var insert =
            c.prepareStatement(
                """
                INSERT INTO signal.account_recoveries(recovery_id,attempt_hash,number,auth_hash,auth_salt,
                  request_hash,device_key_hash,registration_request,signal_agent,user_agent,session_id,created_ms,expires_ms)
                VALUES(?,?,?,?,?,?,?,?::jsonb,?,?,?,?,?)
                """)) {
          insert.setObject(1, id);
          insert.setString(2, attempt);
          insert.setString(3, input.number);
          insert.setString(4, auth.hash());
          insert.setString(5, auth.salt());
          insert.setString(6, commitments.compute(canonical.bytes(), auth.binding()));
          insert.setString(7, canonical.keyCommitment());
          insert.setString(
              8, SystemMapper.jsonMapper().writeValueAsString(canonical.frozenRequest()));
          insert.setString(9, input.signalAgent);
          insert.setString(10, input.userAgent);
          insert.setBytes(11, session.id());
          insert.setLong(12, clock.millis());
          insert.setLong(13, clock.millis() + session.expiration() * 1000);
          insert.executeUpdate();
        }
        Row result = load(c, id, false);
        c.commit();
        return result;
      } catch (Exception failure) {
        c.rollback();
        throw failure;
      }
    }
  }

  private Row authenticate(UUID id, Input input) {
    if (id == null || id.equals(new UUID(0, 0))) throw new IllegalArgumentException();
    Row row = transaction(c -> load(c, id, false));
    if (row == null) throw new Rejected(Code.RECOVERY_UNAVAILABLE);
    authenticate(row, input);
    return row;
  }

  private void authenticate(Row row, Input input) {
    if (!row.number.equals(input.number)
        || !constant(row.attempt, nonceHash(input.attempt))
        || !row.auth.verify(input.password)) throw new Rejected(Code.INVALID_CREDENTIALS);
    try (var request =
        CanonicalRegistrationRequest.beforeVerification(
            input.request, input.number, input.signalAgent, input.userAgent)) {
      if (!constant(row.requestHash, commitments.compute(request.bytes(), row.auth.binding()))
          || !constant(row.keyHash, request.keyCommitment()))
        throw new Rejected(Code.RECOVERY_CONFLICT);
    }
  }

  private void validateStored(Row row) {
    try (var request =
        CanonicalRegistrationRequest.beforeVerification(
            row.request, row.number, row.signalAgent, row.userAgent)) {
      if (!constant(row.requestHash, commitments.compute(request.bytes(), row.auth.binding()))
          || !constant(row.keyHash, request.keyCommitment()))
        throw new Rejected(Code.RECOVERY_CONFLICT);
    }
  }

  private static UUID idFor(Row row) {
    return row.id;
  }

  private void requireSessionUsable(UUID id) {
    Row row = transaction(c -> load(c, id, false));
    if (row == null
        || !row.state.equals("VERIFICATION")
        || clock.millis() >= row.expires
        || row.verified != null) throw new Rejected(Code.RECOVERY_EXPIRED);
  }

  private Row recordVerified(Row original) {
    return transaction(
        c -> {
          Row row = load(c, original.id, true);
          if (row.verified != null) return row;
          try (var query =
              c.prepareStatement(
                  "SELECT number,verified,verified_at_ms FROM signal.registration_sessions WHERE"
                      + " id=? FOR SHARE")) {
            query.setBytes(1, row.session);
            try (var r = query.executeQuery()) {
              if (!r.next()
                  || !r.getBoolean("verified")
                  || !row.number.equals(r.getString("number"))
                  || r.getObject("verified_at_ms") == null)
                throw new Rejected(Code.RECOVERY_UNAVAILABLE);
              long verified = r.getLong("verified_at_ms");
              if (verified > clock.millis() || clock.millis() >= verified + PROOF_MS)
                throw new Rejected(Code.RECOVERY_EXPIRED);
              try (var update =
                  c.prepareStatement(
                      "UPDATE signal.account_recoveries SET verified_ms=?,proof_expires_ms=? WHERE"
                          + " recovery_id=?")) {
                update.setLong(1, verified);
                update.setLong(2, verified + PROOF_MS);
                update.setObject(3, row.id);
                update.executeUpdate();
              }
            }
          }
          return load(c, row.id, false);
        });
  }

  private void requireUnexpiredProof(Row row) {
    if (row.verified == null || clock.millis() < row.verified || clock.millis() >= row.proofExpires)
      throw new Rejected(Code.RECOVERY_EXPIRED);
  }

  private Row attachBinding(Row original) {
    Row row = original;
    if (row.binding == null)
      row =
          transaction(
              c -> {
                // The account is always locked before admission and recovery rows.
                Account account = accountByNumber(c, original.number, true);
                requireOriginalAccount(account, original);
                RecoveryBinding binding = binding(c, original, account);
                Row current = load(c, original.id, true);
                if (current.binding != null) return current;
                requireUnexpiredProof(current);
                try (var update =
                    c.prepareStatement(
                        """
                        UPDATE signal.account_recoveries SET recovery_binding=?::jsonb,aci=?,pni=?,expected_account_version=?,state='REQUESTED'
                        WHERE recovery_id=? AND recovery_binding IS NULL
                        """)) {
                  update.setString(1, json(binding));
                  update.setObject(2, account.getAccountIdentifier());
                  update.setObject(3, account.getPhoneNumberIdentifier().orElseThrow());
                  update.setInt(4, account.getVersion());
                  update.setObject(5, current.id);
                  if (update.executeUpdate() != 1) throw new Rejected(Code.RECOVERY_CONFLICT);
                }
                return load(c, current.id, false);
              });
    // Exact repeats register/recover the same request, never refresh its proof deadline.
    admission.recovery("requests", row.binding).requireFresh();
    return row;
  }

  private RecoveryBinding binding(Connection c, Row row, Account account) throws SQLException {
    try (var query =
        c.prepareStatement(
            """
            SELECT a.* FROM signal.admissions a WHERE a.aci=? AND a.status='ACTIVE'
              AND a.activated_at IS NOT NULL AND a.suspended_at IS NULL
              AND EXISTS(SELECT 1 FROM signal.admission_confirmation_outbox o WHERE o.permit_id=a.permit_id AND o.confirmed_at IS NOT NULL)
            FOR SHARE
            """)) {
      query.setObject(1, account.getAccountIdentifier());
      try (var r = query.executeQuery()) {
        if (!r.next()) throw new Rejected(Code.RECOVERY_UNAVAILABLE);
        UUID member = r.getObject("member_id", UUID.class);
        if (!configuration.memberIds().contains(member)
            || !configuration.allowsPhone(member, row.number)
            || !MessageDigest.isEqual(r.getBytes("phone_binding"), phoneBinding(row.number)))
          throw new Rejected(Code.RECOVERY_UNAVAILABLE);
        return new RecoveryBinding(
            row.id,
            member,
            r.getLong("approval_epoch"),
            r.getObject("signal_operation_id", UUID.class),
            Base64.getUrlEncoder().withoutPadding().encodeToString(r.getBytes("permit_id")),
            HexFormat.of().formatHex(r.getBytes("phone_binding")),
            account.getAccountIdentifier(),
            row.attempt,
            row.keyHash,
            row.requestHash,
            account.getVersion(),
            row.verified,
            row.proofExpires);
      }
    }
  }

  private void requireOriginalAccount(Account account, Row row) {
    if (account == null
        || account.getDevices().size() != 1
        || account.getDevice(Device.PRIMARY_ID).isEmpty()
        || !account.getNumber().filter(row.number::equals).isPresent()
        || account.getPhoneNumberIdentifier().isEmpty()
        || !account.getMfaKeys().isEmpty()) throw new Rejected(Code.RECOVERY_UNAVAILABLE);
    var device = account.getDevice(Device.PRIMARY_ID).orElseThrow();
    // Avoid ambiguous unchanged identity/generation and old-registration-id message routing.
    if (device.getAccountRegistrationId() == row.request.accountAttributes().getRegistrationId()
        || device
            .getPhoneNumberIdentityRegistrationId()
            .equals(row.request.accountAttributes().getPhoneNumberIdentityRegistrationId())
        || account.getAccountIdentityKey().equals(row.request.aciIdentityKey())
        || account
            .getPhoneNumberIdentityKey()
            .filter(row.request.pniIdentityKey()::equals)
            .isPresent()) throw new Rejected(Code.RECOVERY_CONFLICT);
  }

  private Result authorized(Row row, RecoveryReceipt receipt) {
    receipt.requireFresh();
    boolean authorized = !receipt.status().equals("requested");
    return observation(
        row,
        authorized ? "authorized" : "awaiting_authorization",
        false,
        authorized ? receipt : null);
  }

  private Result complete(Row row) {
    validateStored(row);
    var authorization = admission.recovery("authorizations", row.binding);
    if (authorization.status().equals("requested")) return error(Code.RECOVERY_NOT_AUTHORIZED);
    if (!authorization.status().equals("confirmed")) requireUnexpiredProof(row);
    // Durable explicit intent precedes the private consume. A crash in between is recoverable;
    // status of a merely prepared/authorized request still cannot start credential replacement.
    transaction(
        c -> {
          Row current = load(c, row.id, true);
          if (authorization.status().equals("confirmed") && !current.completionRequested)
            throw new Rejected(Code.RECOVERY_CONFLICT);
          if (!current.completionRequested)
            execute(
                c,
                "UPDATE signal.account_recoveries SET completion_requested=true WHERE"
                    + " recovery_id=?",
                row.id);
          return null;
        });
    var receipt =
        authorization.status().equals("confirmed")
            ? authorization
            : admission.recovery("confirmations", row.binding);
    Row fenced =
        transaction(
            c -> {
              Account previous = account(c, row.aci, true);
              lockAdmission(c, row, "ACTIVE", "RECOVERING");
              Row current = load(c, row.id, true);
              if (current.state.equals("RECOVERING") || current.state.equals("ACTIVE"))
                return current;
              receipt.requireFresh();
              if (previous == null
                  || previous.getVersion() != row.binding.expectedAccountVersion()
                  || !previous.getPhoneNumberIdentifier().filter(row.pni::equals).isPresent())
                throw new Rejected(Code.RECOVERY_CONFLICT);
              requireOriginalAccount(previous, row);
              Account replacement = replacement(previous, row);
              try (var update =
                  c.prepareStatement(
                      "UPDATE signal.accounts SET data=?::jsonb,version=version+1 WHERE aci=? AND"
                          + " version=?")) {
                update.setString(1, json(replacement));
                update.setObject(2, row.aci);
                update.setInt(3, previous.getVersion());
                if (update.executeUpdate() != 1) throw new Rejected(Code.RECOVERY_CONFLICT);
              }
              var activation = row.request.deviceActivationRequest();
              SignedPreKeysPostgres.ec(dataSource, Runnable::run)
                  .buildInsertion(row.aci, Device.PRIMARY_ID, activation.aciSignedPreKey())
                  .applySql(c);
              SignedPreKeysPostgres.ec(dataSource, Runnable::run)
                  .buildInsertion(
                      row.pni, Device.PRIMARY_ID, activation.pniSignedPreKey().orElseThrow())
                  .applySql(c);
              SignedPreKeysPostgres.kem(dataSource, Runnable::run)
                  .buildInsertion(row.aci, Device.PRIMARY_ID, activation.aciPqLastResortPreKey())
                  .applySql(c);
              SignedPreKeysPostgres.kem(dataSource, Runnable::run)
                  .buildInsertion(
                      row.pni, Device.PRIMARY_ID, activation.pniPqLastResortPreKey().orElseThrow())
                  .applySql(c);
              for (String table : List.of("single_use_ec_prekeys", "single_use_kem_prekeys"))
                execute(
                    c,
                    "DELETE FROM signal." + table + " WHERE account_id IN (?,?)",
                    row.aci,
                    row.pni);
              for (String table : List.of("profiles_v1", "profiles_v2", "messages"))
                execute(c, "DELETE FROM signal." + table + " WHERE account_id=?", row.aci);
              execute(c, "DELETE FROM signal.phone_recovery_passwords WHERE pni=?", row.pni);
              execute(
                  c,
                  "UPDATE signal.admissions SET status='RECOVERING' WHERE aci=? AND"
                      + " status='ACTIVE'",
                  row.aci);
              execute(
                  c,
                  "UPDATE signal.account_recoveries SET state='RECOVERING',replacement_generation=?"
                      + " WHERE recovery_id=?",
                  replacement.getDevice(Device.PRIMARY_ID).orElseThrow().getCreated(),
                  row.id);
              receipt.requireFresh();
              return load(c, row.id, false);
            });
    return fenced.state.equals("ACTIVE") ? active(fenced) : reconcile(fenced);
  }

  /**
   * Persistent fence plus session advisory ownership prevent any late duplicate cleanup after
   * activation.
   */
  private Result reconcile(Row row) {
    try (var ownership = dataSource.getConnection()) {
      boolean locked;
      try (var q = ownership.prepareStatement("SELECT pg_try_advisory_lock(hashtext(?)::bigint)")) {
        q.setString(1, "recovery-cleanup:" + row.id);
        try (var r = q.executeQuery()) {
          r.next();
          locked = r.getBoolean(1);
        }
      }
      if (!locked)
        return observation(
            row, "recovering", false, admission.recovery("entitlements", row.binding));
      try {
        Row current = transaction(c -> load(c, row.id, false));
        if (current.state.equals("ACTIVE")) return active(current);
        if (!current.state.equals("RECOVERING")) throw new Rejected(Code.RECOVERY_CONFLICT);
        Row cleanupRow = current;
        Account replacement =
            transaction(
                c -> {
                  Account a = account(c, row.aci, false);
                  requireReplacement(a, cleanupRow);
                  return a;
                });
        cleanup.clean(
            replacement); // no SQL transaction/row lock; all futures must finish before this
                          // returns
        var receipt = admission.recovery("entitlements", current.binding);
        current =
            transaction(
                c -> {
                  Account a = account(c, row.aci, true);
                  lockAdmission(c, row, "RECOVERING");
                  Row lockedRow = load(c, row.id, true);
                  requireReplacement(a, lockedRow);
                  receipt.requireFresh();
                  execute(
                      c,
                      "UPDATE signal.admissions SET status='ACTIVE' WHERE aci=? AND"
                          + " status='RECOVERING'",
                      row.aci);
                  execute(
                      c,
                      "UPDATE signal.account_recoveries SET state='ACTIVE',completed_ms=? WHERE"
                          + " recovery_id=? AND state='RECOVERING'",
                      clock.millis(),
                      row.id);
                  receipt.requireFresh();
                  return load(c, row.id, false);
                });
        return observation(current, "active", true, receipt);
      } finally {
        try (var q = ownership.prepareStatement("SELECT pg_advisory_unlock(hashtext(?)::bigint)")) {
          q.setString(1, "recovery-cleanup:" + row.id);
          q.execute();
        }
      }
    } catch (SQLException failure) {
      throw new IllegalStateException("Recovery reconciliation unavailable");
    }
  }

  private Result active(Row row) {
    var receipt = admission.recovery("entitlements", row.binding);
    transaction(
        c -> {
          requireReplacement(account(c, row.aci, true), row);
          lockAdmission(c, row, "ACTIVE");
          receipt.requireFresh();
          return null;
        });
    receipt.requireFresh();
    return observation(row, "active", true, receipt);
  }

  private void requireReplacement(Account account, Row row) {
    if (account == null
        || account.getDevices().size() != 1
        || !account.getNumber().filter(row.number::equals).isPresent()
        || !account.getPhoneNumberIdentifier().filter(row.pni::equals).isPresent()
        || !account.getAccountIdentityKey().equals(row.request.aciIdentityKey())
        || !account
            .getPhoneNumberIdentityKey()
            .filter(row.request.pniIdentityKey()::equals)
            .isPresent()) throw new Rejected(Code.RECOVERY_CONFLICT);
    var d = account.getDevice(Device.PRIMARY_ID).orElseThrow();
    var expected = new Device();
    row.auth.applyTo(expected);
    if (row.generation == null
        || d.getCreated() != row.generation
        || !d.getAuthTokenHash().equals(expected.getAuthTokenHash())
        || d.getAccountRegistrationId() != row.request.accountAttributes().getRegistrationId()
        || !d.getPhoneNumberIdentityRegistrationId()
            .equals(row.request.accountAttributes().getPhoneNumberIdentityRegistrationId()))
      throw new Rejected(Code.RECOVERY_CONFLICT);
  }

  private void lockAdmission(Connection c, Row row, String... statuses) throws SQLException {
    try (var q = c.prepareStatement("SELECT * FROM signal.admissions WHERE aci=? FOR UPDATE")) {
      q.setObject(1, row.aci);
      try (var r = q.executeQuery()) {
        var b = row.binding;
        if (!r.next()
            || !List.of(statuses).contains(r.getString("status"))
            || r.getObject("suspended_at") != null
            || !b.memberId().equals(r.getObject("member_id", UUID.class))
            || b.approvalEpoch() != r.getLong("approval_epoch")
            || !b.signalOperationId().equals(r.getObject("signal_operation_id", UUID.class))
            || !MessageDigest.isEqual(
                Base64.getUrlDecoder().decode(b.jti()), r.getBytes("permit_id"))
            || !MessageDigest.isEqual(
                HexFormat.of().parseHex(b.phoneBinding()), r.getBytes("phone_binding")))
          throw new Rejected(Code.RECOVERY_UNAVAILABLE);
      }
    }
  }

  private Account replacement(Account old, Row row) {
    Account a = old; // Detached, locked SQL snapshot; never a shared cache object.
    var attributes = row.request.accountAttributes();
    var activation = row.request.deviceActivationRequest();
    long created =
        Math.max(
            clock.millis(),
            Math.addExact(old.getDevice(Device.PRIMARY_ID).orElseThrow().getCreated(), 128));
    var spec =
        new DeviceSpec(
            null,
            "recovery-verifier-applied-before-write",
            row.signalAgent,
            attributes.getCapabilities(),
            new DeviceIdentityInfo(
                attributes.getRegistrationId(),
                activation.aciSignedPreKey(),
                activation.aciPqLastResortPreKey()),
            Optional.of(
                new DeviceIdentityInfo(
                    attributes.getPhoneNumberIdentityRegistrationId().orElseThrow(),
                    activation.pniSignedPreKey().orElseThrow(),
                    activation.pniPqLastResortPreKey().orElseThrow())),
            attributes.getFetchesMessages(),
            activation.apnToken(),
            activation.gcmToken());
    var device =
        spec.toDevice(
            Device.PRIMARY_ID,
            Clock.fixed(java.time.Instant.ofEpochMilli(created), java.time.ZoneOffset.UTC),
            row.request.aciIdentityKey());
    row.auth.applyTo(device);
    a.addDevice(device);
    a.setIdentityKey(row.request.aciIdentityKey());
    a.setPhoneNumberIdentityKey(row.request.pniIdentityKey());
    a.setRegistrationLockFromAttributes(attributes);
    a.clearAccountRecoveryPassword();
    a.setUnidentifiedAccessKey(attributes.getUnidentifiedAccessKey());
    a.setUnrestrictedUnidentifiedAccess(attributes.isUnrestrictedUnidentifiedAccess());
    a.setDiscoverableByPhoneNumber(attributes.isDiscoverableByPhoneNumber());
    return a;
  }

  private Result observation(Row row, String state, boolean authorized, RecoveryReceipt receipt) {
    if (receipt != null) receipt.requireFresh();
    var account =
        receipt == null
            ? null
            : new AdmissionEntitlementGate.AccountProjection(
                row.aci, row.pni, row.number, Device.PRIMARY_ID);
    return new Result(
        state.equals("recovering") ? 202 : 200,
        new Observation(
            row.id,
            state,
            row.verified != null,
            null,
            null,
            Math.max(
                0,
                ((row.proofExpires == null ? row.expires : row.proofExpires) - clock.millis() + 999)
                    / 1000),
            authorized,
            receipt == null ? null : row.binding.memberId(),
            account,
            receipt == null ? null : receipt.fullName(),
            receipt == null ? null : receipt.graduationYear()));
  }

  private Account accountByNumber(Connection c, String number, boolean lock) throws SQLException {
    return readAccount(c, "number", number, lock);
  }

  private Account account(Connection c, UUID aci, boolean lock) throws SQLException {
    return readAccount(c, "aci", aci, lock);
  }

  private Account readAccount(Connection c, String column, Object value, boolean lock)
      throws SQLException {
    try (var q =
        c.prepareStatement(
            "SELECT * FROM signal.accounts WHERE " + column + "=?" + (lock ? " FOR UPDATE" : ""))) {
      q.setObject(1, value);
      try (var r = q.executeQuery()) {
        if (!r.next()) return null;
        try {
          var a = SystemMapper.jsonMapper().readValue(r.getString("data"), Account.class);
          a.setAccountIdentifier(r.getObject("aci", UUID.class));
          a.setNumber(r.getString("number"), r.getObject("pni", UUID.class));
          a.setVersion(r.getInt("version"));
          return a;
        } catch (java.io.IOException malformed) {
          throw new IllegalStateException("Invalid recovery account");
        }
      }
    }
  }

  private Row load(Connection c, UUID id, boolean lock) throws SQLException {
    try (var q =
        c.prepareStatement(
            "SELECT * FROM signal.account_recoveries WHERE recovery_id=?"
                + (lock ? " FOR UPDATE" : ""))) {
      q.setObject(1, id);
      try (var r = q.executeQuery()) {
        return r.next() ? row(r) : null;
      }
    }
  }

  private Row row(ResultSet r) throws SQLException {
    try {
      String binding = r.getString("recovery_binding");
      return new Row(
          r.getObject("recovery_id", UUID.class),
          r.getString("attempt_hash"),
          r.getString("number"),
          RegistrationAuthentication.restore(r.getString("auth_hash"), r.getString("auth_salt")),
          r.getString("request_hash"),
          r.getString("device_key_hash"),
          SystemMapper.jsonMapper()
              .readValue(r.getString("registration_request"), RegistrationRequest.class),
          r.getString("signal_agent"),
          r.getString("user_agent"),
          r.getBytes("session_id"),
          r.getLong("expires_ms"),
          (Long) r.getObject("verified_ms"),
          (Long) r.getObject("proof_expires_ms"),
          binding == null
              ? null
              : SystemMapper.jsonMapper().readValue(binding, RecoveryBinding.class),
          r.getObject("aci", UUID.class),
          r.getObject("pni", UUID.class),
          r.getString("state"),
          (Long) r.getObject("replacement_generation"),
          r.getBoolean("completion_requested"));
    } catch (java.io.IOException malformed) {
      throw new IllegalStateException("Invalid recovery record");
    }
  }

  @FunctionalInterface
  private interface Work<T> {
    T run(Connection c) throws SQLException;
  }

  private <T> T transaction(Work<T> work) {
    try (var c = dataSource.getConnection()) {
      c.setAutoCommit(false);
      c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      try {
        limits(c);
        T result = work.run(c);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException failure) {
        c.rollback();
        throw failure;
      }
    } catch (SQLException failure) {
      throw new IllegalStateException("Recovery storage unavailable");
    }
  }

  private static void limits(Connection c) throws SQLException {
    try (var s = c.createStatement()) {
      s.execute("SET LOCAL statement_timeout='5s'");
      s.execute("SET LOCAL lock_timeout='3s'");
    }
  }

  private static void execute(Connection c, String sql, Object... values) throws SQLException {
    try (var q = c.prepareStatement(sql)) {
      for (int i = 0; i < values.length; i++) q.setObject(i + 1, values[i]);
      q.executeUpdate();
    }
  }

  private static String json(Object object) {
    try {
      return SystemMapper.jsonMapper().writeValueAsString(object);
    } catch (java.io.IOException unavailable) {
      throw new IllegalArgumentException("Invalid recovery object");
    }
  }

  private byte[] phoneBinding(String number) {
    try {
      var mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(configuration.phoneBindingKey().value(), "HmacSHA256"));
      return mac.doFinal(("bconnected.phone.v1\0" + number).getBytes(StandardCharsets.UTF_8));
    } catch (java.security.GeneralSecurityException impossible) {
      throw new IllegalStateException();
    }
  }

  private static String nonceHash(String nonce) {
    try {
      byte[] bytes = Base64.getUrlDecoder().decode(nonce);
      if (bytes.length != 32
          || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(nonce))
        throw new IllegalArgumentException();
      var digest = MessageDigest.getInstance("SHA-256");
      digest.update("bconnected.recovery-attempt.v1\0".getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest.digest(bytes));
    } catch (Exception malformed) {
      throw new IllegalArgumentException("Invalid recovery nonce");
    }
  }

  private static boolean constant(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }
}
