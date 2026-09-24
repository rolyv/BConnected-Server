// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.ClientType;
import org.whispersystems.textsecuregcm.registration.MessageTransport;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceException;
import org.whispersystems.textsecuregcm.registration.VerificationCodeExpiredException;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;

/**
 * A phone-only application proof. This service cannot create accounts or approve applications.
 * The application UUID and nonce are bound to one native Telnyx session before any SMS is sent.
 */
public final class PhoneSignupService {
  private static final Duration TIMEOUT = Duration.ofSeconds(15);
  private static final long MAX_APPLICATION_MS = Duration.ofMinutes(30).toMillis();
  private static final long PROOF_MS = Duration.ofDays(30).toMillis();
  private final DataSource dataSource;
  private final Clock clock;
  private final TelnyxRegistrationService registration;
  private final AdmissionServiceClient admission;
  private final byte[] phoneBindingKey;

  public PhoneSignupService(DataSource dataSource, Clock clock, TelnyxRegistrationService registration,
      AdmissionServiceClient admission, byte[] phoneBindingKey) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
    this.registration = Objects.requireNonNull(registration);
    this.admission = Objects.requireNonNull(admission);
    if (phoneBindingKey == null || phoneBindingKey.length < 32)
      throw new IllegalArgumentException("Phone binding key must contain at least 32 bytes");
    this.phoneBindingKey = phoneBindingKey.clone();
  }

  public Result execute(MobileEnrollmentParser.Operation action, UUID applicationId, String enrollmentNonce,
      String phoneNumber, String code, String trustedSource, String acceptLanguage) {
    try {
      if (action == null || applicationId == null || applicationId.equals(new UUID(0, 0)))
        return error(Code.INVALID_REQUEST);
      final String canonical = canonical(phoneNumber);
      final String nonceHash = nonceHash(enrollmentNonce);
      final String lookupHash = sha256("bconnected.phone-allowlist.v1\0" + canonical);
      return switch (action) {
        case BEGIN -> begin(applicationId, nonceHash, lookupHash, canonical, trustedSource);
        case SEND_CODE -> send(applicationId, nonceHash, lookupHash, canonical, acceptLanguage);
        case CHECK_CODE -> check(applicationId, nonceHash, lookupHash, canonical, code);
        case STATUS -> status(applicationId, nonceHash, lookupHash, canonical);
        default -> error(Code.INVALID_REQUEST);
      };
    } catch (Rejected rejected) {
      return error(rejected.code);
    } catch (RateLimitExceededException limited) {
      Long seconds = limited.getRetryDuration().filter(d -> !d.isNegative())
          .map(d -> Math.addExact(d.getSeconds(), d.getNano() == 0 ? 0 : 1)).orElse(null);
      return error(Code.RATE_LIMITED, seconds);
    } catch (IllegalArgumentException malformed) {
      return error(Code.INVALID_REQUEST);
    } catch (Exception unavailable) {
      // Never serialize SQL, provider, IAM, phone, nonce, or proof details to callers.
      return error(Code.TEMPORARILY_UNAVAILABLE);
    }
  }

  private Result begin(UUID id, String nonceHash, String lookupHash, String number, String source) throws Exception {
    if (source == null || source.isBlank()) throw new IllegalArgumentException("Trusted source required");
    // A verified application may no longer issue an unverified private claim. Its native
    // operation is already bound, so authenticate the existing row and resume callback recovery.
    final boolean existingOperation;
    try (var connection = dataSource.getConnection()) {
      Row existing = load(connection, id, false);
      if (existing != null) {
        authenticate(existing, nonceHash, lookupHash, number);
      }
      existingOperation = existing != null;
    }
    if (existingOperation) return status(id, nonceHash, lookupHash, number);
    var claim = admission.signupClaim(id, nonceHash, lookupHash);
    claim.requireFresh();
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        // Locks absence as well as presence. A retry cannot allocate a second provider session.
        try (var lock = connection.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?)::bigint)")) {
          lock.setString(1, id.toString());
          lock.execute();
        }
        Row row = load(connection, id, true);
        if (row == null) {
          claim.requireFresh();
          Phonenumber.PhoneNumber parsed = PhoneNumberUtil.getInstance().parse(number, null);
          RegistrationServiceSession session = registration.createRegistrationSessionInTransaction(
              connection, parsed, source, TIMEOUT, claim::requireFresh);
          if (!number.equals(session.number())) throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
          long now = clock.millis();
          long applicationExpires = Math.min(claim.expiresAtMillis(), Math.addExact(now, MAX_APPLICATION_MS));
          if (applicationExpires <= now) throw new Rejected(Code.ENROLLMENT_EXPIRED);
          long nativeExpires = nativeExpiry(connection, session.id());
          try (var insert = connection.prepareStatement("""
              INSERT INTO signal.phone_signup_operations
                (operation_id,nonce_hash,phone_lookup_hash,requested_number,native_session_id,
                 native_session_expires_ms,created_ms,application_expires_ms)
              VALUES (?,?,?,?,?,?,?,?)
              """)) {
            insert.setObject(1, id);
            insert.setString(2, nonceHash);
            insert.setString(3, lookupHash);
            insert.setString(4, number);
            insert.setBytes(5, session.id());
            insert.setLong(6, nativeExpires);
            insert.setLong(7, now);
            insert.setLong(8, applicationExpires);
            insert.executeUpdate();
          }
          row = load(connection, id, false);
        } else authenticate(row, nonceHash, lookupHash, number);
        claim.requireFresh();
        connection.commit();
      } catch (Exception | java.lang.Error failure) {
        connection.rollback();
        throw failure;
      }
    }
    return status(id, nonceHash, lookupHash, number);
  }

  private Result send(UUID id, String nonceHash, String lookupHash, String number, String language) throws Exception {
    Row row = authenticated(id, nonceHash, lookupHash, number);
    activeBeforeVerification(row);
    var claim = admission.signupClaim(id, nonceHash, lookupHash);
    claim.requireFresh();
    RegistrationServiceSession session = registration.sendVerificationCode(row.nativeSessionId,
        MessageTransport.SMS, ClientType.IOS, language, null, TIMEOUT, claim::requireFresh);
    return snapshot(row, session);
  }

  private Result check(UUID id, String nonceHash, String lookupHash, String number, String code) throws Exception {
    if (code == null || !code.matches("[0-9]{4,10}")) throw new IllegalArgumentException("Invalid code");
    Row row = authenticated(id, nonceHash, lookupHash, number);
    activeBeforeVerification(row);
    var claim = admission.signupClaim(id, nonceHash, lookupHash);
    claim.requireFresh();
    final RegistrationServiceSession session;
    try {
      session = registration.checkVerificationCode(row.nativeSessionId, code, TIMEOUT, claim::requireFresh);
    } catch (VerificationCodeExpiredException expiredCode) {
      return error(Code.CODE_EXPIRED);
    } catch (RegistrationServiceException unavailableCode) {
      return error(Code.CODE_NOT_ACCEPTED);
    }
    if (!session.verified()) return error(Code.CODE_NOT_ACCEPTED);
    persistNativeProof(id, nonceHash, lookupHash, number);
    return confirmAndSnapshot(id, nonceHash, lookupHash, number);
  }

  private Result status(UUID id, String nonceHash, String lookupHash, String number) throws Exception {
    Row row = authenticated(id, nonceHash, lookupHash, number);
    if (row.verifiedAt == null && clock.millis() < Math.min(row.applicationExpires, row.nativeExpires)) {
      // This read recovers a verified result whose provider response was lost after the native SQL commit.
      persistNativeProof(id, nonceHash, lookupHash, number);
      row = authenticated(id, nonceHash, lookupHash, number);
    }
    if (row.verifiedAt != null) return confirmAndSnapshot(id, nonceHash, lookupHash, number);
    activeBeforeVerification(row);
    return snapshot(row);
  }

  private Result confirmAndSnapshot(UUID id, String nonceHash, String lookupHash, String number) throws Exception {
    Row row = authenticated(id, nonceHash, lookupHash, number);
    if (row.verifiedAt == null) throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
    if (clock.millis() >= row.proofExpires) throw new Rejected(Code.ENROLLMENT_EXPIRED);
    if (!row.confirmed) {
      admission.confirmSignupPhone(id, nonceHash, lookupHash, phoneBinding(number),
          row.verifiedAt, row.proofExpires);
      try (var connection = dataSource.getConnection();
          var update = connection.prepareStatement("""
              UPDATE signal.phone_signup_operations SET community_confirmed=true
              WHERE operation_id=? AND nonce_hash=? AND phone_lookup_hash=?
                AND verified_at_ms=? AND proof_expires_ms=?
              """)) {
        update.setObject(1, id);
        update.setString(2, nonceHash);
        update.setString(3, lookupHash);
        update.setLong(4, row.verifiedAt);
        update.setLong(5, row.proofExpires);
        if (update.executeUpdate() != 1) throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
      }
      row = authenticated(id, nonceHash, lookupHash, number);
    }
    return snapshot(row);
  }

  private void persistNativeProof(UUID id, String nonceHash, String lookupHash, String number) throws SQLException {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        Row row = load(connection, id, true);
        if (row == null) throw new Rejected(Code.ENROLLMENT_UNAVAILABLE);
        authenticate(row, nonceHash, lookupHash, number);
        if (row.verifiedAt == null) {
          long now = clock.millis();
          if (now >= Math.min(row.applicationExpires, row.nativeExpires)) {
            connection.commit();
            return;
          }
          try (var nativeRead = connection.prepareStatement("""
              SELECT number,verified,expires_ms FROM signal.registration_sessions WHERE id=? FOR UPDATE
              """)) {
            nativeRead.setBytes(1, row.nativeSessionId);
            try (var result = nativeRead.executeQuery()) {
              if (!result.next() || !number.equals(result.getString("number"))
                  || result.getLong("expires_ms") != row.nativeExpires)
                throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
              if (result.getBoolean("verified") && result.getLong("expires_ms") > now) {
                try (var update = connection.prepareStatement("""
                    UPDATE signal.phone_signup_operations SET verified_at_ms=?,proof_expires_ms=?
                    WHERE operation_id=? AND verified_at_ms IS NULL
                    """)) {
                  update.setLong(1, now);
                  update.setLong(2, Math.addExact(now, PROOF_MS));
                  update.setObject(3, id);
                  if (update.executeUpdate() != 1) throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
                }
              }
            }
          }
        }
        connection.commit();
      } catch (SQLException | RuntimeException | java.lang.Error failure) {
        connection.rollback();
        throw failure;
      }
    }
  }

  private Row authenticated(UUID id, String nonceHash, String lookupHash, String number) throws SQLException {
    try (var connection = dataSource.getConnection()) {
      Row row = load(connection, id, false);
      if (row == null) throw new Rejected(Code.ENROLLMENT_UNAVAILABLE);
      authenticate(row, nonceHash, lookupHash, number);
      return row;
    }
  }

  private static void authenticate(Row row, String nonceHash, String lookupHash, String number) {
    if (!MessageDigest.isEqual(row.nonceHash.getBytes(StandardCharsets.US_ASCII),
            nonceHash.getBytes(StandardCharsets.US_ASCII))
        || !MessageDigest.isEqual(row.lookupHash.getBytes(StandardCharsets.US_ASCII),
            lookupHash.getBytes(StandardCharsets.US_ASCII))
        || !row.number.equals(number)) throw new Rejected(Code.INVALID_CREDENTIALS);
  }

  private void activeBeforeVerification(Row row) {
    if (row.verifiedAt != null) throw new Rejected(Code.ENROLLMENT_CONFLICT);
    if (clock.millis() >= Math.min(row.applicationExpires, row.nativeExpires))
      throw new Rejected(Code.ENROLLMENT_EXPIRED);
  }

  private Result snapshot(Row row) throws Exception {
    if (row.verifiedAt != null) {
      if (clock.millis() >= row.proofExpires) throw new Rejected(Code.ENROLLMENT_EXPIRED);
      return new Result(200, new Verification(row.id, "verification", row.confirmed,
          null, null, secondsUntil(row.proofExpires), false));
    }
    activeBeforeVerification(row);
    RegistrationServiceSession session = registration.getSession(row.nativeSessionId, TIMEOUT)
        .orElseThrow(() -> new Rejected(Code.ENROLLMENT_EXPIRED));
    return snapshot(row, session);
  }

  private Result snapshot(Row row, RegistrationServiceSession session) {
    if (!row.number.equals(session.number()) || !MessageDigest.isEqual(row.nativeSessionId, session.id()))
      throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
    return new Result(200, new Verification(row.id, "verification", false,
        session.nextSms(), session.nextVerificationAttempt(),
        Math.min(session.expiration(), secondsUntil(row.applicationExpires)), false));
  }

  private long secondsUntil(long end) {
    long remaining = Math.max(0, end - clock.millis());
    return remaining / 1000 + (remaining % 1000 == 0 ? 0 : 1);
  }

  private static long nativeExpiry(Connection connection, byte[] session) throws SQLException {
    try (var query = connection.prepareStatement("SELECT expires_ms FROM signal.registration_sessions WHERE id=?")) {
      query.setBytes(1, session);
      try (var result = query.executeQuery()) {
        if (!result.next()) throw new Rejected(Code.TEMPORARILY_UNAVAILABLE);
        return result.getLong(1);
      }
    }
  }

  private static Row load(Connection connection, UUID id, boolean lock) throws SQLException {
    try (var query = connection.prepareStatement("SELECT * FROM signal.phone_signup_operations WHERE operation_id=?"
        + (lock ? " FOR UPDATE" : ""))) {
      query.setObject(1, id);
      try (var result = query.executeQuery()) {
        return result.next() ? new Row(result) : null;
      }
    }
  }

  private static String canonical(String phone) {
    if (phone == null || !phone.matches("\\+[1-9][0-9]{1,14}"))
      throw new IllegalArgumentException("Invalid E.164 phone");
    try {
      var parsed = PhoneNumberUtil.getInstance().parse(phone, null);
      if (!PhoneNumberUtil.getInstance().isPossibleNumber(parsed)
          || !phone.equals(PhoneNumberUtil.getInstance().format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164)))
        throw new IllegalArgumentException("Invalid E.164 phone");
      return phone;
    } catch (com.google.i18n.phonenumbers.NumberParseException malformed) {
      throw new IllegalArgumentException("Invalid E.164 phone");
    }
  }

  private static String nonceHash(String nonce) {
    if (nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}"))
      throw new IllegalArgumentException("Invalid nonce");
    byte[] raw = Base64.getUrlDecoder().decode(nonce);
    if (raw.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(nonce))
      throw new IllegalArgumentException("Invalid nonce");
    return sha256(nonce);
  }

  private static String sha256(String input) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(input.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException impossible) {
      throw new IllegalStateException("SHA-256 unavailable");
    }
  }

  private String phoneBinding(String number) {
    try {
      var mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(phoneBindingKey, "HmacSHA256"));
      mac.update("bconnected.phone.v1\0".getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(mac.doFinal(number.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException impossible) {
      throw new IllegalStateException("Phone binding unavailable");
    }
  }

  private record Row(UUID id, String nonceHash, String lookupHash, String number, byte[] nativeSessionId,
      long nativeExpires, long applicationExpires, Long verifiedAt, Long proofExpires, boolean confirmed) {
    private Row(ResultSet result) throws SQLException {
      this(result.getObject("operation_id", UUID.class), result.getString("nonce_hash"),
          result.getString("phone_lookup_hash"), result.getString("requested_number"),
          result.getBytes("native_session_id"), result.getLong("native_session_expires_ms"),
          result.getLong("application_expires_ms"), result.getObject("verified_at_ms", Long.class),
          result.getObject("proof_expires_ms", Long.class), result.getBoolean("community_confirmed"));
    }
  }

  private static final class Rejected extends RuntimeException {
    private final Code code;
    private Rejected(Code code) { super(null, null, false, false); this.code = code; }
  }
}
