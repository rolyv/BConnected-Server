// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import io.grpc.Status;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.VerificationSessionRateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.ClientType;
import org.whispersystems.textsecuregcm.registration.MessageTransport;
import org.whispersystems.textsecuregcm.registration.RegistrationService;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceException;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceSenderException;
import org.whispersystems.textsecuregcm.registration.TransportNotAllowedException;
import org.whispersystems.textsecuregcm.registration.VerificationCodeExpiredException;

/**
 * Durable coordinator behind VerificationController's CAPTCHA, push and fraud checks. Provider calls happen only
 * after committing a budget reservation, outside database transactions. Unknown outcomes are never retried here.
 */
public final class TelnyxRegistrationService implements RegistrationService {
  private static final int SESSION_ID_LENGTH = 32;
  private static final SecureRandom RANDOM = new SecureRandom();
  private final DataSource dataSource;
  private final TelnyxVerifyClient provider;
  private final TelnyxRegistrationPolicy policy;
  private final byte[] collationKey;
  private final Clock clock;

  public TelnyxRegistrationService(final DataSource dataSource, final TelnyxVerifyClient provider,
      final TelnyxRegistrationPolicy policy, final byte[] collationKey, final Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.provider = Objects.requireNonNull(provider);
    this.policy = Objects.requireNonNull(policy);
    if (collationKey == null || collationKey.length < 32) {
      throw new IllegalArgumentException("Registration collation key must contain at least 32 bytes");
    }
    this.collationKey = collationKey.clone();
    this.clock = Objects.requireNonNull(clock);
  }

  @Override
  public RegistrationServiceSession createRegistrationSession(final Phonenumber.PhoneNumber phoneNumber,
      final String sourceHost, final boolean accountExistsWithPhoneNumber, @Nullable final String clientMcc,
      @Nullable final String clientMnc, final Duration timeout) throws RateLimitExceededException {
    try {
      return transaction(connection -> createSession(connection, phoneNumber, sourceHost, timeout, () -> {}));
    } catch (Rejected e) {
      throw new RateLimitExceededException(e.retryAfter);
    }
  }

  /** Native SQL only: the caller owns commit/rollback of the explicit transaction. */
  public RegistrationServiceSession createRegistrationSessionInTransaction(final Connection connection,
      final Phonenumber.PhoneNumber phoneNumber, final String sourceHost, final Duration timeout,
      final Runnable admissionGuard) throws SQLException, RateLimitExceededException {
    if (connection.getAutoCommit()) {
      throw new IllegalArgumentException("Explicit registration transaction required");
    }
    try {
      return createSession(connection, phoneNumber, sourceHost, timeout, Objects.requireNonNull(admissionGuard));
    } catch (Rejected e) {
      throw new RateLimitExceededException(e.retryAfter);
    }
  }

  private RegistrationServiceSession createSession(final Connection connection,
      final Phonenumber.PhoneNumber phoneNumber, final String sourceHost, final Duration timeout,
      final Runnable admissionGuard) throws SQLException {
    validateTimeout(timeout);
    if (sourceHost == null || sourceHost.isBlank() || !PhoneNumberUtil.getInstance().isPossibleNumber(phoneNumber)) {
      throw new IllegalArgumentException("A valid phone number and trusted source address are required");
    }
    final String number = PhoneNumberUtil.getInstance().format(phoneNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
    final byte[] id = new byte[SESSION_ID_LENGTH];
    RANDOM.nextBytes(id);
    admissionGuard.run();
    final long now = clock.millis();
    quota(connection, "create:number", number, policy.maxSessionsPerNumber(), now, null);
    quota(connection, "create:source", sourceHost, policy.maxSessionsPerSource(), now, null);
    admissionGuard.run(); // Quota rows may have blocked while approval became stale.
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.registration_sessions (id, number, expires_ms) VALUES (?, ?, ?)
        """)) {
      statement.setBytes(1, id);
      statement.setString(2, number);
      statement.setLong(3, Math.addExact(clock.millis(), policy.sessionLifetime().toMillis()));
      statement.executeUpdate();
    }
    admissionGuard.run();
    return snapshot(load(connection, id, false).orElseThrow(), clock.millis());
  }

  @Override
  public Optional<RegistrationServiceSession> getSession(final byte[] sessionId, final Duration timeout) {
    validateTimeout(timeout);
    if (!validId(sessionId)) return Optional.empty();
    return transaction(connection -> {
      final Optional<State> state = load(connection, sessionId, false);
      final long now = clock.millis();
      return active(state, now).map(s -> snapshot(s, now));
    });
  }

  @Override
  public RegistrationServiceSession sendVerificationCode(final byte[] sessionId, final MessageTransport transport,
      final ClientType clientType, @Nullable final String acceptLanguage, @Nullable final String senderOverride,
      final Duration timeout) throws VerificationSessionRateLimitExceededException, RegistrationServiceException,
      RegistrationServiceSenderException {
    return sendVerificationCode(sessionId, transport, clientType, acceptLanguage, senderOverride, timeout, () -> {});
  }

  public RegistrationServiceSession sendVerificationCode(final byte[] sessionId, final MessageTransport transport,
      final ClientType clientType, @Nullable final String acceptLanguage, @Nullable final String senderOverride,
      final Duration timeout, final Runnable admissionGuard) throws VerificationSessionRateLimitExceededException,
      RegistrationServiceException, RegistrationServiceSenderException {
    Objects.requireNonNull(admissionGuard);
    validateTimeout(timeout);
    if (transport != MessageTransport.SMS) {
      throw new TransportNotAllowedException(getSession(sessionId, timeout).orElse(null));
    }
    if (senderOverride != null && !senderOverride.isBlank()) {
      // Sender overrides are admission/fraud decisions, not suggestions to silently ignore.
      throw RegistrationServiceSenderException.unavailable(true);
    }
    final Reservation reservation;
    try {
      reservation = reserve(sessionId, true, timeout);
    } catch (Rejected e) {
      throwRejected(e);
      throw new AssertionError();
    }

    admissionGuard.run(); // Reservation has committed: do not refund quota on stale approval.
    try {
      final TelnyxVerifyClient.Verification sent = provider.sendSms(reservation.number, timeout);
      if (!reservation.number.equals(sent.phoneNumber()) || sent.timeoutSeconds() < 1) {
        throw Status.UNAVAILABLE.withDescription("Invalid verification provider response").asRuntimeException();
      }
      final long codeExpires = Math.addExact(reservation.startedMs, Duration.ofSeconds(sent.timeoutSeconds()).toMillis());
      return complete(reservation, sent.id(), codeExpires, false);
    } catch (TelnyxVerifyException e) {
      final RegistrationServiceSession current = release(reservation, false, e.retryAfter().orElse(null))
          .orElseThrow(() -> new RegistrationServiceException(null));
      switch (e.reason()) {
        case RATE_LIMITED -> throw new VerificationSessionRateLimitExceededException(current,
            e.retryAfter().orElse(null), true);
        case INVALID_REQUEST -> throw RegistrationServiceSenderException.illegalArgument(true);
        case REJECTED -> throw RegistrationServiceSenderException.rejected(true);
        default -> throw RegistrationServiceSenderException.unavailable(false);
      }
    } catch (Rejected e) {
      throwRejected(e);
      throw new AssertionError();
    }
  }

  @Override
  public RegistrationServiceSession checkVerificationCode(final byte[] sessionId, final String verificationCode,
      final Duration timeout) throws VerificationSessionRateLimitExceededException, RegistrationServiceException {
    return checkVerificationCode(sessionId, verificationCode, timeout, () -> {});
  }

  public RegistrationServiceSession checkVerificationCode(final byte[] sessionId, final String verificationCode,
      final Duration timeout, final Runnable admissionGuard)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException {
    Objects.requireNonNull(admissionGuard);
    validateTimeout(timeout);
    if (verificationCode == null || !verificationCode.matches("[0-9]{4,10}")) {
      throw new IllegalArgumentException("Invalid verification code format");
    }
    final Reservation reservation;
    try {
      reservation = reserve(sessionId, false, timeout);
    } catch (Rejected e) {
      throwRejected(e);
      throw new AssertionError();
    }
    admissionGuard.run(); // Reservation has committed: stale approval never reaches the provider.
    try {
      final boolean accepted = provider.verify(reservation.providerId, reservation.number, verificationCode, timeout);
      return complete(reservation, null, 0, accepted);
    } catch (TelnyxVerifyException e) {
      final RegistrationServiceSession current = release(reservation, e.reason() == TelnyxVerifyException.Reason.NOT_FOUND,
          e.retryAfter().orElse(null)).orElseThrow(() -> new RegistrationServiceException(null));
      if (e.reason() == TelnyxVerifyException.Reason.RATE_LIMITED) {
        throw new VerificationSessionRateLimitExceededException(current, e.retryAfter().orElse(null), true);
      }
      if (e.reason() == TelnyxVerifyException.Reason.NOT_FOUND || e.reason() == TelnyxVerifyException.Reason.INVALID_REQUEST) {
        throw new RegistrationServiceException(current);
      }
      throw Status.UNAVAILABLE.withDescription("Verification provider unavailable").asRuntimeException();
    } catch (Rejected e) {
      throwRejected(e);
      throw new AssertionError();
    }
  }

  private Reservation reserve(final byte[] id, final boolean send, final Duration timeout) {
    if (!validId(id)) throw new Rejected(null, null, false);
    return transaction(connection -> {
      final State state = load(connection, id, true).orElseThrow(() -> new Rejected(null, null, false));
      final long now = clock.millis();
      if (state.expiresMs <= now) throw new Rejected(null, null, false);
      final RegistrationServiceSession session = snapshot(state, now);
      if (state.verified) throw new Rejected(session, null, false);
      if (state.operationId != null && state.operationExpiresMs > now) {
        throw new Rejected(session, Duration.ofMillis(state.operationExpiresMs - now), true);
      }
      final int count = send ? state.smsCount : state.checkCount;
      final int max = send ? policy.maxSmsPerSession() : policy.maxChecksPerSession();
      if (count >= max) throw new Rejected(session, null, true);
      final long next = send ? state.nextSmsMs : state.nextCheckMs;
      if (next > now) throw new Rejected(session, Duration.ofMillis(next - now), true);
      if (!send) {
        if (state.providerId == null) throw new Rejected(session, null, false);
        if (state.codeExpiresMs <= now) throw Rejected.expiredCode(session);
      }
      quota(connection, send ? "send:number" : "check:number", state.number,
          send ? policy.maxSmsPerNumber() : policy.maxChecksPerNumber(), now, session);

      final UUID operation = UUID.randomUUID();
      final long leaseExpires = Math.addExact(now, timeout.plusSeconds(5).toMillis());
      final String mutation = send
          ? "sms_count=sms_count+1, next_sms_ms=?, provider_verification_id=NULL, code_expires_ms=NULL"
          : "check_count=check_count+1, next_check_ms=?";
      try (var statement = connection.prepareStatement(
          "UPDATE signal.registration_sessions SET " + mutation + ", operation_id=?, operation_expires_ms=? WHERE id=?")) {
        statement.setLong(1, Math.addExact(now, (send ? policy.smsCooldown() : policy.checkCooldown()).toMillis()));
        statement.setObject(2, operation);
        statement.setLong(3, leaseExpires);
        statement.setBytes(4, id);
        statement.executeUpdate();
      }
      return new Reservation(id.clone(), state.number, state.providerId, operation, now, send);
    });
  }

  private RegistrationServiceSession complete(final Reservation reservation, @Nullable final UUID providerId,
      final long codeExpires, final boolean accepted) {
    return transaction(connection -> {
      // Measure expiry after obtaining the row lock, not before a potentially blocking UPDATE.
      final State current = load(connection, reservation.id, true)
          .orElseThrow(() -> new Rejected(null, null, false));
      final long now = clock.millis();
      // Attribute expiry only to this exact in-flight check. A later send, missing
      // provider binding or expired session is not evidence that this code expired.
      if (!reservation.send && !current.verified && current.expiresMs > now
          && reservation.operationId.equals(current.operationId)
          && reservation.providerId.equals(current.providerId) && current.codeExpiresMs <= now) {
        throw Rejected.expiredCode(snapshot(current, now));
      }
      final String mutation = reservation.send
          ? "provider_verification_id=?, code_expires_ms=LEAST(expires_ms, ?)"
          : "verified=?";
      try (var statement = connection.prepareStatement("UPDATE signal.registration_sessions SET " + mutation + """
          , operation_id=NULL, operation_expires_ms=NULL
          WHERE id=? AND operation_id=? AND expires_ms>? AND operation_expires_ms>?
          """ + (reservation.send ? "" : " AND code_expires_ms>?"))) {
        int parameter = 1;
        if (reservation.send) {
          statement.setObject(parameter++, Objects.requireNonNull(providerId));
          statement.setLong(parameter++, codeExpires);
        } else {
          statement.setBoolean(parameter++, accepted);
        }
        statement.setBytes(parameter++, reservation.id);
        statement.setObject(parameter++, reservation.operationId);
        statement.setLong(parameter++, now);
        statement.setLong(parameter++, now);
        if (!reservation.send) statement.setLong(parameter, now);
        if (statement.executeUpdate() != 1) {
          throw new Rejected(active(load(connection, reservation.id, false), now)
              .map(state -> snapshot(state, now)).orElse(null), null, false);
        }
      }
      return snapshot(load(connection, reservation.id, false).orElseThrow(), now);
    });
  }

  private Optional<RegistrationServiceSession> release(final Reservation reservation, final boolean discardProvider,
      @Nullable final Duration retryAfter) {
    return transaction(connection -> {
      final long now = clock.millis();
      final String cooldown = reservation.send ? "next_sms_ms" : "next_check_ms";
      try (var statement = connection.prepareStatement("UPDATE signal.registration_sessions SET " + cooldown
          + "=GREATEST(" + cooldown + ", ?), operation_id=NULL, operation_expires_ms=NULL"
          + (discardProvider ? ", provider_verification_id=NULL, code_expires_ms=NULL" : "")
          + " WHERE id=? AND operation_id=?")) {
        final long delay = retryAfter == null || retryAfter.isNegative() ? 0
            : Math.min(retryAfter.toMillis(), policy.sessionLifetime().toMillis());
        statement.setLong(1, Math.addExact(now, delay));
        statement.setBytes(2, reservation.id);
        statement.setObject(3, reservation.operationId);
        statement.executeUpdate();
      }
      return active(load(connection, reservation.id, false), now).map(state -> snapshot(state, now));
    });
  }

  private void quota(final Connection connection, final String scope, final String key, final int maximum,
      final long now, @Nullable final RegistrationServiceSession session) throws SQLException {
    final long window = policy.quotaWindow().toMillis();
    final long start = Math.floorDiv(now, window) * window;
    final long expires = Math.addExact(start, window);
    try (var statement = connection.prepareStatement("""
        INSERT INTO signal.registration_quotas (scope, key_hash, window_start_ms, expires_ms, attempts)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT (scope, key_hash, window_start_ms) DO UPDATE SET attempts=signal.registration_quotas.attempts+1
        WHERE signal.registration_quotas.attempts<? RETURNING attempts
        """)) {
      statement.setString(1, scope);
      statement.setBytes(2, hmac(scope, key));
      statement.setLong(3, start);
      statement.setLong(4, expires);
      statement.setInt(5, maximum);
      try (var rows = statement.executeQuery()) {
        if (!rows.next()) throw new Rejected(session, Duration.ofMillis(expires - now), true);
      }
    }
  }

  private byte[] hmac(final String scope, final String key) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(collationKey, "HmacSHA256"));
      mac.update(scope.getBytes(StandardCharsets.UTF_8));
      mac.update((byte) 0);
      return mac.doFinal(key.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Cannot derive registration quota key", e);
    }
  }

  private Optional<State> load(final Connection connection, final byte[] id, final boolean lock) throws SQLException {
    try (var statement = connection.prepareStatement("SELECT * FROM signal.registration_sessions WHERE id=?"
        + (lock ? " FOR UPDATE" : ""))) {
      statement.setBytes(1, id);
      try (var rows = statement.executeQuery()) {
        return rows.next() ? Optional.of(new State(rows)) : Optional.empty();
      }
    }
  }

  private static Optional<State> active(final Optional<State> state, final long now) {
    return state.filter(s -> s.expiresMs > now);
  }

  private RegistrationServiceSession snapshot(final State state, final long now) {
    final long pending = state.operationId == null ? 0 : state.operationExpiresMs;
    final Long nextSms = state.verified || state.smsCount >= policy.maxSmsPerSession() ? null
        : secondsUntil(Math.max(state.nextSmsMs, pending), now);
    final Long nextCheck = state.verified || state.providerId == null || state.codeExpiresMs <= now
        || state.checkCount >= policy.maxChecksPerSession() ? null
        : secondsUntil(Math.max(state.nextCheckMs, pending), now);
    return new RegistrationServiceSession(state.id.clone(), state.number, state.verified, nextSms, null, nextCheck,
        secondsUntil(state.expiresMs, now));
  }

  private static long secondsUntil(final long until, final long now) {
    final long remaining = Math.max(0, until - now);
    return remaining / 1000 + (remaining % 1000 == 0 ? 0 : 1);
  }

  private static void throwRejected(final Rejected rejected)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException {
    if (rejected.rateLimited && rejected.session != null) {
      throw new VerificationSessionRateLimitExceededException(rejected.session, rejected.retryAfter, true);
    }
    if (rejected.codeExpired) throw new VerificationCodeExpiredException(rejected.session);
    throw new RegistrationServiceException(rejected.session);
  }

  private static void validateTimeout(final Duration timeout) {
    if (timeout == null || timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofSeconds(60)) > 0) {
      throw new IllegalArgumentException("Registration request timeout must be positive and at most 60 seconds");
    }
  }

  private static boolean validId(final byte[] id) { return id != null && id.length == SESSION_ID_LENGTH; }

  @FunctionalInterface
  private interface SqlWork<T> { T run(Connection connection) throws SQLException; }

  private <T> T transaction(final SqlWork<T> work) {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        final T result = work.run(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException | Error e) {
        try { connection.rollback(); } catch (SQLException rollbackFailure) { e.addSuppressed(rollbackFailure); }
        throw e;
      }
    } catch (SQLException e) {
      throw Status.UNAVAILABLE.withDescription("Registration storage unavailable").withCause(e).asRuntimeException();
    }
  }

  /** Bounds cleanup work; neither active sessions nor the current quota window are removed. */
  public int deleteExpired(final int limit) {
    if (limit < 1 || limit > 10000) throw new IllegalArgumentException("Invalid expiry batch size");
    return transaction(connection -> {
      int removed = 0;
      for (String table : new String[] {"registration_sessions", "registration_quotas"}) {
        try (var statement = connection.prepareStatement("WITH expired AS (SELECT ctid FROM signal." + table
            + " WHERE expires_ms<=? ORDER BY expires_ms LIMIT ? FOR UPDATE SKIP LOCKED) DELETE FROM signal."
            + table + " t USING expired e WHERE t.ctid=e.ctid")) {
          statement.setLong(1, clock.millis());
          statement.setInt(2, limit);
          removed += statement.executeUpdate();
        }
      }
      return removed;
    });
  }

  @Override
  public void stop() { provider.close(); }

  private record Reservation(byte[] id, String number, UUID providerId, UUID operationId, long startedMs, boolean send) {}

  private record State(byte[] id, String number, long expiresMs, boolean verified, UUID providerId, long codeExpiresMs,
      int smsCount, int checkCount, long nextSmsMs, long nextCheckMs, UUID operationId, long operationExpiresMs) {
    private State(final ResultSet rows) throws SQLException {
      this(rows.getBytes("id"), rows.getString("number"), rows.getLong("expires_ms"), rows.getBoolean("verified"),
          rows.getObject("provider_verification_id", UUID.class), rows.getLong("code_expires_ms"),
          rows.getInt("sms_count"), rows.getInt("check_count"), rows.getLong("next_sms_ms"), rows.getLong("next_check_ms"),
          rows.getObject("operation_id", UUID.class), rows.getLong("operation_expires_ms"));
    }
  }

  private static final class Rejected extends RuntimeException {
    private final RegistrationServiceSession session;
    private final Duration retryAfter;
    private final boolean rateLimited;
    private final boolean codeExpired;
    private Rejected(@Nullable final RegistrationServiceSession session, @Nullable final Duration retryAfter,
        final boolean rateLimited) {
      this(session, retryAfter, rateLimited, false);
    }
    private Rejected(@Nullable final RegistrationServiceSession session, @Nullable final Duration retryAfter,
        final boolean rateLimited, final boolean codeExpired) {
      super(null, null, false, false);
      this.session = session;
      this.retryAfter = retryAfter;
      this.rateLimited = rateLimited;
      this.codeExpired = codeExpired;
    }
    private static Rejected expiredCode(final RegistrationServiceSession session) {
      return new Rejected(Objects.requireNonNull(session), null, false, true);
    }
  }
}
