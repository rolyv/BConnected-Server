// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.Util;

/**
 * Durable request identity only. This does not establish alumni approval, create verification
 * sessions, send SMS, redeem permits, or activate accounts. All controller routes remain unwired.
 */
public final class RegistrationOperations {
  private final DataSource dataSource;
  private final Clock clock;
  private final RegistrationRequestCommitment commitment;

  public RegistrationOperations(
      DataSource dataSource, Clock clock, RegistrationRequestCommitment commitment) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
    this.commitment = Objects.requireNonNull(commitment);
  }

  public static final class OperationRejectedException extends RuntimeException {
    private OperationRejectedException() {
      super("Registration operation unavailable or inputs changed");
    }
  }

  public static final class OperationUnavailableException extends RuntimeException {
    private OperationUnavailableException() {
      super("Registration operation storage unavailable");
    }
  }

  /**
   * Constructible only after password verification and immutable request comparison. Not an
   * approval permit.
   */
  public static final class AuthenticatedOperation {
    private final Stored row;

    private AuthenticatedOperation(Stored row) {
      this.row = row;
    }

    public UUID operationId() {
      return row.id;
    }

    public UUID memberId() {
      return row.member;
    }

    public String registrationAttemptHash() {
      return hex(row.attempt);
    }

    public String challengeHash() {
      return hex(row.challenge);
    }

    public String deviceKeyCommitment() {
      return hex(row.keys);
    }

    public String serverRequestCommitment() {
      return hex(row.request);
    }

    public String requestedNumber() {
      return row.number;
    }

    public long expiresAtMillis() {
      return row.expires;
    }

    // Future account construction must use this original verifier, rather than generating another
    // salt.
    void applyAuthenticationTo(Device device) {
      row.authentication.applyTo(device);
    }

    @Override
    public String toString() {
      return "AuthenticatedOperation[redacted]";
    }
  }

  /**
   * A fresh read of the assigned native phone-verification row; this is not membership entitlement.
   */
  public static final class VerifiedPhone {
    private final UUID operation;
    private final String number, sessionHash;
    private final long observed, expires;

    private VerifiedPhone(
        UUID operation, String number, String sessionHash, long observed, long expires) {
      this.operation = operation;
      this.number = number;
      this.sessionHash = sessionHash;
      this.observed = observed;
      this.expires = expires;
    }

    public UUID operationId() {
      return operation;
    }

    public String canonicalNumber() {
      return number;
    }

    public String serverVerificationSessionHash() {
      return sessionHash;
    }

    public long observedAtMillis() {
      return observed;
    }

    public long sessionExpiresAtMillis() {
      return expires;
    }

    @Override
    public String toString() {
      return "VerifiedPhone[redacted]";
    }
  }

  private record Stored(
      UUID id,
      UUID member,
      byte[] attempt,
      byte[] challenge,
      byte[] keys,
      byte[] request,
      String number,
      RegistrationAuthentication authentication,
      long created,
      long expires,
      byte[] session,
      byte[] sessionHash,
      Long sessionExpires) {
    @Override
    public String toString() {
      return "StoredRegistrationOperation[redacted]";
    }
  }

  public AuthenticatedOperation prepareOrAuthenticateRetry(
      UUID memberId,
      String attemptNonce,
      String bindingChallenge,
      String requestedNumber,
      String password,
      RegistrationRequest request,
      String signalAgent,
      String userAgent) {
    requireUuid(memberId);
    byte[] attempt = hash("bconnected.registration-attempt.v1", decodeNonce(attemptNonce));
    decodeNonce(
        bindingChallenge); // Validate canonical encoding; community hashes the encoded challenge
                           // text.
    byte[] challenge = hash(null, bindingChallenge.getBytes(StandardCharsets.US_ASCII));
    try (var canonical =
        CanonicalRegistrationRequest.beforeVerification(
            request, requestedNumber, signalAgent, userAgent)) {
      byte[] encoded = canonical.bytes();
      try {
        return transaction(
            connection -> {
              // A known operation can authenticate an exact retry after its own account commit.
              // A new operation for any pre-existing account is a recovery flow and is closed here.
              try (var existing =
                  connection.prepareStatement(
                      "SELECT 1 FROM signal.registration_operations WHERE member_id=? AND"
                          + " registration_attempt_hash=?")) {
                existing.setObject(1, memberId);
                existing.setBytes(2, attempt);
                try (var rows = existing.executeQuery()) {
                  if (!rows.next()) {
                    try (var account =
                        connection.prepareStatement(
                            "SELECT 1 FROM signal.accounts WHERE number = ANY(?)")) {
                      var alternatives =
                          connection.createArrayOf(
                              "text",
                              Util.getAlternateForms(canonical.number()).toArray(String[]::new));
                      try {
                        account.setArray(1, alternatives);
                        try (var found = account.executeQuery()) {
                          if (found.next()) throw new OperationRejectedException();
                        }
                      } finally {
                        alternatives.free();
                      }
                    }
                  }
                }
              }
              // New salts are never substituted on retry. Only the inserted winner's verifier is
              // authoritative.
              var proposedAuthentication = RegistrationAuthentication.create(password);
              byte[] proposedCommitment = requestCommitment(encoded, proposedAuthentication);
              UUID generated = UUID.randomUUID();
              long now = clock.millis();
              try (var statement =
                  connection.prepareStatement(
                      """
                      INSERT INTO signal.registration_operations(operation_id,member_id,registration_attempt_hash,challenge_hash,
                        device_key_commitment,server_request_commitment,requested_number,authentication_hash,authentication_salt,created_ms,expires_ms)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(member_id,registration_attempt_hash) DO NOTHING
                      """)) {
                statement.setObject(1, generated);
                statement.setObject(2, memberId);
                statement.setBytes(3, attempt);
                statement.setBytes(4, challenge);
                statement.setBytes(5, unhex(canonical.keyCommitment()));
                statement.setBytes(6, proposedCommitment);
                statement.setString(7, canonical.number());
                statement.setString(8, proposedAuthentication.hash());
                statement.setString(9, proposedAuthentication.salt());
                statement.setLong(10, now);
                statement.setLong(11, Math.addExact(now, 300000));
                statement.executeUpdate();
              }
              Stored stored;
              try (var statement =
                  connection.prepareStatement(
                      "SELECT * FROM signal.registration_operations WHERE member_id=? AND"
                          + " registration_attempt_hash=? FOR UPDATE")) {
                statement.setObject(1, memberId);
                statement.setBytes(2, attempt);
                try (var rows = statement.executeQuery()) {
                  if (!rows.next()) throw new OperationRejectedException();
                  stored = read(rows);
                }
              }
              requireActive(stored);
              if (!stored.authentication.verify(password)
                  || !equal(stored.challenge, challenge)
                  || !stored.number.equals(canonical.number())
                  || !equal(stored.keys, unhex(canonical.keyCommitment()))
                  || !equal(stored.request, requestCommitment(encoded, stored.authentication)))
                throw new OperationRejectedException();
              return new AuthenticatedOperation(stored);
            });
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
    }
  }

  /**
   * Internal future coordinator boundary only. It must first obtain private approval, create a
   * fresh session itself and pass that result here. Never wire a client-selected session ID into
   * this method. No public/session-creation API exists here until the approved-claim coordinator is
   * implemented.
   */
  void attachServerCreatedSession(
      AuthenticatedOperation authenticated, byte[] serverCreatedSessionId) {
    byte[] session = Objects.requireNonNull(serverCreatedSessionId).clone();
    if (session.length != 32) throw new OperationRejectedException();
    transaction(
        connection -> {
          var stored = lock(connection, authenticated);
          try (var statement =
              connection.prepareStatement(
                  "SELECT number,expires_ms,verified FROM signal.registration_sessions WHERE id=?"
                      + " FOR SHARE")) {
            statement.setBytes(1, session);
            try (var rows = statement.executeQuery()) {
              if (!rows.next()
                  || !stored.number.equals(rows.getString("number"))
                  || rows.getLong("expires_ms") <= clock.millis())
                throw new OperationRejectedException();
              long expires = rows.getLong("expires_ms");
              if (stored.session != null) {
                if (!equal(stored.session, session)
                    || !Objects.equals(stored.sessionExpires, expires))
                  throw new OperationRejectedException();
                requireActive(stored);
                return null;
              }
              // A newly associated session must still be unverified; verified sessions cannot be
              // imported.
              if (rows.getBoolean("verified")) throw new OperationRejectedException();
              try (var update =
                  connection.prepareStatement(
                      """
                      UPDATE signal.registration_operations SET verification_session_id=?,verification_session_hash=?,verification_session_expires_ms=?
                      WHERE operation_id=? AND verification_session_id IS NULL
                      """)) {
                update.setBytes(1, session);
                update.setBytes(2, hash("bconnected.verification-session.v1", session));
                update.setLong(3, expires);
                update.setObject(4, stored.id);
                if (update.executeUpdate() != 1) throw new OperationRejectedException();
              }
              requireActive(stored);
              if (expires <= clock.millis()) throw new OperationRejectedException();
            }
          }
          return null;
        });
  }

  /**
   * Internal resumable-coordinator access; callers receive a copy, never the stored mutable array.
   */
  Optional<byte[]> assignedSessionId(AuthenticatedOperation authenticated) {
    return transaction(
        connection -> {
          var stored = lock(connection, authenticated);
          return stored.session == null ? Optional.empty() : Optional.of(stored.session.clone());
        });
  }

  public VerifiedPhone readVerifiedPhone(AuthenticatedOperation authenticated) {
    return transaction(
        connection -> {
          var stored = lock(connection, authenticated);
          if (stored.session == null) throw new OperationRejectedException();
          try (var statement =
              connection.prepareStatement(
                  "SELECT number,expires_ms,verified FROM signal.registration_sessions WHERE id=?"
                      + " FOR SHARE")) {
            statement.setBytes(1, stored.session);
            try (var rows = statement.executeQuery()) {
              long now = clock.millis();
              if (!rows.next()
                  || !rows.getBoolean("verified")
                  || !stored.number.equals(rows.getString("number"))
                  || rows.getLong("expires_ms") <= now
                  || !Objects.equals(stored.sessionExpires, rows.getLong("expires_ms")))
                throw new OperationRejectedException();
              requireActive(stored);
              return new VerifiedPhone(
                  stored.id, stored.number, hex(stored.sessionHash), now, stored.sessionExpires);
            }
          }
        });
  }

  private Stored lock(Connection connection, AuthenticatedOperation authenticated)
      throws SQLException {
    Objects.requireNonNull(authenticated);
    try (var statement =
        connection.prepareStatement(
            "SELECT * FROM signal.registration_operations WHERE operation_id=? FOR UPDATE")) {
      statement.setObject(1, authenticated.row.id);
      try (var rows = statement.executeQuery()) {
        if (!rows.next()) throw new OperationRejectedException();
        var stored = read(rows);
        requireActive(stored);
        if (!stored.member.equals(authenticated.row.member)
            || !equal(stored.attempt, authenticated.row.attempt)
            || !equal(stored.challenge, authenticated.row.challenge)
            || !equal(stored.request, authenticated.row.request)
            || !stored.number.equals(authenticated.row.number)
            || !equal(stored.keys, authenticated.row.keys)
            || !stored.authentication.hash().equals(authenticated.row.authentication.hash())
            || !stored.authentication.salt().equals(authenticated.row.authentication.salt()))
          throw new OperationRejectedException();
        return stored;
      }
    }
  }

  private void requireActive(Stored row) {
    long now = clock.millis();
    if (row.expires <= now || row.created > now + 5000) throw new OperationRejectedException();
  }

  private byte[] requestCommitment(byte[] request, RegistrationAuthentication authentication) {
    byte[] binding = authentication.binding();
    try {
      return unhex(commitment.compute(request, binding));
    } finally {
      Arrays.fill(binding, (byte) 0);
    }
  }

  private static Stored read(ResultSet row) throws SQLException {
    return new Stored(
        row.getObject("operation_id", UUID.class),
        row.getObject("member_id", UUID.class),
        row.getBytes("registration_attempt_hash"),
        row.getBytes("challenge_hash"),
        row.getBytes("device_key_commitment"),
        row.getBytes("server_request_commitment"),
        row.getString("requested_number"),
        RegistrationAuthentication.restore(
            row.getString("authentication_hash"), row.getString("authentication_salt")),
        row.getLong("created_ms"),
        row.getLong("expires_ms"),
        row.getBytes("verification_session_id"),
        row.getBytes("verification_session_hash"),
        row.getObject("verification_session_expires_ms", Long.class));
  }

  private interface SqlTask<T> {
    T run(Connection connection) throws SQLException;
  }

  private <T> T transaction(SqlTask<T> task) {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try {
        T result = task.run(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException failure) {
        connection.rollback();
        throw failure;
      }
    } catch (SQLException ignored) {
      throw new OperationUnavailableException();
    }
  }

  private static void requireUuid(UUID value) {
    if (value == null || value.equals(new UUID(0, 0))) throw new OperationRejectedException();
  }

  private static byte[] decodeNonce(String value) {
    try {
      byte[] decoded = AdmissionPermitVerifier.decode(value, 32);
      if (decoded.length != 32) throw new IllegalArgumentException();
      return decoded;
    } catch (RuntimeException ignored) {
      throw new OperationRejectedException();
    }
  }

  private static byte[] hash(String domain, byte[] value) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      if (domain != null) {
        digest.update(domain.getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) 0);
      }
      return digest.digest(value);
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new AssertionError("SHA-256 unavailable");
    }
  }

  private static boolean equal(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }

  private static String hex(byte[] value) {
    return HexFormat.of().formatHex(value);
  }

  private static byte[] unhex(String value) {
    return HexFormat.of().parseHex(value);
  }
}
