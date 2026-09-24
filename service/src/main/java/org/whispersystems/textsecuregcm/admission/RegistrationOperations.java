// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
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
    public enum Reason { UNAVAILABLE, INVALID_CREDENTIALS, CONFLICT, EXPIRED }
    private final Reason reason;
    private OperationRejectedException() {
      this(Reason.UNAVAILABLE);
    }
    private OperationRejectedException(Reason reason) {
      super("Registration operation unavailable or inputs changed");
      this.reason = reason;
    }
    public Reason reason() { return reason; }
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

    // Future account construction must use this original verifier, rather than generating
    // another
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
    decodeNonce(bindingChallenge); // Validate canonical encoding; community hashes the encoded
    // challenge
    // text.
    byte[] challenge = hash(null, bindingChallenge.getBytes(StandardCharsets.US_ASCII));
    try (var canonical =
        CanonicalRegistrationRequest.beforeVerification(
            request, requestedNumber, signalAgent, userAgent)) {
      byte[] encoded = canonical.bytes();
      try {
        return transaction(
            connection -> {
              // A known operation can authenticate an exact retry after its own
              // account commit.
              // A new operation for any pre-existing account is a recovery flow and
              // is closed here.
              try (var existing =
                  connection.prepareStatement(
                      "SELECT 1 FROM signal.registration_operations WHERE"
                          + " member_id=? AND registration_attempt_hash=?")) {
                existing.setObject(1, memberId);
                existing.setBytes(2, attempt);
                try (var rows = existing.executeQuery()) {
                  if (!rows.next()) {
                    try (var account =
                        connection.prepareStatement(
                            "SELECT 1 FROM signal.accounts WHERE number" + " = ANY(?)")) {
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
              // New salts are never substituted on retry. Only the inserted winner's
              // verifier is
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
                      "SELECT * FROM signal.registration_operations WHERE"
                          + " member_id=? AND registration_attempt_hash=? FOR"
                          + " UPDATE")) {
                statement.setObject(1, memberId);
                statement.setBytes(2, attempt);
                try (var rows = statement.executeQuery()) {
                  if (!rows.next()) throw new OperationRejectedException();
                  stored = read(rows);
                }
              }
              if (!stored.authentication.verify(password))
                throw new OperationRejectedException(OperationRejectedException.Reason.INVALID_CREDENTIALS);
              if (!equal(stored.challenge, challenge)
                  || !stored.number.equals(canonical.number())
                  || !equal(stored.keys, unhex(canonical.keyCommitment()))
                  || !equal(stored.request, requestCommitment(encoded, stored.authentication)))
                throw new OperationRejectedException(OperationRejectedException.Reason.CONFLICT);
              requireActive(stored);
              return new AuthenticatedOperation(stored);
            });
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
    }
  }

  /** Existing-only public-operation boundary. No INSERT, claim, provider call or account write. */
  public AuthenticatedOperation authenticateExisting(UUID expectedId,
      AdmissionRegistrationCoordinator.Input input, boolean allowExpiredCommitted) {
    Objects.requireNonNull(input);
    requireUuid(input.memberId());
    if (expectedId != null) requireUuid(expectedId);
    byte[] attempt = hash("bconnected.registration-attempt.v1", decodeNonce(input.attemptNonce()));
    decodeNonce(input.bindingChallenge());
    byte[] challenge = hash(null, input.bindingChallenge().getBytes(StandardCharsets.US_ASCII));
    try (var canonical = CanonicalRegistrationRequest.beforeVerification(input.request(), input.requestedNumber(),
        input.signalAgent(), input.userAgent())) {
      byte[] encoded = canonical.bytes();
      try {
        return transaction(connection -> {
          try (var query = connection.prepareStatement("""
              SELECT r.* FROM signal.registration_operations r WHERE member_id=? AND registration_attempt_hash=?
              """)) {
            query.setObject(1, input.memberId());
            query.setBytes(2, attempt);
            try (var rows = query.executeQuery()) {
              if (!rows.next()) throw new OperationRejectedException();
              Stored stored = read(rows);
              if (expectedId != null && !stored.id.equals(expectedId)) throw new OperationRejectedException();
              if (!stored.authentication.verify(input.password()))
                throw new OperationRejectedException(OperationRejectedException.Reason.INVALID_CREDENTIALS);
              if (!equal(stored.challenge, challenge) || !stored.number.equals(canonical.number())
                  || !equal(stored.keys, unhex(canonical.keyCommitment()))
                  || !equal(stored.request, requestCommitment(encoded, stored.authentication)))
                throw new OperationRejectedException(OperationRejectedException.Reason.CONFLICT);
              boolean committed = false;
              if (allowExpiredCommitted) {
                try (var admission = connection.prepareStatement(
                    "SELECT 1 FROM signal.admissions WHERE signal_operation_id=?")) {
                  admission.setObject(1, stored.id);
                  try (var found = admission.executeQuery()) { committed = found.next(); }
                }
              }
              if (!committed) requireActive(stored);
              return new AuthenticatedOperation(stored);
            }
          }
        });
      } finally { Arrays.fill(encoded, (byte) 0); }
    }
  }

  /** Read-only native association validation; countdown is capped by both immutable deadlines. */
  public long remainingSessionSeconds(AuthenticatedOperation operation) {
    return transaction(connection -> {
      Stored stored = lock(connection, operation);
      requireSession(connection, stored, false);
      long deadline = Math.min(stored.expires, stored.sessionExpires);
      try (var query = connection.prepareStatement(
          "SELECT claim_expires_ms FROM signal.registration_operations WHERE operation_id=?")) {
        query.setObject(1, stored.id);
        try (var row = query.executeQuery()) {
          if (!row.next() || row.getObject(1) == null) throw new OperationRejectedException();
          deadline = Math.min(deadline, row.getLong(1));
        }
      }
      long remaining = deadline - clock.millis();
      if (remaining <= 0) throw new OperationRejectedException(OperationRejectedException.Reason.EXPIRED);
      return (remaining + 999) / 1000;
    });
  }

  @FunctionalInterface
  interface NativeSessionCreator {
    org.whispersystems.textsecuregcm.entities.RegistrationServiceSession create(
        Connection connection)
        throws SQLException,
            org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
  }

  /**
   * Read-only authentication of an already committed operation, including after expiry. It never
   * creates/refreshes a row and grants no account or messaging authorization.
   */
  Optional<AuthenticatedOperation> authenticateCommittedRetry(
      UUID memberId,
      String attemptNonce,
      String bindingChallenge,
      String number,
      String password,
      RegistrationRequest request,
      String signalAgent,
      String userAgent) {
    requireUuid(memberId);
    byte[] attempt = hash("bconnected.registration-attempt.v1", decodeNonce(attemptNonce));
    decodeNonce(bindingChallenge);
    byte[] challenge = hash(null, bindingChallenge.getBytes(StandardCharsets.US_ASCII));
    try (var canonical =
        CanonicalRegistrationRequest.beforeVerification(request, number, signalAgent, userAgent)) {
      byte[] encoded = canonical.bytes();
      try {
        return transaction(
            connection -> {
              try (var query =
                  connection.prepareStatement(
                      """
                      SELECT r.* FROM signal.registration_operations r
                      JOIN signal.admissions a ON a.signal_operation_id=r.operation_id
                      WHERE r.member_id=? AND r.registration_attempt_hash=?
                      """)) {
                query.setObject(1, memberId);
                query.setBytes(2, attempt);
                try (var rows = query.executeQuery()) {
                  if (!rows.next()) return Optional.empty();
                  var stored = read(rows);
                  if (!stored.authentication.verify(password))
                    throw new OperationRejectedException(OperationRejectedException.Reason.INVALID_CREDENTIALS);
                  if (!equal(stored.challenge, challenge)
                      || !stored.number.equals(canonical.number())
                      || !equal(stored.keys, unhex(canonical.keyCommitment()))
                      || !equal(stored.request, requestCommitment(encoded, stored.authentication)))
                    throw new OperationRejectedException(OperationRejectedException.Reason.CONFLICT);
                  return Optional.of(new AuthenticatedOperation(stored));
                }
              }
            });
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
    }
  }

  /** One SQL transaction for claim binding, native quota/session creation and association. */
  byte[] getOrCreateClaimedSession(
      AuthenticatedOperation operation,
      AdmissionServiceClient.FreshClaim claim,
      NativeSessionCreator creator)
      throws org.whispersystems.textsecuregcm.controllers.RateLimitExceededException {
    try {
      return transaction(
          connection -> {
            Stored stored = lock(connection, operation);
            requireClaim(connection, stored, operation, claim, true);
            if (stored.session != null) return requireSession(connection, stored, false);
            final org.whispersystems.textsecuregcm.entities.RegistrationServiceSession created;
            try {
              created = creator.create(connection);
            } catch (org.whispersystems.textsecuregcm.controllers.RateLimitExceededException e) {
              throw new CreationLimited(e);
            }
            claim.requireOperation(operation);
            requireActive(stored);
            if (created == null
                || created.id() == null
                || created.id().length != 32
                || created.verified()
                || !stored.number.equals(created.number())) throw new OperationRejectedException();
            byte[] id = created.id().clone();
            long expires;
            try (var query =
                connection.prepareStatement(
                    "SELECT number,expires_ms,verified FROM"
                        + " signal.registration_sessions WHERE id=? FOR"
                        + " SHARE")) {
              query.setBytes(1, id);
              try (var row = query.executeQuery()) {
                if (!row.next()
                    || row.getBoolean("verified")
                    || !stored.number.equals(row.getString("number"))
                    || row.getLong("expires_ms") <= clock.millis())
                  throw new OperationRejectedException();
                expires = row.getLong("expires_ms");
              }
            }
            claim.requireOperation(operation);
            requireActive(stored);
            try (var update =
                connection.prepareStatement(
                    """
                    UPDATE signal.registration_operations SET verification_session_id=?,verification_session_hash=?,verification_session_expires_ms=?
                    WHERE operation_id=? AND verification_session_id IS NULL
                    """)) {
              update.setBytes(1, id);
              update.setBytes(2, hash("bconnected.verification-session.v1", id));
              update.setLong(3, expires);
              update.setObject(4, stored.id);
              if (update.executeUpdate() != 1) throw new OperationRejectedException();
            }
            claim.requireOperation(operation);
            requireActive(stored);
            return id;
          });
    } catch (CreationLimited e) {
      throw e.limited;
    }
  }

  byte[] requireClaimedSession(
      AuthenticatedOperation operation, AdmissionServiceClient.FreshClaim claim) {
    return transaction(
        connection -> {
          Stored stored = lock(connection, operation);
          requireClaim(connection, stored, operation, claim, false);
          byte[] id = requireSession(connection, stored, false);
          claim.requireOperation(operation);
          requireActive(stored);
          return id;
        });
  }

  /** Consume a verified signup receipt for exactly one approved native registration operation. */
  void attachSignupProof(AuthenticatedOperation operation, AdmissionServiceClient.FreshClaim claim) {
    if (claim.signupProofId() == null || claim.communitySessionHash() == null)
      throw new OperationRejectedException();
    transaction(connection -> {
      Stored stored = lock(connection, operation);
      requireClaim(connection, stored, operation, claim, true);
      UUID existing = signupProofId(connection, stored.id);
      if (stored.session != null) {
        if (!claim.signupProofId().equals(existing)) throw new OperationRejectedException();
        requireSession(connection, stored, true);
        return null;
      }
      try (var query = connection.prepareStatement(
          "SELECT * FROM signal.phone_signup_operations WHERE operation_id=? FOR UPDATE")) {
        query.setObject(1, claim.signupProofId());
        try (var row = query.executeQuery()) {
          long now = clock.millis();
          if (!row.next() || row.getObject("retired_ms") != null || !row.getBoolean("community_confirmed")
              || row.getObject("verified_at_ms") == null || row.getLong("verified_at_ms") > now + 5000
              || row.getLong("proof_expires_ms") <= now
              || row.getLong("proof_expires_ms") - row.getLong("verified_at_ms") > Duration.ofDays(30).toMillis()
              || !stored.number.equals(row.getString("requested_number"))
              || !equal(unhex(claim.communitySessionHash()), unhex(row.getString("nonce_hash"))))
            throw new OperationRejectedException();
          UUID consumed = row.getObject("consumed_registration_operation_id", UUID.class);
          UUID member = row.getObject("consumed_member_id", UUID.class);
          if (consumed != null && (!consumed.equals(stored.id) || !stored.member.equals(member)))
            throw new OperationRejectedException();
          if (consumed == null) {
            try (var consume = connection.prepareStatement("""
                UPDATE signal.phone_signup_operations SET consumed_registration_operation_id=?,consumed_member_id=?
                WHERE operation_id=? AND consumed_registration_operation_id IS NULL
                """)) {
              consume.setObject(1, stored.id); consume.setObject(2, stored.member);
              consume.setObject(3, claim.signupProofId());
              if (consume.executeUpdate() != 1) throw new OperationRejectedException();
            }
          }
          try (var attach = connection.prepareStatement("""
              UPDATE signal.registration_operations SET phone_signup_proof_id=?,verification_session_id=?,
                verification_session_hash=?,verification_session_expires_ms=?
              WHERE operation_id=? AND verification_session_id IS NULL
              """)) {
            attach.setObject(1, claim.signupProofId()); attach.setBytes(2, row.getBytes("native_session_id"));
            attach.setBytes(3, signupProofHash(claim.signupProofId()));
            attach.setLong(4, row.getLong("proof_expires_ms")); attach.setObject(5, stored.id);
            if (attach.executeUpdate() != 1) throw new OperationRejectedException();
          }
          claim.requireOperation(operation);
          requireActive(stored);
        }
      }
      return null;
    });
  }

  boolean hasSignupProof(AuthenticatedOperation operation) {
    return transaction(connection -> {
      Stored stored = lock(connection, operation);
      if (signupProofId(connection, stored.id) == null) return false;
      requireSession(connection, stored, true);
      return true;
    });
  }

  private static byte[] signupProofHash(UUID id) {
    return hash("bconnected.signup-phone-proof.v1", id.toString().getBytes(StandardCharsets.US_ASCII));
  }

  private UUID signupProofId(Connection connection, UUID operationId) throws SQLException {
    try (var query = connection.prepareStatement(
        "SELECT phone_signup_proof_id FROM signal.registration_operations WHERE operation_id=?")) {
      query.setObject(1, operationId);
      try (var row = query.executeQuery()) {
        if (!row.next()) throw new OperationRejectedException();
        return row.getObject(1, UUID.class);
      }
    }
  }

  private void requireSignupProof(Connection connection, Stored stored, UUID proofId) throws SQLException {
    try (var query = connection.prepareStatement(
        "SELECT * FROM signal.phone_signup_operations WHERE operation_id=? FOR SHARE")) {
      query.setObject(1, proofId);
      try (var row = query.executeQuery()) {
        long now = clock.millis();
        if (!row.next() || row.getObject("retired_ms") != null || !row.getBoolean("community_confirmed") || row.getObject("verified_at_ms") == null
            || row.getLong("verified_at_ms") > now + 5000 || row.getLong("proof_expires_ms") <= now
            || !stored.id.equals(row.getObject("consumed_registration_operation_id", UUID.class))
            || !stored.member.equals(row.getObject("consumed_member_id", UUID.class))
            || !stored.number.equals(row.getString("requested_number"))
            || !equal(stored.session, row.getBytes("native_session_id"))
            || !equal(stored.sessionHash, signupProofHash(proofId))
            || !Objects.equals(stored.sessionExpires, row.getLong("proof_expires_ms")))
          throw new OperationRejectedException();
      }
    }
  }

  private void requireClaim(
      Connection connection,
      Stored stored,
      AuthenticatedOperation operation,
      AdmissionServiceClient.FreshClaim claim,
      boolean allowNew)
      throws SQLException {
    claim.requireOperation(operation);
    requireActive(stored);
    UUID proof = signupProofId(connection, stored.id);
    if (proof != null && !proof.equals(claim.signupProofId())) throw new OperationRejectedException();
    if (claim.expiresAtMillis() > stored.expires || claim.expiresAtMillis() <= clock.millis())
      throw new OperationRejectedException();
    try (var query =
        connection.prepareStatement(
            "SELECT claim_approval_epoch,claim_expires_ms FROM"
                + " signal.registration_operations WHERE operation_id=?")) {
      query.setObject(1, stored.id);
      try (var row = query.executeQuery()) {
        if (!row.next()) throw new OperationRejectedException();
        Long epoch = row.getObject(1, Long.class), expires = row.getObject(2, Long.class);
        if (epoch == null) {
          if (!allowNew || stored.session != null) throw new OperationRejectedException();
          try (var update =
              connection.prepareStatement(
                  "UPDATE signal.registration_operations SET"
                      + " claim_approval_epoch=?,claim_expires_ms=? WHERE"
                      + " operation_id=?")) {
            update.setLong(1, claim.approvalEpoch());
            update.setLong(2, claim.expiresAtMillis());
            update.setObject(3, stored.id);
            update.executeUpdate();
          }
        } else if (epoch != claim.approvalEpoch()
            || expires == null
            || expires != claim.expiresAtMillis()) {
          throw new OperationRejectedException();
        }
      }
    }
    claim.requireOperation(operation);
  }

  private byte[] requireSession(Connection connection, Stored stored, boolean requireVerified)
      throws SQLException {
    if (stored.session == null) throw new OperationRejectedException();
    UUID proof = signupProofId(connection, stored.id);
    if (proof != null) {
      requireSignupProof(connection, stored, proof);
      requireActive(stored);
      return stored.session.clone();
    }
    try (var query =
        connection.prepareStatement(
            "SELECT number,expires_ms,verified FROM signal.registration_sessions WHERE"
                + " id=? FOR SHARE")) {
      query.setBytes(1, stored.session);
      try (var row = query.executeQuery()) {
        if (!row.next()
            || !stored.number.equals(row.getString("number"))
            || !Objects.equals(stored.sessionExpires, row.getLong("expires_ms"))
            || (requireVerified && !row.getBoolean("verified")))
          throw new OperationRejectedException();
        if (row.getLong("expires_ms") <= clock.millis())
          throw new OperationRejectedException(OperationRejectedException.Reason.EXPIRED);
      }
    }
    requireActive(stored);
    return stored.session.clone();
  }

  private static final class CreationLimited extends RuntimeException {
    final org.whispersystems.textsecuregcm.controllers.RateLimitExceededException limited;

    CreationLimited(
        org.whispersystems.textsecuregcm.controllers.RateLimitExceededException limited) {
      super("Registration quota exhausted", null, false, false);
      this.limited = limited;
    }
  }

  /**
   * Legacy package-private storage boundary retained for association tests. The admission
   * coordinator uses getOrCreateClaimedSession so native creation and claim/session binding are
   * atomic. Never expose this method through a client-selected session identifier.
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
                  "SELECT number,expires_ms,verified FROM"
                      + " signal.registration_sessions WHERE id=? FOR SHARE")) {
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
              // A newly associated session must still be unverified; verified
              // sessions cannot be
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
          UUID proof = signupProofId(connection, stored.id);
          if (proof != null) {
            requireSignupProof(connection, stored, proof);
            requireActive(stored);
            return new VerifiedPhone(stored.id, stored.number, hex(stored.sessionHash), clock.millis(), stored.sessionExpires);
          }
          try (var statement =
              connection.prepareStatement(
                  "SELECT number,expires_ms,verified FROM"
                      + " signal.registration_sessions WHERE id=? FOR SHARE")) {
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
            "SELECT * FROM signal.registration_operations WHERE operation_id=? FOR" + " UPDATE")) {
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

  /** Last-moment guard on the account transaction; never a standalone redemption. */
  org.whispersystems.textsecuregcm.storage.AccountMutation.Sql accountCreationGuard(
      AuthenticatedOperation operation,
      AdmissionPermitVerifier.VerifiedPermit permit,
      UUID accountId) {
    return new org.whispersystems.textsecuregcm.storage.AccountMutation.Sql(
        connection -> {
          if (connection.getAutoCommit())
            throw new IllegalStateException("Account transaction required");
          Stored stored = lock(connection, operation);
          requireSession(connection, stored, true);
          var binding = permit.binding();
          // Account INSERT has already serialized competing current owners of this phone/PNI.
          // A spent historical admission also excludes fresh enrollment after account deletion.
          try (var previous =
              connection.prepareStatement(
                  """
                  SELECT a.signal_operation_id FROM signal.admissions a
                  LEFT JOIN signal.registration_operations r ON r.operation_id=a.signal_operation_id
                  LEFT JOIN signal.phone_number_identifiers pn ON pn.e164=r.requested_number
                  WHERE a.phone_binding=? OR pn.pni=(SELECT pni FROM signal.accounts WHERE aci=?)
                  """)) {
            previous.setBytes(1, unhex(binding.phoneBinding()));
            previous.setObject(2, Objects.requireNonNull(accountId));
            try (var rows = previous.executeQuery()) {
              while (rows.next())
                if (!stored.id.equals(rows.getObject(1, UUID.class)))
                  throw new OperationRejectedException();
            }
          }
          if (!stored.id.equals(binding.signalOperationId())
              || !stored.member.equals(binding.memberId())
              || !stored.number.equals(binding.canonicalVerifiedNumber())
              || !hex(stored.attempt).equals(binding.registrationAttemptHash())
              || !hex(stored.keys).equals(binding.deviceKeyCommitment())
              || !hex(stored.request).equals(binding.serverRequestCommitment())
              || !hex(stored.sessionHash).equals(binding.serverVerificationSessionHash()))
            throw new OperationRejectedException();
          try (var query =
              connection.prepareStatement(
                  "SELECT claim_approval_epoch,claim_expires_ms FROM signal.registration_operations"
                      + " WHERE operation_id=?")) {
            query.setObject(1, stored.id);
            try (var row = query.executeQuery()) {
              if (!row.next()
                  || row.getObject(1) == null
                  || row.getObject(2) == null
                  || row.getLong(1) != binding.approvalEpoch()
                  || row.getLong(2) <= clock.millis()) throw new OperationRejectedException();
            }
          }
          requireActive(stored);
          long now = clock.instant().getEpochSecond();
          if (permit.expiresAt() <= now || permit.issuedAt() > now + 5)
            throw new OperationRejectedException();
        });
  }

  private void requireActive(Stored row) {
    long now = clock.millis();
    if (row.expires <= now) throw new OperationRejectedException(OperationRejectedException.Reason.EXPIRED);
    if (row.created > now + 5000) throw new OperationRejectedException();
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
