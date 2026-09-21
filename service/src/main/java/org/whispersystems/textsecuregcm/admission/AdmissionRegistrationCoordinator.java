// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.VerificationSessionRateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.ClientType;
import org.whispersystems.textsecuregcm.registration.MessageTransport;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceException;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceSenderException;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;

/**
 * Source-only enrollment orchestration through verified phone attestation. No public route, account
 * creation, activation or authentication capability is supplied by this class.
 */
public final class AdmissionRegistrationCoordinator {
  private final RegistrationOperations operations;
  private final AdmissionServiceClient admission;
  private final TelnyxRegistrationService registration;
  private final AdmissionPermitVerifier verifier;
  private final byte[] phoneKey;

  /**
   * Transient request input; every operation revalidates the complete original request/password.
   */
  public record Input(
      UUID memberId,
      String attemptNonce,
      String bindingChallenge,
      String requestedNumber,
      String password,
      RegistrationRequest request,
      String signalAgent,
      String userAgent) {
    @Override
    public String toString() {
      return "RegistrationInput[redacted]";
    }
  }

  /** Deliberately excludes the raw authoritative session identifier and phone number. */
  public record SessionStatus(
      UUID operationId,
      boolean verified,
      Long nextSmsSeconds,
      Long nextCheckSeconds,
      long expiresInSeconds) {
    @Override
    public String toString() {
      return "RegistrationSessionStatus[redacted]";
    }
  }

  /**
   * Only an attested operation; the caller still needs atomic PENDING creation and confirmation.
   */
  public static final class AttestedRegistration {
    private final RegistrationOperations.AuthenticatedOperation operation;
    private final AdmissionPermitVerifier.VerifiedPermit permit;

    private AttestedRegistration(
        RegistrationOperations.AuthenticatedOperation operation,
        AdmissionPermitVerifier.VerifiedPermit permit) {
      this.operation = operation;
      this.permit = permit;
    }

    public RegistrationOperations.AuthenticatedOperation operation() {
      return operation;
    }

    public AdmissionPermitVerifier.VerifiedPermit permit() {
      return permit;
    }

    @Override
    public String toString() {
      return "AttestedRegistration[redacted]";
    }
  }

  public AdmissionRegistrationCoordinator(
      RegistrationOperations operations,
      AdmissionServiceClient admission,
      TelnyxRegistrationService registration,
      AdmissionPermitVerifier verifier,
      byte[] phoneKey) {
    this.operations = Objects.requireNonNull(operations);
    this.admission = Objects.requireNonNull(admission);
    this.registration = Objects.requireNonNull(registration);
    this.verifier = Objects.requireNonNull(verifier);
    if (phoneKey == null || phoneKey.length < 32)
      throw new IllegalArgumentException("Owned phone binding key required");
    this.phoneKey = phoneKey.clone();
  }

  /** The source address must be obtained from the server's trusted forwarding policy, not JSON. */
  public SessionStatus begin(Input input, String trustedSourceAddress, Duration timeout)
      throws RateLimitExceededException {
    timeout(timeout);
    if (trustedSourceAddress == null || trustedSourceAddress.isBlank())
      throw new IllegalArgumentException("Trusted source address required");
    var operation = authenticate(input);
    var claim = admission.claim(operation, input.bindingChallenge());
    final com.google.i18n.phonenumbers.Phonenumber.PhoneNumber number;
    try {
      number = PhoneNumberUtil.getInstance().parse(operation.requestedNumber(), null);
    } catch (com.google.i18n.phonenumbers.NumberParseException ignored) {
      throw new IllegalArgumentException("Invalid registration destination");
    }
    byte[] session =
        operations.getOrCreateClaimedSession(
            operation,
            claim,
            connection ->
                registration.createRegistrationSessionInTransaction(
                    connection, number, trustedSourceAddress, timeout, claim::requireFresh));
    claim.requireFresh();
    return status(
        operation,
        registration
            .getSession(session, timeout)
            .orElseThrow(() -> new IllegalStateException("Registration session unavailable")));
  }

  public SessionStatus sendCode(Input input, String acceptLanguage, Duration timeout)
      throws VerificationSessionRateLimitExceededException,
          RegistrationServiceException,
          RegistrationServiceSenderException {
    return sendCode(null, input, acceptLanguage, timeout);
  }

  public SessionStatus sendCode(UUID expectedOperationId, Input input, String acceptLanguage, Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException,
          RegistrationServiceSenderException {
    timeout(timeout);
    var operation = operations.authenticateExisting(expectedOperationId, input, false);
    var claim = admission.claim(operation, input.bindingChallenge());
    byte[] session = operations.requireClaimedSession(operation, claim);
    return status(
        operation,
        registration.sendVerificationCode(
            session,
            MessageTransport.SMS,
            ClientType.IOS,
            acceptLanguage,
            null,
            timeout,
            claim::requireFresh));
  }

  public SessionStatus checkCode(Input input, String code, Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException {
    return checkCode(null, input, code, timeout);
  }

  public SessionStatus checkCode(UUID expectedOperationId, Input input, String code, Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException {
    timeout(timeout);
    if (code == null || !code.matches("[0-9]{4,10}"))
      throw new IllegalArgumentException("Invalid verification code format");
    var operation = operations.authenticateExisting(expectedOperationId, input, false);
    var claim = admission.claim(operation, input.bindingChallenge());
    byte[] session = operations.requireClaimedSession(operation, claim);
    return status(
        operation, registration.checkVerificationCode(session, code, timeout, claim::requireFresh));
  }

  /**
   * Reads authoritative native verification state; client or provider receipt claims never suffice.
   */
  public AttestedRegistration attestVerifiedPhone(Input input) {
    return attestVerifiedPhone(null, input);
  }

  public AttestedRegistration attestVerifiedPhone(UUID expectedOperationId, Input input) {
    var operation = operations.authenticateExisting(expectedOperationId, input, false);
    var claim = admission.claim(operation, input.bindingChallenge());
    operations.requireClaimedSession(operation, claim);
    var phone = operations.readVerifiedPhone(operation);
    claim.requireFresh();
    var permit =
        admission.attest(operation, claim, phone, phoneBinding(phone.canonicalNumber()), verifier);
    return new AttestedRegistration(operation, permit);
  }

  /** Pure status read: no claim renewal, session creation, provider request, or account mutation. */
  public SessionStatus status(UUID expectedOperationId, Input input, Duration timeout) {
    timeout(timeout);
    var operation = operations.authenticateExisting(expectedOperationId, input, false);
    byte[] session = operations.assignedSessionId(operation)
        .orElseThrow(() -> new IllegalStateException("Registration session unavailable"));
    return status(operation, registration.getSession(session, timeout)
        .orElseThrow(() -> new IllegalStateException("Registration session unavailable")));
  }

  private RegistrationOperations.AuthenticatedOperation authenticate(Input input) {
    Objects.requireNonNull(input);
    return operations.prepareOrAuthenticateRetry(
        input.memberId(),
        input.attemptNonce(),
        input.bindingChallenge(),
        input.requestedNumber(),
        input.password(),
        input.request(),
        input.signalAgent(),
        input.userAgent());
  }

  private SessionStatus status(
      RegistrationOperations.AuthenticatedOperation operation, RegistrationServiceSession session) {
    if (!operation.requestedNumber().equals(session.number()))
      throw new IllegalStateException("Invalid registration session binding");
    return new SessionStatus(
        operation.operationId(),
        session.verified(),
        session.nextSms(),
        session.nextVerificationAttempt(),
        Math.min(session.expiration(), operations.remainingSessionSeconds(operation)));
  }

  private String phoneBinding(String number) {
    try {
      var mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(phoneKey, "HmacSHA256"));
      mac.update("bconnected.phone.v1\0".getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(mac.doFinal(number.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException impossible) {
      throw new IllegalStateException("Phone binding unavailable");
    }
  }

  private static void timeout(Duration timeout) {
    if (timeout == null
        || timeout.isNegative()
        || timeout.isZero()
        || timeout.compareTo(Duration.ofSeconds(60)) > 0)
      throw new IllegalArgumentException("Invalid registration timeout");
  }

  @Override
  public String toString() {
    return "AdmissionRegistrationCoordinator[redacted]";
  }
}
