// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.storage.AccountAlreadyExistsException;

/**
 * Source-only first enrollment. No route, scheduler, cache publication, reclaim or messaging
 * authorization is enabled here. All externally useful account capabilities still require gates.
 */
public final class AdmissionAccountCreator {
  private final RegistrationOperations operations;
  private final AdmissionLedger ledger;
  private final AccountsPostgres accounts;
  private final PhoneNumberIdentifiersPostgres numbers;
  private final SignedPreKeysPostgres<org.whispersystems.textsecuregcm.entities.ECSignedPreKey> ec;
  private final SignedPreKeysPostgres<org.whispersystems.textsecuregcm.entities.KEMSignedPreKey>
      kem;
  private final PhoneNumberRecoveryPasswordsManager recovery;
  private final Clock clock;

  /** A local observation only, including when status is ACTIVE. */
  public record Status(UUID operationId, UUID aci, String status, boolean confirmed) {
    public boolean registrationAuthorized() {
      return false;
    }
  }

  public AdmissionAccountCreator(
      DataSource dataSource,
      Clock clock,
      RegistrationOperations operations,
      Duration recoveryRetention) {
    this.operations = Objects.requireNonNull(operations);
    this.clock = Objects.requireNonNull(clock);
    this.ledger = new AdmissionLedger(dataSource, clock);
    this.accounts = new AccountsPostgres(dataSource, clock, Runnable::run);
    this.numbers = new PhoneNumberIdentifiersPostgres(dataSource, Runnable::run);
    this.ec = SignedPreKeysPostgres.ec(dataSource, Runnable::run);
    this.kem = SignedPreKeysPostgres.kem(dataSource, Runnable::run);
    this.recovery =
        new PhoneNumberRecoveryPasswordsManager(
            new PhoneNumberRecoveryPasswordsPostgres(dataSource, recoveryRetention, clock));
  }

  /**
   * Exact committed retries may inspect their original status after the enrollment deadline.
   * Missing operations are never inserted, and deleted accounts are never reconstructed.
   */
  public Optional<Status> findCommittedStatus(AdmissionRegistrationCoordinator.Input input) {
    Objects.requireNonNull(input);
    var operation =
        operations.authenticateCommittedRetry(
            input.memberId(),
            input.attemptNonce(),
            input.bindingChallenge(),
            input.requestedNumber(),
            input.password(),
            input.request(),
            input.signalAgent(),
            input.userAgent());
    return operation.map(value -> existing(value).orElseThrow(AdmissionAccountCreator::rejected));
  }

  public Status createOrResumePending(
      AdmissionRegistrationCoordinator.Input input,
      AdmissionRegistrationCoordinator.AttestedRegistration attested) {
    return createOrResumePending(null, input, attested);
  }

  /** Public enrollment adapters must select an existing operation before any creation effects. */
  public Status createOrResumePending(UUID expectedOperationId,
      AdmissionRegistrationCoordinator.Input input,
      AdmissionRegistrationCoordinator.AttestedRegistration attested) {
    Objects.requireNonNull(input);
    Objects.requireNonNull(attested);
    // The caller's arrays/DTOs must never be read after authenticating a different snapshot.
    try (var snapshot =
        CanonicalRegistrationRequest.beforeVerification(
            input.request(), input.requestedNumber(), input.signalAgent(), input.userAgent())) {
      RegistrationRequest request = snapshot.frozenRequest();
      var committed =
          operations.authenticateCommittedRetry(
              input.memberId(),
              input.attemptNonce(),
              input.bindingChallenge(),
              input.requestedNumber(),
              input.password(),
              request,
              input.signalAgent(),
              input.userAgent());
      var operation = expectedOperationId != null
          ? operations.authenticateExisting(expectedOperationId,
              new AdmissionRegistrationCoordinator.Input(input.memberId(), input.attemptNonce(),
                  input.bindingChallenge(), input.requestedNumber(), input.password(), request,
                  input.signalAgent(), input.userAgent()), true)
          : committed.orElseGet(
              () ->
                  operations.prepareOrAuthenticateRetry(
                      input.memberId(),
                      input.attemptNonce(),
                      input.bindingChallenge(),
                      input.requestedNumber(),
                      input.password(),
                      request,
                      input.signalAgent(),
                      input.userAgent()));
      requireAttestation(operation, attested);
      var existing = existing(operation);
      if (existing.isPresent()) return existing.get();
      var permit = attested.permit();
      if (permit.expiresAt() <= clock.instant().getEpochSecond()) throw rejected();

      // Permanent phone-identity resolution may survive a failed enrollment; it is never
      // reassigned.
      UUID pni = numbers.getPhoneNumberIdentifier(operation.requestedNumber()).join();
      var account = account(request, input, operation, pni);
      var activation = request.deviceActivationRequest();
      var guard =
          operations.accountCreationGuard(operation, permit, account.getAccountIdentifier());
      var mutations = new ArrayList<AccountMutation>();
      mutations.add(guard);
      mutations.add(
          ec.buildInsertion(
              account.getAccountIdentifier(), Device.PRIMARY_ID, activation.aciSignedPreKey()));
      mutations.add(
          kem.buildInsertion(
              account.getAccountIdentifier(),
              Device.PRIMARY_ID,
              activation.aciPqLastResortPreKey()));
      mutations.add(
          ec.buildInsertion(pni, Device.PRIMARY_ID, activation.pniSignedPreKey().orElseThrow()));
      mutations.add(
          kem.buildInsertion(
              pni, Device.PRIMARY_ID, activation.pniPqLastResortPreKey().orElseThrow()));
      request
          .accountAttributes()
          .recoveryPassword()
          .ifPresent(
              password ->
                  mutations.add(recovery.buildTransactWriteItemForStorePassword(pni, password)));
      mutations.add(ledger.pendingMutation(permit, account));
      mutations.add(guard); // Recheck deadlines after all potentially blocking writes.
      try {
        accounts.createFreshWithMutations(account, mutations);
      } catch (AccountAlreadyExistsException conflict) {
        // Never invoke AccountsManager's legacy reclaim path. A different owner's collision fails.
        return existing(operation).orElseThrow(AdmissionAccountCreator::rejected);
      }
      return existing(operation).orElseThrow(AdmissionAccountCreator::rejected);
    }
  }

  private Account account(
      RegistrationRequest request,
      AdmissionRegistrationCoordinator.Input input,
      RegistrationOperations.AuthenticatedOperation operation,
      UUID pni) {
    var attributes = request.accountAttributes();
    var activation = request.deviceActivationRequest();
    var spec =
        new DeviceSpec(
            attributes.getName(),
            input.password(),
            input.signalAgent(),
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
    var device = spec.toDevice(Device.PRIMARY_ID, clock, request.aciIdentityKey());
    operation.applyAuthenticationTo(device); // Preserve the exact verifier bound before SMS.
    var account = new Account();
    account.setAccountIdentifier(UUID.randomUUID());
    account.setNumber(operation.requestedNumber(), pni);
    account.setIdentityKey(request.aciIdentityKey());
    account.setPhoneNumberIdentityKey(request.pniIdentityKey());
    account.setRegistrationLockFromAttributes(attributes);
    account.setUnidentifiedAccessKey(attributes.getUnidentifiedAccessKey());
    account.setUnrestrictedUnidentifiedAccess(attributes.isUnrestrictedUnidentifiedAccess());
    account.setDiscoverableByPhoneNumber(attributes.isDiscoverableByPhoneNumber());
    attributes.recoveryPassword().ifPresent(account::setAccountRecoveryPassword);
    account.addDevice(device);
    return account;
  }

  private Optional<Status> existing(RegistrationOperations.AuthenticatedOperation operation) {
    final Optional<AdmissionLedger.AdmissionRecord> found;
    try {
      found = ledger.findByOperation(operation.operationId());
    } catch (SQLException failure) {
      throw new IllegalStateException("Admission status unavailable");
    }
    if (found.isEmpty()) return Optional.empty();
    var record = found.get();
    if (!record.memberId().equals(operation.memberId())
        || !record.registrationAttemptHash().equals(operation.registrationAttemptHash())
        || !record.deviceKeyCommitment().equals(operation.deviceKeyCommitment())
        || !record.serverRequestCommitment().equals(operation.serverRequestCommitment()))
      throw rejected();
    var account =
        accounts
            .getByAccountIdentifier(record.aci())
            .orElseThrow(AdmissionAccountCreator::rejected);
    if (!account.getNumber().filter(operation.requestedNumber()::equals).isPresent())
      throw rejected();
    var expected = new Device();
    operation.applyAuthenticationTo(expected);
    var current =
        account
            .getDevice(Device.PRIMARY_ID)
            .orElseThrow(AdmissionAccountCreator::rejected)
            .getAuthTokenHash();
    if (!current.equals(expected.getAuthTokenHash())) throw rejected();
    return Optional.of(
        new Status(operation.operationId(), record.aci(), record.status(), record.confirmed()));
  }

  private static void requireAttestation(
      RegistrationOperations.AuthenticatedOperation operation,
      AdmissionRegistrationCoordinator.AttestedRegistration attested) {
    var b = attested.permit().binding();
    if (!operation.operationId().equals(attested.operation().operationId())
        || !operation.operationId().equals(b.signalOperationId())
        || !operation.memberId().equals(b.memberId())
        || !operation.requestedNumber().equals(b.canonicalVerifiedNumber())
        || !operation.registrationAttemptHash().equals(b.registrationAttemptHash())
        || !operation.deviceKeyCommitment().equals(b.deviceKeyCommitment())
        || !operation.serverRequestCommitment().equals(b.serverRequestCommitment()))
      throw rejected();
  }

  public static final class EnrollmentRejectedException extends IllegalStateException {
    private EnrollmentRejectedException() { super("Enrollment is unavailable or binding changed"); }
  }

  private static EnrollmentRejectedException rejected() {
    return new EnrollmentRejectedException();
  }
}
