// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionAccountCreator;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionRegistrationCoordinator;
import org.whispersystems.textsecuregcm.admission.RegistrationOperations;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.storage.Device;

/** Public contract adapter only. No route registration, confirmation scheduling or provider retry. */
public final class MobileEnrollmentService {
  private final RegistrationOperations operations;
  private final AdmissionRegistrationCoordinator coordinator;
  private final AdmissionAccountCreator creator;
  private final AdmissionEntitlementGate gate;
  private final Duration timeout;
  private final java.util.Set<UUID> allowedMembers;

  public MobileEnrollmentService(RegistrationOperations operations, AdmissionRegistrationCoordinator coordinator,
      AdmissionAccountCreator creator, AdmissionEntitlementGate gate, Duration timeout) {
    this(operations, coordinator, creator, gate, timeout, null);
  }

  /** A bounded alpha cohort is additional to current approved-alumni authorization. */
  public MobileEnrollmentService(RegistrationOperations operations, AdmissionRegistrationCoordinator coordinator,
      AdmissionAccountCreator creator, AdmissionEntitlementGate gate, Duration timeout,
      java.util.Set<UUID> allowedMembers) {
    this.operations = Objects.requireNonNull(operations);
    this.coordinator = Objects.requireNonNull(coordinator);
    this.creator = Objects.requireNonNull(creator);
    this.gate = Objects.requireNonNull(gate);
    if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(60)) > 0)
      throw new IllegalArgumentException("Bounded registration timeout required");
    this.timeout = timeout;
    this.allowedMembers = allowedMembers == null ? null : java.util.Set.copyOf(allowedMembers);
  }

  public Result execute(MobileEnrollmentParser.Operation action, UUID operationId,
      AdmissionRegistrationCoordinator.Input input, String code, String trustedSourceAddress,
      String acceptLanguage) {
    try {
      if (action == null || input == null) return error(Code.INVALID_REQUEST);
      if (allowedMembers != null && !allowedMembers.contains(input.memberId()))
        return error(Code.ENROLLMENT_UNAVAILABLE);
      if (action == MobileEnrollmentParser.Operation.BEGIN) {
        if (operationId != null) return error(Code.INVALID_REQUEST);
        return verification(coordinator.begin(input, trustedSourceAddress, timeout));
      }
      if (operationId == null || operationId.equals(new UUID(0, 0))) return error(Code.INVALID_REQUEST);
      // Resolve/authenticate first; a path UUID is never authority and cannot cause a new INSERT.
      operations.authenticateExisting(operationId, input,
          action == MobileEnrollmentParser.Operation.COMPLETE || action == MobileEnrollmentParser.Operation.STATUS);
      return switch (action) {
        case SEND_CODE -> verification(coordinator.sendCode(operationId, input, acceptLanguage, timeout));
        case CHECK_CODE -> {
          var status = coordinator.checkCode(operationId, input, code, timeout);
          yield status.verified() ? verification(status) : error(Code.CODE_NOT_ACCEPTED);
        }
        case STATUS, COMPLETE -> {
          var committed = creator.findCommittedStatus(input);
          if (committed.isPresent()) yield account(committed.get(), input,
              action == MobileEnrollmentParser.Operation.COMPLETE);
          if (action == MobileEnrollmentParser.Operation.STATUS)
            yield verification(coordinator.status(operationId, input, timeout));
          var attested = coordinator.attestVerifiedPhone(operationId, input);
          yield account(creator.createOrResumePending(operationId, input, attested), input, true);
        }
        default -> error(Code.INVALID_REQUEST);
      };
    } catch (RegistrationOperations.OperationRejectedException rejected) {
      return error(switch (rejected.reason()) {
        case UNAVAILABLE -> Code.ENROLLMENT_UNAVAILABLE;
        case INVALID_CREDENTIALS -> Code.INVALID_CREDENTIALS;
        case CONFLICT -> Code.ENROLLMENT_CONFLICT;
        case EXPIRED -> Code.ENROLLMENT_EXPIRED;
      });
    } catch (AdmissionAccountCreator.EnrollmentRejectedException rejected) {
      return error(Code.ENROLLMENT_UNAVAILABLE);
    } catch (RateLimitExceededException limited) {
      Long delay = limited.getRetryDuration().filter(d -> !d.isNegative()).map(d -> {
        long seconds = d.getSeconds();
        return seconds == Long.MAX_VALUE ? seconds : seconds + (d.getNano() == 0 ? 0 : 1);
      }).orElse(null);
      return error(Code.RATE_LIMITED, delay);
    } catch (IllegalArgumentException malformed) {
      return error(Code.INVALID_REQUEST);
    } catch (Exception unavailable) {
      // Private IAM/provider/SQL errors and ambiguous send outcomes never imply bad credentials.
      // No logging or chained exception/DTO serialization crosses this public boundary.
      return error(Code.TEMPORARILY_UNAVAILABLE);
    }
  }

  private static Result verification(AdmissionRegistrationCoordinator.SessionStatus status) {
    return new Result(200, new Verification(status.operationId(), "verification", status.verified(),
        status.nextSmsSeconds(), status.nextCheckSeconds(), status.expiresInSeconds(), false));
  }

  private Result account(AdmissionAccountCreator.Status status,
      AdmissionRegistrationCoordinator.Input input, boolean newlyCompleted) {
    return switch (status.status()) {
      case "PENDING" -> new Result(newlyCompleted ? 202 : 200,
          new AccountStatus(status.operationId(), "pending_confirmation", false, null));
      case "SUSPENDED" -> new Result(200, new AccountStatus(status.operationId(), "suspended", false, null));
      case "ACTIVE" -> {
        var proof = gate.authorizeDevice(status.aci(), Device.PRIMARY_ID, input.password());
        var projection = proof.accountProjection();
        if (!projection.aci().equals(status.aci()) || !projection.number().equals(input.requestedNumber()))
          yield error(Code.TEMPORARILY_UNAVAILABLE);
        proof.requireCurrent(status.aci(), Device.PRIMARY_ID);
        yield new Result(200, new AccountStatus(status.operationId(), "active", true, projection));
      }
      default -> error(Code.TEMPORARILY_UNAVAILABLE);
    };
  }
}
