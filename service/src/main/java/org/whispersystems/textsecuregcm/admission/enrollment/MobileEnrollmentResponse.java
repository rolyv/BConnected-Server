// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.AccountProjection;

/** Explicit public wire DTOs; no private permit, claim, session ID, or credential verifier. */
public final class MobileEnrollmentResponse {
  private MobileEnrollmentResponse() {}

  @JsonInclude(JsonInclude.Include.ALWAYS)
  public record Verification(UUID operationId, String state, boolean phoneVerified, Long nextSmsSeconds,
      Long nextCheckSeconds, long expiresInSeconds, boolean registrationAuthorized) {}

  @JsonInclude(JsonInclude.Include.ALWAYS)
  public record Supersession(UUID correctionId, UUID originalApplicationId, UUID replacementApplicationId,
      String state, Long expiresAt, boolean registrationAuthorized) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record AccountStatus(UUID operationId, String state, boolean registrationAuthorized,
      AccountProjection account) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Error(String code, Long retryAfterSeconds) {}

  public record Result(int status, Object body) {}

  public enum Code {
    INVALID_REQUEST(400), INVALID_CREDENTIALS(401), ENROLLMENT_UNAVAILABLE(404),
    ENROLLMENT_CONFLICT(409), ENROLLMENT_EXPIRED(410), CODE_NOT_ACCEPTED(422), CODE_EXPIRED(422), RATE_LIMITED(429),
    TEMPORARILY_UNAVAILABLE(503);
    public final int status;
    Code(int status) { this.status = status; }
  }

  public static Result error(Code code) { return error(code, null); }
  public static Result error(Code code, Long retryAfter) {
    return new Result(code.status, new Error(code.name(), retryAfter));
  }
}
