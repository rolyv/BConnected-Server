// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import java.util.UUID;
import org.whispersystems.textsecuregcm.entities.RegistrationRequest;

/** Parsed public input, not authentication or admission authority. Snapshot again at coordinator use. */
public record MobileEnrollmentRequest(
    UUID memberId,
    String registrationAttemptId,
    String bindingChallenge,
    RegistrationRequest registrationRequest,
    String originalSignalAgent,
    String originalUserAgent,
    String code) {
  @Override
  public String toString() {
    return "MobileEnrollmentRequest[redacted]";
  }
}
