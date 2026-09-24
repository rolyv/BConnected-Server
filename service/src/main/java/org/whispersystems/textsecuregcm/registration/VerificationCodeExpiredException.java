// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration;

import java.util.Objects;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;

/** The bound code's persisted deadline elapsed while its native session is still active. */
public final class VerificationCodeExpiredException extends RegistrationServiceException {
  public VerificationCodeExpiredException(RegistrationServiceSession session) {
    super(Objects.requireNonNull(session));
  }
}
