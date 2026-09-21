/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import java.security.Principal;
import java.time.Instant;
import java.util.UUID;
import javax.security.auth.Subject;
import com.fasterxml.jackson.annotation.JsonIgnore;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;

public record AuthenticatedDevice(UUID accountIdentifier, byte deviceId, Instant primaryDeviceLastSeen,
                                  @JsonIgnore @Nullable AdmissionEntitlementGate.DeviceAuthorization admissionAuthorization)
    implements Principal {

  public AuthenticatedDevice(UUID accountIdentifier, byte deviceId, Instant primaryDeviceLastSeen) {
    this(accountIdentifier, deviceId, primaryDeviceLastSeen, null);
  }

  /** Recheck retained pilot evidence after waits; legacy principals cannot satisfy this boundary. */
  public void requireCurrentEntitlement() {
    if (admissionAuthorization == null) {
      throw new IllegalStateException("Current alumni entitlement evidence required");
    }
    admissionAuthorization.requireCurrent(accountIdentifier, deviceId);
  }

  @Override
  public String getName() {
    return null;
  }

  @Override
  public boolean implies(final Subject subject) {
    return false;
  }
}
