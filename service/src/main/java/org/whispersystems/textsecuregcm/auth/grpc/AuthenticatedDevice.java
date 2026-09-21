/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth.grpc;

import java.util.UUID;
import javax.annotation.Nullable;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;

public record AuthenticatedDevice(UUID accountIdentifier, byte deviceId,
                                 @JsonIgnore @Nullable AdmissionEntitlementGate.DeviceAuthorization admissionAuthorization) {
  public AuthenticatedDevice(UUID accountIdentifier, byte deviceId) {
    this(accountIdentifier, deviceId, null);
  }

  public void requireCurrentEntitlement() {
    if (admissionAuthorization == null) {
      throw new IllegalStateException("Current alumni entitlement evidence required");
    }
    admissionAuthorization.requireCurrent(accountIdentifier, deviceId);
  }
}
