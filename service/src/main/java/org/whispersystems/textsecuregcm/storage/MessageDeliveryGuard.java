// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.util.UUID;
import java.util.concurrent.Executor;

/** One immutable device proof for one delivery/acknowledgment use, including asynchronous waits. */
public interface MessageDeliveryGuard {
  /** Exact captured admission proof for guarded server receipt forwarding; absent for legacy uses. */
  default org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.DeviceAuthorization admissionAuthorization() {
    return null;
  }
  void requireCurrent();

  void requireCurrent(UUID expectedAccount, Device expectedDevice);

  /** Recheck and retain account/admission locks in the caller's native SQL transaction. */
  void requireCurrent(Connection connection, UUID expectedAccount, Device expectedDevice);

  /** Bounded blocking-work executor; never dispatch SQL on transport or Redis event loops. */
  Executor executor();
}
