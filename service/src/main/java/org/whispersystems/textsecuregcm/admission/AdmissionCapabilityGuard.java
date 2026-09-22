// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.grpc.Status;
import jakarta.ws.rs.WebApplicationException;
import java.util.UUID;
import org.whispersystems.textsecuregcm.storage.Device;

/** One capability-issuance use; all checks retain its original device proof and receipt deadline. */
public final class AdmissionCapabilityGuard implements Runnable {
  private final UUID account;
  private final byte device;
  private final AdmissionEntitlementGate.DeviceAuthorization proof;
  private final boolean grpc;

  private AdmissionCapabilityGuard(UUID account, byte device,
      AdmissionEntitlementGate.DeviceAuthorization proof, boolean grpc) {
    this.account = account; this.device = device; this.proof = proof; this.grpc = grpc;
  }

  public static Runnable http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal, boolean required) {
    return required ? new AdmissionCapabilityGuard(principal.accountIdentifier(), principal.deviceId(),
        principal.admissionAuthorization(), false) : () -> {};
  }

  public static Runnable grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal, boolean required) {
    return required ? new AdmissionCapabilityGuard(principal.accountIdentifier(), principal.deviceId(),
        principal.admissionAuthorization(), true) : () -> {};
  }

  @Override public void run() {
    if (proof == null || device != Device.PRIMARY_ID) throw failure(false);
    try { proof.requireCurrent(account, device); }
    catch (AdmissionEntitlementGate.DeniedException rejected) { throw failure(false); }
    catch (RuntimeException unavailable) { throw failure(true); }
  }

  private RuntimeException failure(boolean unavailable) {
    return grpc ? (unavailable ? Status.UNAVAILABLE : Status.UNAUTHENTICATED)
        .withDescription(unavailable ? "Current membership unavailable" : "Current membership required")
        .asRuntimeException() : new WebApplicationException(unavailable ? 503 : 401);
  }
}
