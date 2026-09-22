// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.grpc.Status;
import jakarta.ws.rs.WebApplicationException;
import java.util.UUID;
import java.util.function.Supplier;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;

/** One capability-issuance use; all checks retain its original device proof and receipt deadline. */
public final class AdmissionCapabilityGuard implements Runnable {
  private final UUID account;
  private final byte device;
  private final AdmissionEntitlementGate.DeviceAuthorization proof;
  private final boolean grpc;
  private final boolean required;

  private AdmissionCapabilityGuard(UUID account, byte device,
      AdmissionEntitlementGate.DeviceAuthorization proof, boolean grpc, boolean required) {
    this.account = account; this.device = device; this.proof = proof; this.grpc = grpc;
    this.required = required;
  }

  public static AdmissionCapabilityGuard http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal, boolean required) {
    if (!required) return new AdmissionCapabilityGuard(null, (byte) 0, null, false, false);
    return new AdmissionCapabilityGuard(principal.accountIdentifier(), principal.deviceId(),
        principal.admissionAuthorization(), false, required);
  }

  public static AdmissionCapabilityGuard grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal, boolean required) {
    if (!required) return new AdmissionCapabilityGuard(null, (byte) 0, null, true, false);
    return new AdmissionCapabilityGuard(principal.accountIdentifier(), principal.deviceId(),
        principal.admissionAuthorization(), true, required);
  }

  @Override public void run() {
    if (!required) return;
    if (proof == null || device != Device.PRIMARY_ID) throw failure(false);
    try { proof.requireCurrent(account, device); }
    catch (AdmissionEntitlementGate.DeniedException rejected) { throw failure(false); }
    catch (RuntimeException unavailable) { throw failure(true); }
  }

  /** The pilot signs only identity fields from the exact credential-verified authoritative snapshot. */
  public Account accountForCredentialIssuance(Supplier<Account> legacyAccount) {
    if (!required) return legacyAccount.get();
    if (proof == null || device != Device.PRIMARY_ID) throw failure(false);
    try { return proof.accountForCredentialIssuance(account, device); }
    catch (AdmissionEntitlementGate.DeniedException rejected) { throw failure(false); }
    catch (RuntimeException unavailable) { throw failure(true); }
  }

  private RuntimeException failure(boolean unavailable) {
    return grpc ? (unavailable ? Status.UNAVAILABLE : Status.UNAUTHENTICATED)
        .withDescription(unavailable ? "Current membership unavailable" : "Current membership required")
        .asRuntimeException() : new WebApplicationException(unavailable ? 503 : 401);
  }
}
