// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.util.UUID;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;

/** Self reads use the original authoritative snapshot and recheck it after response construction. */
public final class AdmissionAccountReadGuard {
  private final AdmissionEntitlementGate.DeviceAuthorization proof;
  private final UUID aci;
  private final byte device;
  private final Account account;

  private AdmissionAccountReadGuard(AdmissionEntitlementGate.DeviceAuthorization proof, UUID aci, byte device) {
    if (proof == null || device != Device.PRIMARY_ID) throw new jakarta.ws.rs.NotAuthorizedException("Current primary device required");
    this.proof = proof; this.aci = aci; this.device = device;
    account = proof.accountForCredentialIssuance(aci, device);
    if (account.getDevices().size() != 1 || account.getDevice(Device.PRIMARY_ID).isEmpty())
      throw new jakarta.ws.rs.NotAuthorizedException("Current primary device required");
  }

  public static AdmissionAccountReadGuard http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal) {
    try { return new AdmissionAccountReadGuard(principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId()); }
    catch (RuntimeException failure) { throw httpFailure(failure); }
  }
  public static AdmissionAccountReadGuard grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal) {
    try { return new AdmissionAccountReadGuard(principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId()); }
    catch (RuntimeException failure) { throw grpcFailure(failure); }
  }
  /** Detached from both the store and cache; never persisted or used to refresh authentication. */
  public Account account() { return account; }
  public <T> T httpResult(T response) {
    try { proof.requireCurrent(aci, device); return response; }
    catch (RuntimeException failure) { throw httpFailure(failure); }
  }
  public <T> T grpcResult(T response) {
    try { proof.requireCurrent(aci, device); return response; }
    catch (RuntimeException failure) { throw grpcFailure(failure); }
  }
  private static RuntimeException httpFailure(RuntimeException failure) {
    if (failure instanceof jakarta.ws.rs.NotAuthorizedException) return failure;
    return AdmissionAccountMutationGuard.failure(failure).http();
  }
  private static RuntimeException grpcFailure(RuntimeException failure) {
    if (failure instanceof jakarta.ws.rs.NotAuthorizedException)
      return io.grpc.Status.UNAUTHENTICATED.withDescription("Current primary device required").asRuntimeException();
    return AdmissionAccountMutationGuard.failure(failure).grpc();
  }
  @Override public String toString() { return "AdmissionAccountReadGuard[redacted]"; }
}
