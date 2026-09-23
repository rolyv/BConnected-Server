// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.grpc.Status;
import jakarta.ws.rs.WebApplicationException;
import java.sql.Connection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** A single self-mutation, with a private result check that cannot become new device credentials. */
public final class AdmissionAccountMutationGuard {
  public static final class Failure extends RuntimeException {
    private final int status;
    private Failure(int status) { super("Current account mutation authorization required"); this.status = status; }
    public RuntimeException http() { return new WebApplicationException(getMessage(), status); }
    public RuntimeException grpc() {
      return (status == 401 ? Status.UNAUTHENTICATED : Status.UNAVAILABLE)
          .withDescription(getMessage()).asRuntimeException();
    }
  }
  private final AdmissionEntitlementGate gate;
  private final AdmissionEntitlementGate.DeviceAuthorization caller;
  private final UUID aci;
  private final byte device;
  private final Account original;
  private final boolean profileMutation;
  private final AtomicBoolean used = new AtomicBoolean();
  private AdmissionEntitlementGate.Authorization result;

  private AdmissionAccountMutationGuard(AdmissionEntitlementGate gate,
      AdmissionEntitlementGate.DeviceAuthorization caller, UUID aci, byte device, boolean profileMutation) {
    if (gate == null || caller == null || device != Device.PRIMARY_ID) throw new Failure(401);
    this.profileMutation = profileMutation;
    this.gate = gate; this.caller = caller; this.aci = aci; this.device = device;
    original = checked(() -> caller.accountForCredentialIssuance(aci, device));
    if (original.getDevices().size() != 1 || original.getDevice(Device.PRIMARY_ID).isEmpty()) throw new Failure(401);
    requireFresh();
  }
  public static AdmissionAccountMutationGuard http(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return new AdmissionAccountMutationGuard(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId(), false);
  }
  public static AdmissionAccountMutationGuard grpc(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return new AdmissionAccountMutationGuard(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId(), false);
  }
  public static AdmissionAccountMutationGuard profileHttp(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return new AdmissionAccountMutationGuard(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId(), true);
  }
  public static AdmissionAccountMutationGuard profileGrpc(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return new AdmissionAccountMutationGuard(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId(), true);
  }
  public void requireProfilePublication() { if (!profileMutation) throw unavailable(); }
  public Account begin() {
    if (!used.compareAndSet(false, true)) throw unavailable();
    requireFresh();
    // Round-trip JSON bytes: cpv uses a string deserializer that cannot read convertValue binary tokens.
    try {
      return SystemMapper.jsonMapper().readValue(SystemMapper.jsonMapper().writeValueAsBytes(original), Account.class);
    } catch (java.io.IOException failure) { throw unavailable(); }
  }
  public void requireCurrent(Connection connection) {
    checked(() -> { gate.requireCurrentKeys(connection, caller, aci, device, null, aci); return null; });
  }
  public void requireFresh() {
    checked(() -> { gate.requireKeyReceipts(caller, null); return null; });
  }
  public void validate(Account updated) {
    if (!protectedFields(original).equals(protectedFields(updated))) throw unavailable();
  }
  private ObjectNode protectedFields(Account account) {
    final ObjectNode tree = SystemMapper.jsonMapper().valueToTree(account);
    if (profileMutation) {
      tree.remove(List.of("cpv", "badges"));
      return tree;
    }
    tree.remove(List.of("registrationLock", "registrationLockSalt", "uak", "uua", "inCds"));
    if (account.getDevices().size() != 1 || account.getDevice(Device.PRIMARY_ID).isEmpty()) throw unavailable();
    final ObjectNode primary = (ObjectNode) tree.path("devices").get(0);
    primary.remove(List.of("name", "gcmId", "apnId", "pushTimestamp", "fetchesMessages", "lastSeen", "userAgent", "capabilities"));
    return tree;
  }
  public void recordResult(Connection connection, Account written) {
    validate(written);
    result = checked(() -> gate.accountMutationResult(connection, caller, written));
  }
  public void requireResult() {
    if (result == null) throw unavailable();
    checked(() -> { result.requireCurrent(aci); return null; });
  }
  public static Failure unavailable() { return new Failure(503); }
  public static Failure failure(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof Failure failure) return failure;
      if (cause instanceof AdmissionEntitlementGate.DeniedException) return new Failure(401);
      if (cause.getCause() == cause) break;
    }
    return unavailable();
  }
  private static <T> T checked(Supplier<T> action) {
    try { return action.get(); }
    catch (RuntimeException failure) { throw failure(failure); }
  }
  @Override public String toString() { return "AdmissionAccountMutationGuard[redacted]"; }
}
