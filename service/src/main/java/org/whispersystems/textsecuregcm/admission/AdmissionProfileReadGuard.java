// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.grpc.Status;
import jakarta.ws.rs.WebApplicationException;
import java.sql.Connection;
import java.util.UUID;
import java.util.function.Supplier;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;

/** One profile read, retaining the exact caller proof and (for fetch) the target's original receipt. */
public final class AdmissionProfileReadGuard {
  public static final class Failure extends RuntimeException {
    private final int status;
    private Failure(int status) { super("Current profile authorization required"); this.status = status; }
    public RuntimeException http() { return new WebApplicationException(getMessage(), status); }
    public RuntimeException grpc() {
      return (status == 401 ? Status.UNAUTHENTICATED : status == 404 ? Status.NOT_FOUND : Status.UNAVAILABLE)
          .withDescription(getMessage()).asRuntimeException();
    }
    public boolean targetDenied() { return status == 404; }
  }
  private final AdmissionEntitlementGate gate;
  private final AdmissionEntitlementGate.DeviceAuthorization caller;
  private final UUID callerAci;
  private final byte callerDevice;
  private final AdmissionEntitlementGate.Authorization target;
  private final UUID targetAci;

  private AdmissionProfileReadGuard(AdmissionEntitlementGate gate, AdmissionEntitlementGate.DeviceAuthorization caller,
      UUID callerAci, byte callerDevice, AdmissionEntitlementGate.Authorization target, UUID targetAci) {
    this.gate = gate; this.caller = caller; this.callerAci = callerAci; this.callerDevice = callerDevice;
    this.target = target; this.targetAci = targetAci;
  }
  public static AdmissionProfileReadGuard http(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return own(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId());
  }
  public static AdmissionProfileReadGuard grpc(AdmissionEntitlementGate gate,
      org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(401);
    return own(gate, principal.admissionAuthorization(), principal.accountIdentifier(), principal.deviceId());
  }
  private static AdmissionProfileReadGuard own(AdmissionEntitlementGate gate,
      AdmissionEntitlementGate.DeviceAuthorization caller, UUID aci, byte device) {
    if (gate == null || caller == null || device != Device.PRIMARY_ID) throw new Failure(401);
    var guard = new AdmissionProfileReadGuard(gate, caller, aci, device, null, aci);
    guard.requireCurrent();
    guard.account();
    return guard;
  }
  public AdmissionProfileReadGuard forTarget(UUID aci, ServiceIdentifier identifier) {
    if (target != null) throw new Failure(401);
    return checked(() -> {
      requireCurrent();
      AdmissionEntitlementGate.Authorization receipt;
      try { receipt = gate.authorize(aci); }
      catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(404); }
      var next = new AdmissionProfileReadGuard(gate, caller, callerAci, callerDevice, receipt, aci);
      if (!next.account().isIdentifiedBy(identifier)) throw new Failure(404);
      next.requireCurrent(); // private HTTP wait consumes the original caller deadline
      return next;
    });
  }
  public Account account() {
    return checked(() -> {
      final Account result;
      if (target == null) result = caller.accountForCredentialIssuance(callerAci, callerDevice);
      else {
        try { result = target.accountForMessageSend(targetAci); }
        catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(404); }
      }
      if (result.getDevices().size() != 1 || result.getDevice(Device.PRIMARY_ID).isEmpty())
        throw new Failure(target == null ? 401 : 404);
      return result;
    });
  }
  public void requireCurrent() {
    checked(() -> {
      if (target == null) caller.requireCurrent(callerAci, callerDevice);
      else gate.requireCurrentSend(caller, callerAci, callerDevice, target, targetAci);
      gate.requireKeyReceipts(caller, target);
      return null;
    });
  }
  public void requireCurrent(Connection connection) {
    checked(() -> { gate.requireCurrentKeys(connection, caller, callerAci, callerDevice, target, targetAci); return null; });
  }
  public void requireFresh() {
    checked(() -> { gate.requireKeyReceipts(caller, target); return null; });
  }
  public static Failure targetNotFound() { return new Failure(404); }
  public static Failure unavailable() { return new Failure(503); }
  public static Failure failure(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof Failure failure) return failure;
      if (cause.getCause() == cause) break;
    }
    return unavailable();
  }
  private static <T> T checked(Supplier<T> action) {
    try { return action.get(); }
    catch (Failure failure) { throw failure; }
    catch (AdmissionEntitlementGate.RecipientDeniedException denied) { throw new Failure(404); }
    catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(401); }
    catch (RuntimeException unavailable) { throw unavailable(); }
  }
  @Override public String toString() { return "AdmissionProfileReadGuard[redacted]"; }
}
