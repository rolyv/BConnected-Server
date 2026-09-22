// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.grpc.Status;
import jakarta.ws.rs.WebApplicationException;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Supplier;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.entities.MessageProtos.Envelope;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.MessageDeliveryGuard;

/** One authenticated send: original sender proof and a fixed recipient receipt survive every wait. */
public final class AdmissionMessageSendGuard implements Runnable {
  public static final class Failure extends RuntimeException {
    private final boolean unavailable;
    private final boolean recipientDenied;
    private Failure(boolean unavailable) {
      this(unavailable, false);
    }
    private Failure(boolean unavailable, boolean recipientDenied) {
      super(unavailable ? "Current message authorization unavailable" : "Current message authorization required");
      this.unavailable = unavailable;
      this.recipientDenied = recipientDenied;
    }
    public boolean recipientDenied() { return recipientDenied; }
    public RuntimeException http() { return new WebApplicationException(unavailable ? 503 : recipientDenied ? 404 : 401); }
    public RuntimeException grpc() {
      return (unavailable ? Status.UNAVAILABLE : recipientDenied ? Status.NOT_FOUND : Status.UNAUTHENTICATED)
          .withDescription(getMessage()).asRuntimeException();
    }
  }

  /** Opaque caller evidence; no bare account ID, UAK, group token or caller-provided Runnable suffices. */
  public static final class Source {
    private final UUID account;
    private final byte device;
    private final AdmissionEntitlementGate.DeviceAuthorization proof;
    private final MessageDeliveryGuard delivery;
    private final ServiceIdentifier serviceIdentifier;
    private Source(UUID account, byte device, AdmissionEntitlementGate.DeviceAuthorization proof,
        MessageDeliveryGuard delivery, ServiceIdentifier serviceIdentifier) {
      this.serviceIdentifier = serviceIdentifier;
      this.account = account; this.device = device; this.proof = proof; this.delivery = delivery;
    }
    public void requireCurrent() {
      if (proof == null || device != Device.PRIMARY_ID) throw new Failure(false);
      checked(() -> {
        if (delivery != null) delivery.requireCurrent();
        proof.requireCurrent(account, device);
        return null;
      });
    }
    @Override public String toString() { return "AdmissionMessageSource[redacted]"; }
  }

  private final AdmissionEntitlementGate gate;
  private final Source source;
  private final AdmissionEntitlementGate.Authorization recipient;
  private final UUID recipientAci;
  private final ServiceIdentifier destinationIdentifier;
  private final Executor executor;

  private AdmissionMessageSendGuard(AdmissionEntitlementGate gate, Source source,
      AdmissionEntitlementGate.Authorization recipient, Account destination, ServiceIdentifier destinationIdentifier, Executor executor) {
    this.gate = gate; this.source = source; this.recipient = recipient;
    this.recipientAci = destination.getAccountIdentifier(); this.destinationIdentifier = destinationIdentifier; this.executor = executor;
  }

  public static Source http(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(false);
    return new Source(principal.accountIdentifier(), principal.deviceId(), principal.admissionAuthorization(), null, new AciServiceIdentifier(principal.accountIdentifier()));
  }
  public static Source grpc(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice principal) {
    if (principal == null) throw new Failure(false);
    return new Source(principal.accountIdentifier(), principal.deviceId(), principal.admissionAuthorization(), null, new AciServiceIdentifier(principal.accountIdentifier()));
  }
  public static Source receipt(ServiceIdentifier sourceIdentifier, byte sourceDevice, MessageDeliveryGuard delivery) {
    if (delivery == null || delivery.admissionAuthorization() == null) throw new Failure(false);
    return checked(() -> {
      delivery.requireCurrent();
      var proof = delivery.admissionAuthorization();
      var identity = proof.accountProjection();
      UUID expected = switch (sourceIdentifier.identityType()) {
        case ACI -> identity.aci();
        case PNI -> identity.pni();
      };
      if (!sourceIdentifier.uuid().equals(expected) || sourceDevice != identity.deviceId()) throw new Failure(false);
      return new Source(identity.aci(), sourceDevice, proof, delivery, sourceIdentifier);
    });
  }

  public static AdmissionMessageSendGuard authorize(AdmissionEntitlementGate gate, Source source,
      UUID recipientAci, ServiceIdentifier destinationIdentifier, Executor executor) {
    if (source == null) throw new Failure(false);
    return checked(() -> {
      source.requireCurrent();
      final AdmissionEntitlementGate.Authorization recipient;
      try { recipient = gate.authorize(recipientAci); }
      catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(false, true); }
      final Account destination;
      try { destination = recipient.accountForMessageSend(recipientAci); }
      catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(false, true); }
      if (!destination.isIdentifiedBy(destinationIdentifier)
          || destination.getDevices().size() != 1
          || destination.getDevice(Device.PRIMARY_ID).isEmpty()) throw new Failure(false, true);
      var guard = new AdmissionMessageSendGuard(gate, source, recipient, destination, destinationIdentifier, Objects.requireNonNull(executor));
      guard.run();
      return guard;
    });
  }

  @Override public void run() {
    checked(() -> {
      if (source.delivery != null) source.delivery.requireCurrent();
      gate.requireCurrentSend(source.proof, source.account, source.device, recipient, recipientAci);
      return null;
    });
  }
  public void requireDestination(UUID account, byte device) {
    if (!recipientAci.equals(account) || device != Device.PRIMARY_ID) throw new Failure(false);
    run();
  }
  public void requireEnvelope(Envelope envelope) {
    if (envelope.getStory() || envelope.hasSharedMrmKey() || envelope.getType() == Envelope.Type.UNIDENTIFIED_SENDER
        || !envelope.hasSourceServiceId() || envelope.getSourceDevice() != source.device
        || !envelope.getSourceServiceId().equals(source.serviceIdentifier.toCompactByteString())
        || !envelope.getDestinationServiceId().equals(destinationIdentifier.toCompactByteString())) throw new Failure(false);
  }
  public Account destination() {
    return checked(() -> {
      try { return recipient.accountForMessageSend(recipientAci); }
      catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(false, true); }
    });
  }
  public Executor executor() { return executor; }

  public static Failure unavailable() { return new Failure(true); }

  /** Redis connection wrappers and completion stages must preserve admission status, not turn it into a 500. */
  public static RuntimeException unwrapDispatchFailure(RuntimeException failure) {
    for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
      if (cause instanceof Failure authorizationFailure) return authorizationFailure;
      if (cause instanceof java.util.concurrent.RejectedExecutionException) return new Failure(true);
      if (cause.getCause() == cause) break;
    }
    return failure;
  }

  /** The queue wait consumes the original budgets; never run SQL on Redis/provider callback threads. */
  public <T> CompletableFuture<T> dispatch(Supplier<CompletableFuture<T>> operation) {
    try {
      return CompletableFuture.supplyAsync(() -> { run(); return operation.get(); }, executor)
          .thenCompose(future -> future);
    } catch (RuntimeException rejected) {
      return CompletableFuture.failedFuture(new Failure(true));
    }
  }
  private static <T> T checked(Supplier<T> action) {
    try { return action.get(); }
    catch (Failure failure) { throw failure; }
    catch (AdmissionEntitlementGate.RecipientDeniedException denied) { throw new Failure(false, true); }
    catch (AdmissionEntitlementGate.DeniedException denied) { throw new Failure(false); }
    catch (RuntimeException unavailable) { throw new Failure(true); }
  }
  @Override public String toString() { return "AdmissionMessageSendGuard[redacted]"; }
}
