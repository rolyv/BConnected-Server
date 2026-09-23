// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.DeviceAuthorization;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.*;

/** Bounded single-instance bridge retaining the original credential-verified proof, never renewing it. */
public final class GroupOriginalProofRegistry {
  private final int capacity;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, Ticket> retained = new HashMap<>();

  public GroupOriginalProofRegistry(int capacity) {
    if (capacity < 1 || capacity > 4096) throw new IllegalArgumentException("Invalid group registry capacity");
    this.capacity = capacity;
  }

  /** Handle is service metadata. Close after dispatch (including failure) and never serialize a Ticket. */
  public final class Ticket implements AutoCloseable {
    private final String handle;
    private final Operation operation;
    private final DeviceAuthorization original;
    private final Membership membership;
    private final long deadline;
    private Ticket(String handle, Operation operation, DeviceAuthorization original, Membership membership, long deadline) {
      this.handle = handle; this.operation = operation; this.original = original;
      this.membership = membership; this.deadline = deadline;
    }
    public String handle() { return handle; }
    public Operation operation() { return operation; }
    public void requireCurrent() {
      checkTime(); original.requireCurrent(membership.aci(), (byte) 1);
      if (!membership.equals(binding(original))) throw denied(); checkTime();
    }
    private void checkTime() { if (deadline - System.nanoTime() <= 0) throw denied(); }
    @Override public void close() { synchronized (retained) { retained.remove(handle, this); } }
    @Override public String toString() { return "GroupOriginalProofTicket[redacted]"; }
  }

  /** Caller must be the actual transport-authenticated DeviceAuthorization, never reconstructed fields. */
  public Ticket retain(DeviceAuthorization original, Operation operation) {
    Objects.requireNonNull(original); Objects.requireNonNull(operation);
    long start = System.nanoTime();
    long remaining = original.remainingNanos();
    if (remaining <= 0 || remaining > GroupBridgeProtocol.MAX_LIFETIME_NANOS) throw denied();
    var identity = original.accountProjection();
    if (identity.deviceId() != 1) throw denied();
    var membership = binding(original);
    if (!membership.aci().equals(identity.aci())) throw denied();
    byte[] entropy = new byte[32]; random.nextBytes(entropy);
    var ticket = new Ticket(GroupBridgeProtocol.encode(entropy), operation, original, membership, start + remaining);
    ticket.requireCurrent();
    synchronized (retained) {
      retained.values().removeIf(t -> t.deadline - System.nanoTime() <= 0);
      if (retained.size() >= capacity) throw new IllegalStateException("Group authorization capacity unavailable");
      if (retained.putIfAbsent(ticket.handle, ticket) != null) throw new IllegalStateException("Group authorization unavailable");
    }
    return ticket;
  }

  /** Package-private: the authenticated resolve endpoint is the only production caller. Consumed once. */
  Resolution resolve(ResolveRequest request) {
    final Ticket ticket;
    synchronized (retained) { ticket = retained.remove(request.handle()); }
    if (ticket == null || !ticket.operation.equals(request.operation())) throw denied();
    ticket.requireCurrent();
    long remaining = Math.min(ticket.deadline - System.nanoTime(), ticket.original.remainingNanos());
    if (remaining <= 0 || remaining > GroupBridgeProtocol.MAX_LIFETIME_NANOS) throw denied();
    return new Resolution(request.nonce(), ticket.operation, ticket.membership, 1, remaining);
  }

  private static Membership binding(DeviceAuthorization proof) {
    var b = proof.groupOperationBinding();
    return new Membership(b.memberId(), b.approvalEpoch(), b.signalOperationId(), b.permitId(), b.aci());
  }
  private static SecurityException denied() { return new SecurityException("Group authorization unavailable"); }
  @Override public String toString() { return "GroupOriginalProofRegistry[redacted]"; }
}
