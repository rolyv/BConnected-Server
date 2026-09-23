// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Operation;

/** Unregistered authenticated Signal dispatch. The original principal proof spans all waits. */
public final class GroupDispatchService {
  public record GatewayResult(int status, byte[] json) {
    public GatewayResult {
      if (status != 200 || json == null || json.length == 0 || json.length > 20 * 1024 * 1024)
        throw new IllegalArgumentException("Invalid private group gateway result");
      json = json.clone();
    }
    @Override public byte[] json() { return json.clone(); }
  }
  @FunctionalInterface public interface Transport {
    CompletableFuture<GatewayResult> dispatch(String method, String path, byte[] body, String handle,
        long deadlineNanos, Runnable requireOriginalCurrent);
  }
  public static final class GatewayException extends RuntimeException {
    private final int status;
    public GatewayException(int status) {
      super("Private group gateway unavailable");
      if (status != 403 && status != 404 && status != 409 && status != 503) throw new IllegalArgumentException();
      this.status = status;
    }
    public int status() { return status; }
  }
  public static final class Failure extends RuntimeException {
    private final int status;
    private Failure(int status) { super("Group request unavailable"); this.status = status; }
    public int status() { return status; }
  }
  private static final class AccountSlot {
    int inFlight;
    int tokens = 10;
    long refilledAt = System.nanoTime();
    long lastSeen = refilledAt;
  }
  private final GroupOriginalProofRegistry proofs;
  private final Transport transport;
  private final Map<UUID, AccountSlot> accounts = new HashMap<>();
  private int globalInFlight;

  public GroupDispatchService(GroupOriginalProofRegistry proofs, Transport transport) {
    this.proofs = Objects.requireNonNull(proofs); this.transport = Objects.requireNonNull(transport);
  }

  public GatewayResult execute(AuthenticatedDevice principal, String method, String path, String contentType,
      String contentEncoding, byte[] body) {
    if (principal == null || principal.admissionAuthorization() == null || principal.deviceId() != 1)
      throw new Failure(401);
    if (body == null || body.length > GroupDispatchRequest.MAX_BODY_BYTES) throw new Failure(413);
    final UUID account = principal.accountIdentifier();
    final Operation operation;
    try {
      principal.requireCurrentEntitlement();
      operation = GroupDispatchRequest.parse(method, path, contentType, contentEncoding, body);
    } catch (IllegalArgumentException invalid) { throw new Failure(400); }
    catch (RuntimeException denied) { throw new Failure(403); }
    acquire(account);
    try (var ticket = proofs.retain(principal.admissionAuthorization(), operation)) {
      ticket.requireCurrent(); // Before network dispatch, including capacity/queue waits.
      long deadline = System.nanoTime() + Math.min(principal.admissionAuthorization().remainingNanos(),
          GroupBridgeProtocol.MAX_LIFETIME_NANOS);
      if (deadline - System.nanoTime() <= 0) throw new Failure(403);
      CompletableFuture<GatewayResult> pending = transport.dispatch(method, path, body.clone(), ticket.handle(), deadline,
          ticket::requireCurrent);
      GatewayResult result;
      try { result = pending.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS); }
      catch (java.util.concurrent.ExecutionException failure) {
        ticket.requireCurrent();
        if (failure.getCause() instanceof GatewayException denied) throw new Failure(denied.status());
        throw new Failure(503);
      } catch (InterruptedException interrupted) {
        pending.cancel(true); Thread.currentThread().interrupt(); throw new Failure(503);
      } catch (Exception unavailable) { pending.cancel(true); throw new Failure(503); }
      GroupDispatchResult.requireExact(operation, result.json());
      ticket.requireCurrent(); // Also covers time spent parsing a large signed state response.
      return result;
    } catch (Failure failure) { throw failure; }
    catch (SecurityException denied) { throw new Failure(403); }
    catch (IllegalStateException saturated) { throw new Failure(503); }
    catch (RuntimeException unavailable) { throw new Failure(503); }
    finally { release(account); }
  }

  private synchronized void acquire(UUID account) {
    long now = System.nanoTime();
    if (accounts.size() >= 4096 && !accounts.containsKey(account)) {
      accounts.entrySet().removeIf(e -> e.getValue().inFlight == 0 && now - e.getValue().lastSeen > TimeUnit.MINUTES.toNanos(2));
      if (accounts.size() >= 4096) throw new Failure(503);
    }
    AccountSlot slot = accounts.computeIfAbsent(account, _ -> new AccountSlot());
    long refill = Math.max(0, now - slot.refilledAt) / TimeUnit.SECONDS.toNanos(6);
    if (refill > 0) { slot.tokens = (int) Math.min(10, slot.tokens + refill); slot.refilledAt = now; }
    slot.lastSeen = now;
    if (slot.tokens == 0 || slot.inFlight >= 2) throw new Failure(429);
    if (globalInFlight >= 4) throw new Failure(503);
    slot.tokens--; slot.inFlight++; globalInFlight++;
  }
  private synchronized void release(UUID account) {
    AccountSlot slot = accounts.get(account);
    if (slot != null && slot.inFlight > 0) { slot.inFlight--; globalInFlight--; slot.lastSeen = System.nanoTime(); }
  }
}
