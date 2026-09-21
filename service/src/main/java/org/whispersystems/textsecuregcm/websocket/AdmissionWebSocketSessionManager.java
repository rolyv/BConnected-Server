// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.websocket;

import io.dropwizard.lifecycle.Managed;
import jakarta.ws.rs.NotAuthorizedException;
import java.util.Map;
import java.util.Collections;
import java.util.WeakHashMap;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.AuthenticationUnavailableException;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.websocket.setup.WebSocketConnectListener;
import org.whispersystems.websocket.session.WebSocketSessionContext;

/**
 * Pilot chat request admission and bounded connection leases. SQL/HTTP run only in request workers
 * or the separately bounded renewal executor, never on the independent deadline scheduler. This
 * does not authorize server-initiated delivery, acknowledgments, or anonymous capabilities.
 */
public final class AdmissionWebSocketSessionManager implements Managed {
  private final ScheduledExecutorService deadlines;
  private final Executor renewals;
  private final Map<WebSocketSessionContext, Lease> leases = new ConcurrentHashMap<>();
  // Preserve a sanitized terminal classification for requests already received on a closing
  // transport. Weak keys avoid retaining a closed socket, identity, proof, or session indefinitely.
  private final Map<WebSocketSessionContext, Boolean> terminated =
      Collections.synchronizedMap(new WeakHashMap<>());
  private boolean stopped;

  public AdmissionWebSocketSessionManager(ScheduledExecutorService deadlines, Executor renewals) {
    this.deadlines = Objects.requireNonNull(deadlines);
    this.renewals = Objects.requireNonNull(renewals);
  }

  private static final class Lease {
    final WebSocketSessionContext context;
    AuthenticatedDevice current;
    boolean closed;
    ScheduledFuture<?> deadline, renewal;
    FutureTask<Void> inFlight;

    Lease(WebSocketSessionContext context, AuthenticatedDevice current) {
      this.context = context;
      this.current = current;
    }
  }

  public WebSocketConnectListener wrap(WebSocketConnectListener delegate) {
    Objects.requireNonNull(delegate);
    return context -> {
      if (!(context.getAuthenticated() instanceof AuthenticatedDevice principal)
          || principal.admissionAuthorization() == null || principal.deviceId() != Device.PRIMARY_ID) {
        closeTransport(context, 1008);
        return;
      }
      try {
        principal.requireCurrentEntitlement();
      } catch (RuntimeException failure) {
        closeTransport(context, code(failure));
        return;
      }
      Lease lease = new Lease(context, principal);
      final boolean wasStopped;
      final Lease previous;
      synchronized (this) {
        wasStopped = stopped;
        previous = wasStopped ? null : leases.putIfAbsent(context, lease);
      }
      if (wasStopped) {
        closeTransport(context, 1013);
        return;
      }
      if (previous != null) {
        finish(previous, 1013);
        return;
      }
      context.addWebsocketClosedListener((_, _, _) -> finish(lease, null));
      synchronized (lease) {
        if (lease.closed) return;
        try {
          schedule(lease);
        } catch (RuntimeException unavailable) {
          finish(lease, 1013);
          return;
        }
      }
      try {
        requireCurrent(context);
        delegate.onWebSocketConnect(context);
      } catch (RuntimeException failure) {
        finish(lease, code(failure));
      }
    };
  }

  /** Rechecked after Jersey's dispatch wait, before any matched handler (including Optional auth). */
  public AuthenticatedDevice requireCurrent(WebSocketSessionContext context) {
    Lease lease = leases.get(context);
    if (lease == null) {
      if (Boolean.TRUE.equals(terminated.get(context))) throw new AuthenticationUnavailableException();
      throw new NotAuthorizedException("Current device authentication required");
    }
    final AuthenticatedDevice principal;
    synchronized (lease) {
      principal = lease.current;
      if (lease.closed || context.getAuthenticated() != principal
          || principal.admissionAuthorization().remainingNanos() == 0) {
        finish(lease, 1013);
        throw new AuthenticationUnavailableException();
      }
    }
    recheck(lease, principal);
    return principal;
  }

  /** Opaque request-local proof. The actual handler boundary must recheck this same lease. */
  public final class RequestAuthorization {
    private final Lease lease;
    private final AuthenticatedDevice principal;

    private RequestAuthorization(Lease lease, AuthenticatedDevice principal) {
      this.lease = lease;
      this.principal = principal;
    }

    public AuthenticatedDevice principal() { return principal; }
    public void requireCurrent() { recheck(lease, principal); }
  }

  public RequestAuthorization authorizeRequest(WebSocketSessionContext context) {
    AuthenticatedDevice principal = requireCurrent(context);
    Lease lease = leases.get(context);
    if (lease == null) throw new AuthenticationUnavailableException();
    return new RequestAuthorization(lease, principal);
  }

  private void recheck(Lease lease, AuthenticatedDevice principal) {
    try {
      synchronized (lease) {
        if (lease.closed) throw new AuthenticationUnavailableException();
      }
      principal.requireCurrentEntitlement();
      synchronized (lease) {
        // Do not substitute a newly renewed lease to rescue a check delayed past its own deadline.
        if (lease.closed || lease.context.getAuthenticated() != lease.current
            || principal.admissionAuthorization().remainingNanos() == 0)
          throw new AuthenticationUnavailableException();
      }
    } catch (RuntimeException failure) {
      failIfCurrent(lease, principal, code(failure));
      if (failure instanceof AdmissionEntitlementGate.DeniedException)
        throw new NotAuthorizedException("Current device authentication required");
      throw new AuthenticationUnavailableException();
    }
  }

  // Caller holds the lease monitor. The scheduler executes only lightweight bookkeeping/close.
  private void schedule(Lease lease) {
    AuthenticatedDevice expected = lease.current;
    long remaining = expected.admissionAuthorization().remainingNanos();
    if (remaining == 0) throw new AuthenticationUnavailableException();
    lease.deadline = deadlines.schedule(() -> expire(lease, expected), remaining, TimeUnit.NANOSECONDS);
    lease.renewal = deadlines.schedule(() -> renew(lease, expected), Math.max(1, remaining / 2), TimeUnit.NANOSECONDS);
  }

  private void expire(Lease lease, AuthenticatedDevice expected) {
    synchronized (lease) {
      if (lease.closed || lease.current != expected) return;
      long remaining = expected.admissionAuthorization().remainingNanos();
      if (remaining == 0) {
        finish(lease, 1013);
      } else {
        try {
          lease.deadline = deadlines.schedule(() -> expire(lease, expected), remaining, TimeUnit.NANOSECONDS);
        } catch (RuntimeException rejected) {
          finish(lease, 1013);
        }
      }
    }
  }

  private void renew(Lease lease, AuthenticatedDevice expected) {
    synchronized (lease) {
      if (lease.closed || lease.current != expected || lease.inFlight != null) return;
      if (expected.admissionAuthorization().remainingNanos() == 0) {
        finish(lease, 1013);
        return;
      }
      FutureTask<Void> task = new FutureTask<>(() -> {
        try {
          var proof = expected.admissionAuthorization().renew(expected.accountIdentifier(), expected.deviceId());
          var next = new AuthenticatedDevice(expected.accountIdentifier(), expected.deviceId(),
              proof.primaryDeviceLastSeen(), proof);
          synchronized (lease) {
            if (lease.closed || lease.current != expected) return null;
            // Publication itself may wait. Neither an expired old lease nor late success reopens it.
            if (expected.admissionAuthorization().remainingNanos() == 0 || proof.remainingNanos() == 0) {
              finish(lease, 1013);
              return null;
            }
            lease.deadline.cancel(false);
            lease.current = next;
            lease.inFlight = null;
            lease.context.setAuthenticated(next);
            try {
              schedule(lease);
            } catch (RuntimeException rejected) {
              finish(lease, 1013);
            }
          }
        } catch (RuntimeException failure) {
          failIfCurrent(lease, expected, code(failure));
        }
        return null;
      });
      lease.inFlight = task;
      try {
        // The production executor has bounded concurrency and no queue or caller-runs policy.
        renewals.execute(task);
      } catch (RuntimeException rejected) {
        finish(lease, 1013);
      }
    }
  }

  private void failIfCurrent(Lease lease, AuthenticatedDevice expected, int code) {
    synchronized (lease) {
      if (!lease.closed && lease.current == expected) finish(lease, code);
    }
  }

  private void finish(Lease lease, Integer closeCode) {
    synchronized (lease) {
      if (lease.closed) return;
      lease.closed = true;
      terminated.put(lease.context, closeCode == null || closeCode != 1008);
      leases.remove(lease.context, lease);
      if (lease.deadline != null) lease.deadline.cancel(false);
      if (lease.renewal != null) lease.renewal.cancel(false);
      if (lease.inFlight != null) lease.inFlight.cancel(true);
      // Keep the authenticated identity: null would downgrade Optional-auth handlers to anonymous.
    }
    if (closeCode != null) closeTransport(lease.context, closeCode);
  }

  private void closeTransport(WebSocketSessionContext context, int code) {
    terminated.putIfAbsent(context, code != 1008);
    try {
      context.getClient().close(code, "Current device authentication unavailable");
      // A peer need not cooperate with a close frame. Closure is independent of renewal workers.
      deadlines.schedule(context.getClient()::disconnect, 250, TimeUnit.MILLISECONDS);
    } catch (RuntimeException rejected) {
      context.getClient().disconnect();
    }
  }

  private static int code(RuntimeException failure) {
    return failure instanceof AdmissionEntitlementGate.DeniedException ? 1008 : 1013;
  }

  @Override
  public void stop() {
    synchronized (this) { stopped = true; }
    leases.values().forEach(lease -> {
      finish(lease, null);
      lease.context.getClient().disconnect();
    });
  }
}
