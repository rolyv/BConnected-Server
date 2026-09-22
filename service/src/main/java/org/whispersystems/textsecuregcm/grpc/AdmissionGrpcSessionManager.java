// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import io.dropwizard.lifecycle.Managed;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.sql.Connection;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Function;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.DeviceAuthorization;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.MessageDeliveryGuard;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/** Primary-device gRPC message-stream leases. Timers never perform SQL or wait for worker pools. */
public final class AdmissionGrpcSessionManager implements Managed {
  private final ScheduledExecutorService deadlines;
  private final Executor renewals;
  private final Executor deliveries;
  private final Scheduler deliveryScheduler;
  private final Set<Session> sessions = ConcurrentHashMap.newKeySet();
  private boolean stopped;

  public AdmissionGrpcSessionManager(ScheduledExecutorService deadlines, Executor renewals, Executor deliveries) {
    this.deadlines = Objects.requireNonNull(deadlines);
    this.renewals = Objects.requireNonNull(renewals);
    this.deliveries = Objects.requireNonNull(deliveries);
    this.deliveryScheduler = Schedulers.fromExecutor(deliveries);
  }

  /** Opens only upon subscription. Cancellation during initialization cannot leave a renewing lease. */
  public <T> Flux<T> withSession(AuthenticatedDevice principal, Function<Session, Flux<T>> stream) {
    return Mono.fromFuture(() -> open(principal))
        .flatMapMany(session -> session.guard(Flux.defer(() -> stream.apply(session))))
        .doOnDiscard(Session.class, Session::close);
  }

  private CompletableFuture<Session> open(AuthenticatedDevice principal) {
    var result = new CompletableFuture<Session>();
    if (principal == null || principal.admissionAuthorization() == null || principal.deviceId() != Device.PRIMARY_ID) {
      result.completeExceptionally(denied());
      return result;
    }
    final DeviceAuthorization original = principal.admissionAuthorization();
    try {
      deliveries.execute(() -> {
        Session session = null;
        try {
          original.requireCurrent(principal.accountIdentifier(), principal.deviceId());
          session = new Session(principal.accountIdentifier(), principal.deviceId(), original);
          synchronized (this) {
            if (stopped) throw unavailable();
            sessions.add(session);
          }
          session.start();
          if (!result.complete(session)) session.close();
        } catch (RuntimeException failure) {
          if (session != null) session.finish(map(failure));
          result.completeExceptionally(map(failure));
        }
      });
    } catch (RuntimeException rejected) {
      result.completeExceptionally(unavailable());
    }
    return result;
  }

  public final class Session implements AutoCloseable {
    private final UUID account;
    private final byte deviceId;
    private final Sinks.Empty<Void> termination = Sinks.empty();
    private DeviceAuthorization current;
    private boolean closed;
    private ScheduledFuture<?> deadline, renewal;
    private FutureTask<Void> inFlight;
    private org.reactivestreams.Subscription output;

    private Session(UUID account, byte deviceId, DeviceAuthorization original) {
      this.account = account;
      this.deviceId = deviceId;
      this.current = original;
    }

    private void start() {
      synchronized (this) { schedule(); }
    }

    private Guard capture() {
      synchronized (this) {
        requireOpen(current);
        return new Guard(current);
      }
    }

    /** For initial account-cache lookup, already executing on the bounded initialization worker. */
    public void requireDevice(UUID expectedAccount, Device device) {
      capture().requireCurrent(expectedAccount, device);
    }

    /** One ACK/story-discard use captures its proof before dispatch and retains it through waits. */
    public <T> CompletableFuture<T> execute(Function<MessageDeliveryGuard, CompletableFuture<T>> action) {
      final Guard guard;
      try { guard = capture(); }
      catch (RuntimeException failure) { return CompletableFuture.failedFuture(map(failure)); }
      var result = new CompletableFuture<T>();
      try {
        deliveries.execute(() -> {
          try {
            guard.requireCurrent();
            action.apply(guard).whenComplete((value, failure) -> {
              if (failure == null) result.complete(value);
              else { finish(map(failure)); result.completeExceptionally(map(failure)); }
            });
          } catch (RuntimeException failure) {
            finish(map(failure)); result.completeExceptionally(map(failure));
          }
        });
      } catch (RuntimeException rejected) {
        finish(unavailable()); result.completeExceptionally(unavailable());
      }
      return result;
    }

    private <T> Flux<T> guard(Flux<T> source) {
      // One buffered response. The handle callback runs only after downstream demand and the
      // delivery-worker wait, after MessageDispatcher's ACK-permit/backpressure coordination.
      // The simple-grpc bridge immediately calls its response observer from this onNext boundary.
      return source.subscribeOn(deliveryScheduler).publishOn(deliveryScheduler, 1)
          .<T>handle((value, sink) -> {
            try { capture().requireCurrent(); sink.next(value); }
            catch (RuntimeException failure) { sink.error(map(failure)); }
          })
          .doOnSubscribe(subscription -> {
            synchronized (this) {
              if (!closed && output == null) { output = subscription; return; }
            }
            subscription.cancel();
          })
          // This terminal signal is downstream of the blocking worker stage. A stalled native
          // check cannot postpone expiry/error delivery or cancellation of the input ACK stream.
          .takeUntilOther(termination.asMono())
          .onErrorMap(AdmissionGrpcSessionManager::map)
          .doFinally(_ -> close());
    }

    private void requireOpen(DeviceAuthorization proof) {
      synchronized (this) {
        if (closed || proof.remainingNanos() == 0) throw unavailable();
      }
    }

    private final class Guard implements MessageDeliveryGuard {
      private final DeviceAuthorization proof;
      Guard(DeviceAuthorization proof) { this.proof = proof; }
      @Override public Executor executor() { return deliveries; }
      @Override public void requireCurrent() {
        requireOpen(proof);
        proof.requireCurrent(account, deviceId);
        requireOpen(proof);
      }
      @Override public void requireCurrent(UUID expectedAccount, Device device) {
        identity(expectedAccount, device);
        requireOpen(proof);
        proof.requireCurrent(account, deviceId, device.getCreated());
        requireOpen(proof);
      }
      @Override public void requireCurrent(Connection connection, UUID expectedAccount, Device device) {
        identity(expectedAccount, device);
        requireOpen(proof);
        proof.requireCurrent(connection, account, deviceId, device.getCreated());
        requireOpen(proof);
      }
      private void identity(UUID expectedAccount, Device device) {
        if (!account.equals(expectedAccount) || device.getId() != deviceId) throw unavailable();
      }
    }

    // Called with this monitor held. Only scheduling/closure is performed on timer threads.
    private void schedule() {
      DeviceAuthorization expected = current;
      requireOpen(expected);
      long remaining = expected.remainingNanos();
      deadline = deadlines.schedule(() -> expire(expected), remaining, TimeUnit.NANOSECONDS);
      renewal = deadlines.schedule(() -> renew(expected), Math.max(1, remaining / 2), TimeUnit.NANOSECONDS);
    }

    private void expire(DeviceAuthorization expected) {
      try {
        synchronized (this) {
          if (closed || current != expected) return;
          long remaining = expected.remainingNanos();
          if (remaining > 0) {
            deadline = deadlines.schedule(() -> expire(expected), remaining, TimeUnit.NANOSECONDS);
            return;
          }
        }
      } catch (RuntimeException rejected) { /* Fail closed outside the lease monitor. */ }
      finish(unavailable());
    }

    private void renew(DeviceAuthorization expected) {
      try {
        synchronized (this) {
          if (closed || current != expected || inFlight != null) return;
          requireOpen(expected);
          inFlight = new FutureTask<>(() -> {
            try {
              DeviceAuthorization next = expected.renew(account, deviceId);
              synchronized (this) {
                if (closed || current != expected) return null;
                requireOpen(expected);
                requireOpen(next);
                deadline.cancel(false);
                current = next;
                inFlight = null;
                schedule();
              }
            } catch (RuntimeException failure) { finish(map(failure)); }
            return null;
          });
          renewals.execute(inFlight);
        }
      } catch (RuntimeException failure) { finish(map(failure)); }
    }

    private void finish(StatusRuntimeException failure) {
      final org.reactivestreams.Subscription subscription;
      synchronized (this) {
        if (closed) return;
        closed = true;
        sessions.remove(this);
        if (deadline != null) deadline.cancel(false);
        if (renewal != null) renewal.cancel(false);
        if (inFlight != null) inFlight.cancel(true);
        subscription = output;
        output = null;
      }
      // Reactor takeUntilOther propagates an error from the other publisher without cancelling
      // its main subscription. Explicitly cancel both message and ACK sources even at zero demand.
      try { if (subscription != null) subscription.cancel(); }
      finally { if (failure == null) termination.tryEmitEmpty(); else termination.tryEmitError(failure); }
    }
    @Override public void close() { finish(null); }
  }

  private static StatusRuntimeException denied() {
    return Status.UNAUTHENTICATED.withDescription("Current device authentication required").asRuntimeException();
  }
  private static StatusRuntimeException unavailable() {
    return Status.UNAVAILABLE.withDescription("Current device authentication unavailable").asRuntimeException();
  }
  private static StatusRuntimeException map(Throwable failure) {
    while (failure instanceof CompletionException && failure.getCause() != null) failure = failure.getCause();
    if (failure instanceof AdmissionEntitlementGate.DeniedException) return denied();
    if (failure instanceof StatusRuntimeException status) return status;
    return unavailable();
  }

  @Override public void stop() {
    synchronized (this) { stopped = true; }
    sessions.forEach(session -> session.finish(unavailable()));
    deliveryScheduler.dispose();
  }
}
