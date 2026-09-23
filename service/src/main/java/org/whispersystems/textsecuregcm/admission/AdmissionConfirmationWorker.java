// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.dropwizard.lifecycle.Managed;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lifecycle-managed poller for durable admission confirmation work. Constructing this worker does
 * not schedule or execute work; the owning runtime must explicitly start it through its lifecycle.
 */
public final class AdmissionConfirmationWorker implements Managed {
  private static final Logger log = LoggerFactory.getLogger(AdmissionConfirmationWorker.class);
  private static final Duration DEFAULT_INTERVAL = Duration.ofSeconds(1);
  private static final Duration DEFAULT_SHUTDOWN_TIMEOUT = Duration.ofSeconds(10);

  private enum State {
    NEW,
    RUNNING,
    STOPPED
  }

  private final Supplier<AdmissionConfirmationOutbox.Outcome> runOne;
  private final ScheduledExecutorService executor;
  private final Duration interval;
  private final Duration shutdownTimeout;
  private final AtomicReference<State> state = new AtomicReference<>(State.NEW);
  private final AtomicBoolean running = new AtomicBoolean();
  private volatile ScheduledFuture<?> scheduled;

  public AdmissionConfirmationWorker(AdmissionConfirmationOutbox outbox) {
    this(Objects.requireNonNull(outbox)::runOne, newExecutor(), DEFAULT_INTERVAL,
        DEFAULT_SHUTDOWN_TIMEOUT);
  }

  AdmissionConfirmationWorker(Supplier<AdmissionConfirmationOutbox.Outcome> runOne,
      ScheduledExecutorService executor, Duration interval, Duration shutdownTimeout) {
    this.runOne = Objects.requireNonNull(runOne);
    this.executor = Objects.requireNonNull(executor);
    this.interval = requireBounded(interval, Duration.ofMillis(100), Duration.ofMinutes(1), "interval");
    this.shutdownTimeout = requireBounded(shutdownTimeout, Duration.ofMillis(1), Duration.ofSeconds(30),
        "shutdown timeout");
  }

  @Override
  public void start() {
    if (!state.compareAndSet(State.NEW, State.RUNNING)) {
      if (state.get() == State.RUNNING) return;
      throw new IllegalStateException("Admission confirmation worker cannot be restarted");
    }

    try {
      scheduled = executor.scheduleWithFixedDelay(this::runSafely, 0, interval.toNanos(),
          TimeUnit.NANOSECONDS);
    } catch (RuntimeException failure) {
      state.set(State.STOPPED);
      executor.shutdownNow();
      throw failure;
    }
  }

  @Override
  public void stop() {
    State previous = state.getAndSet(State.STOPPED);
    if (previous == State.STOPPED) return;

    ScheduledFuture<?> task = scheduled;
    if (task != null) task.cancel(false);
    executor.shutdown();
    try {
      if (!executor.awaitTermination(shutdownTimeout.toNanos(), TimeUnit.NANOSECONDS)) {
        if (task != null) task.cancel(true);
        executor.shutdownNow();
      }
    } catch (InterruptedException interrupted) {
      if (task != null) task.cancel(true);
      executor.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }

  private void runSafely() {
    if (state.get() != State.RUNNING || !running.compareAndSet(false, true)) return;
    try {
      runOne.get();
    } catch (RuntimeException failure) {
      // Do not include the exception or its message: this boundary may wrap provider/SQL details.
      // Fixed-delay scheduling ensures another attempt waits for the configured interval.
      log.warn("Admission confirmation iteration failed; a later retry is scheduled");
    } finally {
      running.set(false);
    }
  }

  private static ScheduledExecutorService newExecutor() {
    ThreadFactory factory = task -> {
      Thread thread = new Thread(task, "admission-confirmation");
      thread.setDaemon(false);
      return thread;
    };
    return Executors.newSingleThreadScheduledExecutor(factory);
  }

  private static Duration requireBounded(Duration value, Duration minimum, Duration maximum, String name) {
    if (value == null || value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
      throw new IllegalArgumentException("Invalid admission confirmation " + name);
    }
    return value;
  }
}
