// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.admission.AdmissionConfirmationOutbox.Outcome;

class AdmissionConfirmationWorkerTest {
  @Test
  void startsOnlyWhenManagedAndContainsIterationFailures() throws Exception {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    @SuppressWarnings("unchecked")
    ScheduledFuture<?> scheduled = mock(ScheduledFuture.class);
    AtomicReference<Runnable> tick = new AtomicReference<>();
    AtomicInteger runs = new AtomicInteger();
    when(executor.scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any()))
        .thenAnswer(call -> {
          tick.set(call.getArgument(0));
          return scheduled;
        });

    AdmissionConfirmationWorker worker = new AdmissionConfirmationWorker(() -> {
      if (runs.incrementAndGet() == 1) throw new IllegalStateException("synthetic failure");
      return Outcome.IDLE;
    }, executor, Duration.ofMillis(100), Duration.ofMillis(250));

    verifyNoInteractions(executor);
    worker.start();
    worker.start();
    verify(executor, times(1)).scheduleWithFixedDelay(any(Runnable.class), eq(0L),
        eq(Duration.ofMillis(100).toNanos()), eq(TimeUnit.NANOSECONDS));

    // The periodic task survives a failed iteration, so the next bounded-delay tick can retry.
    tick.get().run();
    tick.get().run();
    assertThat(runs.get()).isEqualTo(2);
    verify(scheduled, never()).cancel(anyBoolean());

    when(executor.awaitTermination(Duration.ofMillis(250).toNanos(), TimeUnit.NANOSECONDS))
        .thenReturn(true);
    worker.stop();
    verify(scheduled).cancel(false);
    verify(executor).shutdown();
    verify(executor).awaitTermination(Duration.ofMillis(250).toNanos(), TimeUnit.NANOSECONDS);
    verify(executor, never()).shutdownNow();
  }

  @Test
  void forcesShutdownAfterTheConfiguredBound() throws Exception {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    @SuppressWarnings("unchecked")
    ScheduledFuture<?> scheduled = mock(ScheduledFuture.class);
    when(executor.scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any()))
        .thenAnswer(call -> scheduled);
    when(executor.awaitTermination(Duration.ofMillis(200).toNanos(), TimeUnit.NANOSECONDS))
        .thenReturn(false);
    AdmissionConfirmationWorker worker = new AdmissionConfirmationWorker(
        () -> Outcome.IDLE, executor, Duration.ofMillis(100), Duration.ofMillis(200));

    worker.start();
    worker.stop();
    worker.stop();

    verify(scheduled).cancel(false);
    verify(scheduled).cancel(true);
    verify(executor).shutdown();
    verify(executor).shutdownNow();
    verify(executor, times(1)).awaitTermination(Duration.ofMillis(200).toNanos(), TimeUnit.NANOSECONDS);
  }

  @Test
  void schedulingFailureShutsDownExecutorAndWorkerCannotRestart() {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    when(executor.scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any()))
        .thenThrow(new IllegalStateException("synthetic scheduling failure"));
    AdmissionConfirmationWorker worker = new AdmissionConfirmationWorker(
        () -> Outcome.IDLE, executor, Duration.ofMillis(100), Duration.ofMillis(200));

    assertThrows(IllegalStateException.class, worker::start);
    verify(executor).shutdownNow();
    assertThrows(IllegalStateException.class, worker::start);
  }
}
