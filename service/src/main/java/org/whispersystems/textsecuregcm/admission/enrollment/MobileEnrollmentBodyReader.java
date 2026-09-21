// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import java.io.InputStream;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import org.whispersystems.textsecuregcm.util.BoundedVirtualThreadFactory;

/** Bounded wire-read/parse work; caller latency does not depend on a cooperative request stream. */
public final class MobileEnrollmentBodyReader implements AutoCloseable {
  private final ExecutorService executor;
  private final long timeoutNanos;

  public MobileEnrollmentBodyReader(Duration timeout, int concurrency) {
    if (timeout == null || timeout.isNegative() || timeout.isZero()
        || timeout.compareTo(Duration.ofSeconds(10)) > 0 || concurrency < 1 || concurrency > 64)
      throw new IllegalArgumentException("Bounded enrollment body reader required");
    timeoutNanos = timeout.toNanos();
    executor = Executors.newThreadPerTaskExecutor(new BoundedVirtualThreadFactory("enrollment-body", concurrency));
  }

  public static final class Unavailable extends RuntimeException {
    private Unavailable() { super("Enrollment body unavailable"); }
  }

  public MobileEnrollmentRequest read(InputStream body, MobileEnrollmentParser.Operation operation, String number) {
    Objects.requireNonNull(body);
    final Future<MobileEnrollmentRequest> read;
    long started = System.nanoTime();
    try {
      read = executor.submit(() -> {
        try (body) { return MobileEnrollmentParser.parse(body, operation, number); }
      });
    } catch (RejectedExecutionException rejected) { throw new Unavailable(); }
    try {
      long remaining = timeoutNanos - (System.nanoTime() - started);
      if (remaining <= 0) throw new TimeoutException();
      return read.get(remaining, TimeUnit.NANOSECONDS);
    } catch (ExecutionException failure) {
      if (failure.getCause() instanceof MobileEnrollmentParser.InvalidRequestException invalid) throw invalid;
      throw new Unavailable();
    } catch (TimeoutException | InterruptedException unavailable) {
      read.cancel(true);
      if (unavailable instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new Unavailable();
    }
  }

  /** Never wait indefinitely for an uncooperative client stream. Servlet read timeout is still required. */
  @Override public void close() { executor.shutdownNow(); }
}
