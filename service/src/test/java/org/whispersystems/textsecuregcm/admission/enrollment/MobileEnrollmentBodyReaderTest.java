// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.*;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class MobileEnrollmentBodyReaderTest {
  @Test void uncooperativeReadHasBoundedCallerDeadlineAndCannotQueueUnboundedWork() throws Exception {
    var release = new CountDownLatch(1);
    var reads = new AtomicInteger();
    InputStream blocked = new InputStream() {
      @Override public int read() {
        reads.incrementAndGet();
        while (true) {
          try { release.await(); return -1; }
          catch (InterruptedException ignored) { /* Deliberately uncooperative network fixture. */ }
        }
      }
    };
    try (var reader = new MobileEnrollmentBodyReader(Duration.ofMillis(50), 1)) {
      assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
        assertThrows(MobileEnrollmentBodyReader.Unavailable.class,
            () -> reader.read(blocked, MobileEnrollmentParser.Operation.BEGIN, "+13055550123"));
        assertThat(reads.get()).isEqualTo(1);
        assertThrows(MobileEnrollmentBodyReader.Unavailable.class,
            () -> reader.read(new ByteArrayInputStream(new byte[0]), MobileEnrollmentParser.Operation.BEGIN,
                "+13055550123"));
      });
    } finally { release.countDown(); }
  }

  @Test void oversizedBodyStopsAtSentinelAndClosesOwnedStream() {
    AtomicInteger bytes = new AtomicInteger();
    AtomicBoolean closed = new AtomicBoolean();
    InputStream endless = new InputStream() {
      @Override public int read() { bytes.incrementAndGet(); return ' '; }
      @Override public void close() { closed.set(true); }
    };
    try (var reader = new MobileEnrollmentBodyReader(Duration.ofSeconds(2), 1)) {
      assertThrows(MobileEnrollmentParser.InvalidRequestException.class,
          () -> reader.read(endless, MobileEnrollmentParser.Operation.BEGIN, "+13055550123"));
    }
    assertThat(bytes.get()).isEqualTo(65_537);
    assertThat(closed.get()).isTrue();
  }

  @Test void validBodyMapsActualRegistrationPayloadAndReaderShutdownRejectsWork() throws Exception {
    var reader = new MobileEnrollmentBodyReader(Duration.ofSeconds(2), 1);
    try (var body = getClass().getResourceAsStream("/admission/mobile-enrollment-v1.json")) {
      assertThat(reader.read(body, MobileEnrollmentParser.Operation.BEGIN, "+13055550123")
          .originalSignalAgent()).isEqualTo("BConnected-iOS");
    } finally { reader.close(); }
    assertThrows(MobileEnrollmentBodyReader.Unavailable.class,
        () -> reader.read(new ByteArrayInputStream(new byte[0]), MobileEnrollmentParser.Operation.BEGIN,
            "+13055550123"));
  }
}
