// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.monitoring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.timeout;

import jakarta.validation.constraints.Min;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.whispersystems.textsecuregcm.asn.AsnInfoProvider;
import org.whispersystems.textsecuregcm.asn.AsnInfoProviderImpl;
import org.whispersystems.textsecuregcm.configuration.MonitoredFileObjectConfiguration;
import org.whispersystems.textsecuregcm.configuration.ObjectMonitorFactory;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class FileObjectMonitorTest {
  @TempDir Path directory;
  private ScheduledExecutorService scheduler;
  private ScheduledFuture<?> scheduled;
  private AtomicReference<Runnable> refresh;

  @BeforeEach
  void setUp() {
    scheduler = mock(ScheduledExecutorService.class);
    scheduled = mock(ScheduledFuture.class);
    refresh = new AtomicReference<>();
    doAnswer(invocation -> {
      refresh.set(invocation.getArgument(0));
      return scheduled;
    }).when(scheduler).scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any());
  }

  private FileObjectMonitor monitor(final Path path, final long maxSize) {
    return new FileObjectMonitor(path, maxSize, scheduler, Duration.ofSeconds(1));
  }

  private String read(final InputStream stream) {
    try { return new String(stream.readAllBytes(), StandardCharsets.UTF_8); }
    catch (IOException e) { throw new UncheckedIOException(e); }
  }

  @Test
  void initialMissingNonRegularAndOversizeFilesFailBeforeScheduling() throws Exception {
    IllegalStateException missing = assertThrows(IllegalStateException.class,
        () -> monitor(directory.resolve("missing"), 8).start(this::read));
    assertThat(missing).hasMessageContaining("Cannot read initial monitored file").hasCauseInstanceOf(IOException.class);
    assertThrows(IllegalStateException.class, () -> monitor(directory, 8).start(this::read));
    Path oversized = Files.writeString(directory.resolve("oversize"), "123456789");
    assertThrows(IllegalStateException.class, () -> monitor(oversized, 8).start(this::read));
    verifyNoInteractions(scheduler);
  }

  @Test
  void refreshDetectsContentChangesEvenWithUnchangedSizeAndTimestamp() throws Exception {
    Path file = Files.writeString(directory.resolve("config"), "one");
    FileTime pinned = FileTime.fromMillis(1000);
    Files.setLastModifiedTime(file, pinned);
    var received = new ArrayList<String>();
    FileObjectMonitor monitor = monitor(file, 3);
    monitor.start(input -> received.add(read(input)));
    refresh.get().run();
    assertThat(received).containsExactly("one");
    Files.writeString(file, "two");
    Files.setLastModifiedTime(file, pinned);
    refresh.get().run();
    refresh.get().run();
    assertThat(received).containsExactly("one", "two");
    assertThrows(IllegalStateException.class, () -> monitor.start(this::read));
  }

  @Test
  void missingAndOversizeRefreshesRetainThePreviousValueAndRecover() throws Exception {
    Path file = Files.writeString(directory.resolve("config"), "good");
    AtomicReference<String> value = new AtomicReference<>();
    monitor(file, 4).start(input -> value.set(read(input)));
    Files.delete(file);
    refresh.get().run();
    assertThat(value).hasValue("good");
    Files.writeString(file, "too large");
    refresh.get().run();
    assertThat(value).hasValue("good");
    Files.writeString(file, "next");
    refresh.get().run();
    assertThat(value).hasValue("next");
  }

  @Test
  void atomicSecretSymlinkRotationIsObserved() throws Exception {
    Files.writeString(directory.resolve("version-one"), "first");
    Files.writeString(directory.resolve("version-two"), "second");
    Path mounted = directory.resolve("mounted-secret");
    Files.createSymbolicLink(mounted, Path.of("version-one"));
    AtomicReference<String> value = new AtomicReference<>();
    monitor(mounted, 10).start(input -> value.set(read(input)));
    Path replacement = Files.createSymbolicLink(directory.resolve("new-link"), Path.of("version-two"));
    Files.move(replacement, mounted, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    refresh.get().run();
    assertThat(value).hasValue("second");
  }

  @Test
  void stopCancelsOnlyItsTaskAndLeavesTheCallersSchedulerRunning() throws Exception {
    Path file = Files.writeString(directory.resolve("config"), "first");
    AtomicReference<String> value = new AtomicReference<>();
    FileObjectMonitor monitor = monitor(file, 10);
    monitor.start(input -> value.set(read(input)));
    monitor.stop();
    Files.writeString(file, "second");
    refresh.get().run();
    assertThat(value).hasValue("first");
    verify(scheduled).cancel(false);
    verify(scheduler, never()).shutdown();
    verify(scheduler, never()).shutdownNow();
  }

  public record TestConfiguration(@Min(1) int value) {}

  @Test
  void existingDynamicConfigurationValidationRetainsLastValidValue() throws Exception {
    Path file = Files.writeString(directory.resolve("dynamic.yml"), "value: 1");
    var manager = new DynamicConfigurationManager<>(monitor(file, 1024), TestConfiguration.class);
    manager.start();
    assertThat(manager.getConfiguration().value()).isEqualTo(1);
    Files.writeString(file, "value: invalid");
    refresh.get().run();
    assertThat(manager.getConfiguration().value()).isEqualTo(1);
    Files.writeString(file, "value: 0");
    refresh.get().run();
    assertThat(manager.getConfiguration().value()).isEqualTo(1);
    Files.writeString(file, "value: 2");
    refresh.get().run();
    assertThat(manager.getConfiguration().value()).isEqualTo(2);
  }

  @Test
  void asnSupplierUsesTheExistingGzipParserAndRetainsItsValidTable() throws Exception {
    Path file = directory.resolve("asn.tsv.gz");
    try (var output = new GZIPOutputStream(Files.newOutputStream(file))) {
      output.write("1.1.1.0\t1.1.1.255\t13335\tUS\tSynthetic test\n".getBytes(StandardCharsets.UTF_8));
    }
    var supplier = new MonitoringSupplier<AsnInfoProvider>(scheduler,
        new MonitoredFileObjectConfiguration(file.toString(), 1024L, Duration.ofSeconds(1)),
        AsnInfoProviderImpl::fromTsvGz, null, "file-monitor-test");
    supplier.start();
    AsnInfoProvider valid = supplier.get();
    assertThat(valid.lookup("1.1.1.1")).isPresent();
    assertThat(valid.lookup("1.1.1.1").orElseThrow().asn()).isEqualTo(13335);
    Files.writeString(file, "invalid gzip");
    refresh.get().run();
    assertThat(supplier.get()).isSameAs(valid);
    supplier.stop();
  }

  @Test
  void fileFactoryIsDiscoveredAndObsoleteS3ConfigurationIsRejected() throws Exception {
    ObjectMonitorFactory file = SystemMapper.yamlMapper().readValue("""
        type: file
        path: /mounted/config.yml
        maxSize: 1024
        refreshInterval: PT1S
        """, ObjectMonitorFactory.class);
    assertThat(file).isInstanceOf(MonitoredFileObjectConfiguration.class);
    assertThat(file.build(scheduler)).isInstanceOf(FileObjectMonitor.class);
    for (String legacy : new String[] {
        "s3Region: us-east-1\ns3Bucket: obsolete\nobjectKey: config.yml\n",
        "type: default\ns3Region: us-east-1\ns3Bucket: obsolete\nobjectKey: config.yml\n",
        "type: s3\ns3Region: us-east-1\ns3Bucket: obsolete\nobjectKey: config.yml\n",
        "path: /mounted/config.yml\n"}) {
      assertThrows(IOException.class, () -> SystemMapper.yamlMapper().readValue(legacy, ObjectMonitorFactory.class));
    }
    assertThrows(IllegalArgumentException.class,
        () -> new MonitoredFileObjectConfiguration("", null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new MonitoredFileObjectConfiguration("/config", 0L, Duration.ofSeconds(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new MonitoredFileObjectConfiguration("/config", 1024L, Duration.ZERO));
  }

  @Test
  void invalidInitialDynamicFileDoesNotBecomeReadyUntilAValidRefresh() throws Exception {
    Path file = Files.writeString(directory.resolve("initial-invalid.yml"), "value: 0");
    var manager = new DynamicConfigurationManager<>(monitor(file, 1024), TestConfiguration.class);
    CompletableFuture<Void> starting = CompletableFuture.runAsync(manager::start);
    try {
      verify(scheduler, timeout(1000)).scheduleWithFixedDelay(any(Runnable.class), anyLong(), anyLong(), any());
      assertThat(starting).isNotDone();
    } finally {
      Files.writeString(file, "value: 1");
      if (refresh.get() != null) refresh.get().run();
    }
    starting.get(1, TimeUnit.SECONDS);
    assertThat(manager.getConfiguration().value()).isEqualTo(1);
  }
}
