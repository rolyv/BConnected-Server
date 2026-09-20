// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.s3;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Polls a mounted file, including atomically rotated secret-volume symlinks, without owning its scheduler. */
public final class FileObjectMonitor implements ObjectMonitor {
  private static final Logger logger = LoggerFactory.getLogger(FileObjectMonitor.class);
  private final Path path;
  private final int maxSize;
  private final ScheduledExecutorService executor;
  private final long refreshMillis;
  private ScheduledFuture<?> refreshFuture;
  private byte[] lastDigest;
  private boolean started;
  private boolean stopped;

  public FileObjectMonitor(final Path path, final long maxSize, final ScheduledExecutorService executor,
      final Duration refreshInterval) {
    this.path = Objects.requireNonNull(path).toAbsolutePath().normalize();
    if (maxSize < 1 || maxSize >= Integer.MAX_VALUE) throw new IllegalArgumentException("Invalid monitored file maximum size");
    this.maxSize = (int) maxSize;
    this.executor = Objects.requireNonNull(executor);
    this.refreshMillis = Objects.requireNonNull(refreshInterval).toMillis();
    if (refreshMillis < 1) throw new IllegalArgumentException("Monitored file refresh interval must be at least one millisecond");
  }

  @Override
  public synchronized void start(final Consumer<InputStream> changeListener) {
    Objects.requireNonNull(changeListener);
    if (started) throw new IllegalStateException("File object monitor already started");
    try {
      // Initial file access must succeed before scheduling. Do not silently substitute an empty configuration.
      refresh(changeListener);
    } catch (IOException e) {
      throw new IllegalStateException("Cannot read initial monitored file: " + path, e);
    }
    refreshFuture = executor.scheduleWithFixedDelay(() -> refreshSafely(changeListener),
        refreshMillis, refreshMillis, TimeUnit.MILLISECONDS);
    started = true;
  }

  private synchronized void refreshSafely(final Consumer<InputStream> changeListener) {
    if (stopped) return;
    try {
      refresh(changeListener);
    } catch (Exception e) {
      // Consumers retain their last successfully parsed value; leave the last digest intact on failed reads.
      logger.warn("Failed to refresh monitored file {}", path, e);
    }
  }

  private void refresh(final Consumer<InputStream> changeListener) throws IOException {
    // Follow the mount's current symlink target on every read, while rejecting directories and special files.
    if (!Files.isRegularFile(path)) throw new IOException("Monitored path is not a readable regular file: " + path);
    if (Files.size(path) > maxSize) throw new IOException("Monitored file exceeds configured maximum size: " + path);
    final byte[] bytes;
    try (InputStream input = Files.newInputStream(path)) {
      // The extra byte catches growth after the size check without allowing an unbounded read.
      bytes = input.readNBytes(maxSize + 1);
    }
    if (bytes.length > maxSize) throw new IOException("Monitored file exceeds configured maximum size: " + path);
    final byte[] digest;
    try {
      digest = MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
    if (Arrays.equals(lastDigest, digest)) return;
    try (InputStream input = new ByteArrayInputStream(bytes)) {
      changeListener.accept(input);
    }
    lastDigest = digest;
  }

  @Override
  public synchronized void stop() {
    if (refreshFuture != null) {
      stopped = true;
      refreshFuture.cancel(false);
    }
  }
}
