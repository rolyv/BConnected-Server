// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import jakarta.validation.constraints.NotBlank;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import org.whispersystems.textsecuregcm.monitoring.FileObjectMonitor;

@JsonTypeName("file")
public record MonitoredFileObjectConfiguration(@NotBlank String path, Long maxSize, Duration refreshInterval)
    implements ObjectMonitorFactory {
  public MonitoredFileObjectConfiguration {
    if (path == null || path.isBlank()) throw new IllegalArgumentException("Monitored file path is required");
    if (maxSize == null) maxSize = 16L * 1024 * 1024;
    if (refreshInterval == null) refreshInterval = Duration.ofMinutes(5);
    if (maxSize < 1 || maxSize >= Integer.MAX_VALUE) throw new IllegalArgumentException("Invalid monitored file maximum size");
    if (refreshInterval.toMillis() < 1) throw new IllegalArgumentException("Invalid monitored file refresh interval");
  }

  @Override
  public FileObjectMonitor build(final ScheduledExecutorService refreshExecutorService) {
    return new FileObjectMonitor(Path.of(path), maxSize, refreshExecutorService, refreshInterval);
  }
}
