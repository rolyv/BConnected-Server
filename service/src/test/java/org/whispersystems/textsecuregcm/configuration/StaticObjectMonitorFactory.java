/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.whispersystems.textsecuregcm.monitoring.ObjectMonitor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

@JsonTypeName("static")
public class StaticObjectMonitorFactory implements ObjectMonitorFactory {

  @JsonProperty
  private String object = "";

  @JsonProperty
  private boolean gzip;

  @Override
  public ObjectMonitor build(final ScheduledExecutorService refreshExecutorService) {
    final byte[] bytes;
    if (gzip) {
      try (var output = new ByteArrayOutputStream()) {
        try (var compressed = new GZIPOutputStream(output)) {
          compressed.write(object.getBytes(StandardCharsets.UTF_8));
        }
        bytes = output.toByteArray();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    } else {
      bytes = object.getBytes(StandardCharsets.UTF_8);
    }
    return new ObjectMonitor() {
      @Override
      public void start(final Consumer<InputStream> listener) {
        try (var input = new ByteArrayInputStream(bytes)) {
          listener.accept(input);
        } catch (IOException e) {
          throw new UncheckedIOException(e);
        }
      }

      @Override
      public void stop() {}
    };
  }
}
