// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.monitoring;

import java.io.InputStream;
import java.util.function.Consumer;

/** Supplies an initial object and refreshes it through the existing parser/validation consumer. */
public interface ObjectMonitor {
  void start(Consumer<InputStream> changeListener);

  void stop();
}
