// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import java.util.Set;

/** An explicit deployment capability boundary; remote flags cannot enable excluded infrastructure. */
public enum RuntimeMode {
  LEGACY,
  GCP_PILOT;

  private static final Set<String> PILOT_WORKERS = Set.of("message-persister-service");

  public void requireWorker(final String name) {
    if (this == GCP_PILOT && !PILOT_WORKERS.contains(name)) {
      throw new UnsupportedOperationException("Worker '" + name + "' is unavailable in GCP_PILOT mode");
    }
  }
}
