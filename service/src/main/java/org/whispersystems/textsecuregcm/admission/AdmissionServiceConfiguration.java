// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.net.URI;
import java.time.Duration;

/** Explicit single-service pin. This is not a general authenticated HTTP destination setting. */
public record AdmissionServiceConfiguration(URI origin, Duration requestTimeout) {
  public static final URI PILOT_ORIGIN =
      URI.create("https://bconnected-admission-mk5xfhz7jq-ue.a.run.app");

  public AdmissionServiceConfiguration {
    if ((origin == null || !PILOT_ORIGIN.toString().equals(origin.toString()))
        || requestTimeout == null
        || requestTimeout.isNegative()
        || requestTimeout.isZero()
        || requestTimeout.compareTo(Duration.ofSeconds(4)) > 0)
      throw new IllegalArgumentException("Invalid private admission service configuration");
  }

  public static AdmissionServiceConfiguration pilot() {
    return new AdmissionServiceConfiguration(PILOT_ORIGIN, Duration.ofSeconds(4));
  }

  @Override
  public String toString() {
    return "AdmissionServiceConfiguration[pinned pilot origin]";
  }
}
