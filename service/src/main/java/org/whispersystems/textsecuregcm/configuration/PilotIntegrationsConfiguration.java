// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

/** Owned external integrations must be explicitly enabled in the private GCP pilot. */
public record PilotIntegrationsConfiguration(boolean apnsEnabled, boolean fcmEnabled,
                                             boolean storageEnabled, boolean svr2Enabled) {
  public static final PilotIntegrationsConfiguration DISABLED =
      new PilotIntegrationsConfiguration(false, false, false, false);
}
