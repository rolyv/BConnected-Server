// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.auth;

import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;

/** Deployment policy for deferred account-management operations, independent of authentication. */
public enum AccountOperationsPolicy {
  STANDARD,
  PILOT_PRIMARY_ONLY;

  public void requireAnonymousDiscovery() { require("Anonymous account discovery"); }

  public void requireLinkedDevices() { require("Linked devices and device transfer"); }
  public void requirePhoneNumberChange() { require("Phone number changes"); }
  public void requireRecoveryPasswordChanges() { require("Recovery password changes"); }

  public void requireDeviceTarget(byte deviceId) {
    if (deviceId != org.whispersystems.textsecuregcm.storage.Device.PRIMARY_ID) requireLinkedDevices();
  }

  private void require(String feature) {
    if (this == PILOT_PRIMARY_ONLY) throw new FeatureUnavailableException(feature);
  }
}
