// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import com.vdurmont.semver4j.Semver;
import java.util.Map;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

public interface ClientReleaseStore {
  /** Reads release metadata, including expired releases; the manager determines which versions are active. */
  Map<ClientPlatform, Map<Semver, ClientRelease>> getClientReleases();
}
