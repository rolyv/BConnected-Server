// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.List;

public interface RemoteConfigStore {
  void set(RemoteConfig config);
  List<RemoteConfig> getAll();
  void delete(String name);
}
