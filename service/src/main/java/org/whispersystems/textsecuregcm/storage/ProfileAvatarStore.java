// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.Optional;

public interface ProfileAvatarStore {
  Optional<String> setAvatarUrl(byte[] identity, String url);
  Optional<String> updateAvatarTtl(byte[] identity);
  Optional<String> deleteAvatarUrl(byte[] identity);
}
