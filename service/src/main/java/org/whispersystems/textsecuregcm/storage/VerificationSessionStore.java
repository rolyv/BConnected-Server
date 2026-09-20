// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;
import java.util.Optional;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
public interface VerificationSessionStore {
  void insert(String key, VerificationSession session);
  void update(String key, VerificationSession session);
  Optional<VerificationSession> findForKey(String key);
  void remove(String key);
}
