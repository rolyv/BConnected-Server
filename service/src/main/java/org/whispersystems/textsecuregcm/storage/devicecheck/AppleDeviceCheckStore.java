// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import java.util.List;
import java.util.Optional;
import org.whispersystems.textsecuregcm.storage.Account;

/** Persistence for already-validated App Attest data; validation remains in the manager. */
public interface AppleDeviceCheckStore {
  List<byte[]> keyIds(Account account);
  boolean storeAttestation(Account account, byte[] keyId, DCAppleDevice appleDevice)
      throws DuplicatePublicKeyException;
  Optional<DCAppleDevice> lookup(Account account, byte[] keyId);
  boolean updateCounter(Account account, byte[] keyId, long newCounter);
}
