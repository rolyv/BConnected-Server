// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import java.util.List;
import java.util.Optional;
import org.whispersystems.textsecuregcm.storage.Account;

/** Persistence for already-validated App Attest data; validation remains in the manager. */
public interface AppleDeviceCheckStore {
  /** Returns only the key IDs associated with this account. */
  List<byte[]> keyIds(Account account);

  /**
   * Stores a validated attestation when its counter is at least the current value; returns false
   * for an older counter. Equal counters may replace an attestation. Public-key ownership is global
   * across accounts and survives replacement under a key ID. A duplicate ownership failure must
   * roll back the entire attestation write.
   */
  boolean storeAttestation(Account account, byte[] keyId, DCAppleDevice appleDevice)
      throws DuplicatePublicKeyException;

  Optional<DCAppleDevice> lookup(Account account, byte[] keyId);

  /** Updates an existing counter only when it does not decrease; equality is accepted. */
  boolean updateCounter(Account account, byte[] keyId, long newCounter);
}
