// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.util.Optional;
import java.util.UUID;
import org.whispersystems.textsecuregcm.auth.SaltedTokenHash;

public interface PhoneNumberRecoveryPasswordStore {
  Optional<SaltedTokenHash> lookup(UUID phoneNumberIdentifier);

  boolean addOrReplace(UUID phoneNumberIdentifier, SaltedTokenHash data);

  boolean removeEntry(UUID phoneNumberIdentifier);

  AccountMutation buildMutationForAddOrReplace(UUID phoneNumberIdentifier, SaltedTokenHash data);

  AccountMutation buildMutationForRemove(UUID phoneNumberIdentifier);

  AccountMutation buildConditionMutationForMigration(UUID phoneNumberIdentifier, SaltedTokenHash expectedPassword);
}
