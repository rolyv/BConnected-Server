// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
public interface PhoneNumberIdentifierStore {
  CompletableFuture<UUID> getPhoneNumberIdentifier(String phoneNumber);
  CompletableFuture<List<String>> getPhoneNumber(UUID identifier);
  CompletableFuture<UUID> setPni(String originalPhoneNumber, List<String> allForms, UUID identifier);
  CompletableFuture<Void> regeneratePhoneNumberIdentifierMappings(Account account);
}
