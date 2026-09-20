// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.time.Duration;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Scheduler;

/** Account persistence; related key and recovery mutations share its commit boundary. */
public interface AccountStore {
  boolean createWithMutations(Account account, Collection<AccountMutation> mutations)
      throws AccountAlreadyExistsException;

  boolean createWithMutations(
      Account account,
      ReceiptCredentialPresentation receipt,
      byte[] recoveryPassword,
      Collection<AccountMutation> mutations)
      throws AccountAlreadyExistsException, ReceiptAlreadyRedeemedException;

  CompletionStage<Void> reclaimWithMutations(
      Account previous, Account replacement, Collection<AccountMutation> mutations);

  void updateWithMutations(Account account, Collection<AccountMutation> mutations);

  void changeNumberWithMutations(
      Account account,
      String number,
      UUID pni,
      Optional<UUID> displaced,
      Collection<AccountMutation> mutations);

  void deleteWithMutations(UUID aci, Collection<AccountMutation> mutations);

  AccountMutation linkDeviceMutation(String token, Duration ttl);

  void update(Account account);

  void reserveUsernameHash(Account account, byte[] hash, Duration ttl)
      throws UsernameHashNotAvailableException;

  void confirmUsernameHash(Account account, byte[] hash, byte[] encryptedUsername)
      throws UsernameHashNotAvailableException;

  void clearUsernameHash(Account account);

  Optional<Account> getByE164(String number);

  CompletableFuture<Optional<Account>> getByE164Async(String number);

  Optional<Account> getByPhoneNumberIdentifier(UUID pni);

  CompletableFuture<Optional<Account>> getByPhoneNumberIdentifierAsync(UUID pni);

  Optional<Account> getByAccountIdentifier(UUID aci);

  CompletableFuture<Optional<Account>> getByAccountIdentifierAsync(UUID aci);

  CompletableFuture<Optional<Account>> getByUsernameHash(byte[] hash);

  CompletableFuture<Optional<Account>> getByUsernameLinkHandle(UUID handle);

  boolean accountExists(UUID aci);

  Optional<UUID> findRecentlyDeletedAccountIdentifier(UUID pni);

  Optional<UUID> findRecentlyDeletedPhoneNumberIdentifier(UUID aci);

  Flux<Account> getAll(int segments, Scheduler scheduler);

  Flux<UUID> getAllAccountIdentifiers(int segments, Scheduler scheduler);

  CompletableFuture<Void> regenerateConstraints(Account account);
}
