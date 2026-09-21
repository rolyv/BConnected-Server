/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.entities.ECPreKey;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.metrics.UserAgentTagUtil;
import org.whispersystems.textsecuregcm.util.Futures;
import org.whispersystems.textsecuregcm.util.Optionals;

public class KeysManager {
  // KeysController for backwards compatibility
  private static final String GET_KEYS_COUNTER_NAME = MetricsUtil.name(KeysManager.class, "getKeys");

  private final SingleUseECPreKeyStorage ecPreKeys;
  private final SingleUseKEMPreKeyStorage pagedPqPreKeys;
  private final SignedPreKeyStore<ECSignedPreKey> ecSignedPreKeys;
  private final SignedPreKeyStore<KEMSignedPreKey> pqLastResortKeys;

  private static final String  TAKE_PQ_NAME = MetricsUtil.name(KeysManager.class, "takePq");

  public KeysManager(
      final SingleUseECPreKeyStorage ecPreKeys,
      final SingleUseKEMPreKeyStorage pagedPqPreKeys,
      final SignedPreKeyStore<ECSignedPreKey> ecSignedPreKeys,
      final SignedPreKeyStore<KEMSignedPreKey> pqLastResortKeys) {
    this.ecPreKeys = ecPreKeys;
    this.pagedPqPreKeys = pagedPqPreKeys;
    this.ecSignedPreKeys = ecSignedPreKeys;
    this.pqLastResortKeys = pqLastResortKeys;
  }

  public AccountMutation buildWriteItemForEcSignedPreKey(final UUID identifier,
      final byte deviceId,
      final ECSignedPreKey ecSignedPreKey) {

    return ecSignedPreKeys.buildInsertion(identifier, deviceId, ecSignedPreKey);
  }

  public AccountMutation buildWriteItemForLastResortKey(final UUID identifier,
      final byte deviceId,
      final KEMSignedPreKey lastResortSignedPreKey) {

    return pqLastResortKeys.buildInsertion(identifier, deviceId, lastResortSignedPreKey);
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  public List<AccountMutation> buildWriteItemsForNewDevice(final UUID accountIdentifier,
      final Optional<UUID> maybePhoneNumberIdentifier,
      final byte deviceId,
      final ECSignedPreKey aciSignedPreKey,
      final Optional<ECSignedPreKey> maybePniSignedPreKey,
      final KEMSignedPreKey aciPqLastResortPreKey,
      final Optional<KEMSignedPreKey> maybePniPqLastResortPreKey) {
    final List<AccountMutation> writeItems = new ArrayList<>(buildWriteItemsForNewDevice(accountIdentifier, deviceId, aciSignedPreKey, aciPqLastResortPreKey));

    maybePhoneNumberIdentifier.ifPresent(pni ->
        writeItems.addAll(buildWriteItemsForNewDevice(pni, deviceId,
            maybePniSignedPreKey.orElseThrow(() -> new AssertionError("PNI signed pre key must be provided if PNI is present")),
            maybePniPqLastResortPreKey.orElseThrow(() -> new AssertionError("PNI PQ last resort pre key must be provided if PNI is present")))
        ));
    return writeItems;
  }

  private List<AccountMutation> buildWriteItemsForNewDevice(final UUID identifier,
      final byte deviceId,
      final ECSignedPreKey signedPreKey,
      final KEMSignedPreKey lastResortPreKey) {
    return List.of(
        ecSignedPreKeys.buildInsertion(identifier, deviceId, signedPreKey),
        pqLastResortKeys.buildInsertion(identifier, deviceId, lastResortPreKey)
    );
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  public List<AccountMutation> buildWriteItemsForRemovedDevice(final UUID accountIdentifier,
      final Optional<UUID> maybePhoneNumberIdentifier,
      final byte deviceId) {
    final List<AccountMutation> writeItems = new ArrayList<>(List.of(
        ecSignedPreKeys.buildDeletion(accountIdentifier, deviceId),
        pqLastResortKeys.buildDeletion(accountIdentifier, deviceId)
    ));

    maybePhoneNumberIdentifier.ifPresent(phoneNumberIdentifier -> writeItems.addAll(List.of(
        ecSignedPreKeys.buildDeletion(phoneNumberIdentifier, deviceId),
        pqLastResortKeys.buildDeletion(phoneNumberIdentifier, deviceId)))
    );

    return writeItems;
  }

  public CompletableFuture<Void> storeEcSignedPreKeys(final UUID identifier, final byte deviceId,
      final ECSignedPreKey ecSignedPreKey) {
    return ecSignedPreKeys.store(identifier, deviceId, ecSignedPreKey);
  }

  public CompletableFuture<Void> storePqLastResort(final UUID identifier, final byte deviceId,
      final KEMSignedPreKey lastResortKey) {
    return pqLastResortKeys.store(identifier, deviceId, lastResortKey);
  }

  public CompletableFuture<Void> storeEcOneTimePreKeys(final UUID identifier, final byte deviceId,
      final List<ECPreKey> preKeys) {
    return ecPreKeys.store(identifier, deviceId, preKeys);
  }

  public CompletableFuture<Void> storeKemOneTimePreKeys(final UUID identifier, final byte deviceId,
      final List<KEMSignedPreKey> preKeys) {
    return pagedPqPreKeys.store(identifier, deviceId, preKeys);

  }

  @VisibleForTesting
  CompletableFuture<Optional<ECPreKey>> takeEC(final UUID identifier, final byte deviceId) {
    return ecPreKeys.take(identifier, deviceId);
  }

  @VisibleForTesting
  CompletableFuture<Optional<KEMSignedPreKey>> takePQ(final UUID identifier, final byte deviceId) {
    return tagTakePQ(pagedPqPreKeys.take(identifier, deviceId), PQSource.PAGE)
        .thenCompose(maybeSingleUsePreKey -> maybeSingleUsePreKey
            .map(_ -> CompletableFuture.completedFuture(maybeSingleUsePreKey))
            .orElseGet(() -> tagTakePQ(pqLastResortKeys.find(identifier, deviceId), PQSource.LAST_RESORT)));
  }

  private enum PQSource {
    PAGE,
    LAST_RESORT
  }
  private CompletableFuture<Optional<KEMSignedPreKey>> tagTakePQ(CompletableFuture<Optional<KEMSignedPreKey>> prekey, final PQSource source) {
    return prekey.thenApply(maybeSingleUsePreKey -> {
      final Optional<String> maybeSourceTag = maybeSingleUsePreKey
          // If we found a PK, use this source tag
          .map(ignore -> source.name())
          // If we didn't and this is our last resort, we didn't find a PK
          .or(() -> source == PQSource.LAST_RESORT ? Optional.of("absent") : Optional.empty());
      maybeSourceTag.ifPresent(sourceTag -> {
        Metrics.counter(TAKE_PQ_NAME, "source", sourceTag).increment();
      });
      return maybeSingleUsePreKey;
    });
  }

  public CompletableFuture<Optional<KEMSignedPreKey>> getLastResort(final UUID identifier, final byte deviceId) {
    return pqLastResortKeys.find(identifier, deviceId);
  }

  public CompletableFuture<Optional<ECSignedPreKey>> getEcSignedPreKey(final UUID identifier, final byte deviceId) {
    return ecSignedPreKeys.find(identifier, deviceId);
  }

  public CompletableFuture<Integer> getEcCount(final UUID identifier, final byte deviceId) {
    return ecPreKeys.getCount(identifier, deviceId);
  }

  public CompletableFuture<Integer> getPqCount(final UUID identifier, final byte deviceId) {
    return pagedPqPreKeys.getCount(identifier, deviceId);
  }

  public CompletableFuture<Void> deleteSingleUsePreKeys(final UUID identifier) {
    return CompletableFuture.allOf(
        ecPreKeys.delete(identifier),
        pagedPqPreKeys.delete(identifier)
    );
  }

  public CompletableFuture<Void> deleteSingleUsePreKeys(final UUID accountUuid, final byte deviceId) {
    return CompletableFuture.allOf(
        ecPreKeys.delete(accountUuid, deviceId),
        pagedPqPreKeys.delete(accountUuid, deviceId)
    );
  }

  public record DevicePreKeys(
      ECSignedPreKey ecSignedPreKey,
      Optional<ECPreKey> ecPreKey,
      KEMSignedPreKey kemSignedPreKey) {}

  public CompletableFuture<Optional<DevicePreKeys>> takeDevicePreKeys(
      final byte deviceId,
      final ServiceIdentifier serviceIdentifier,
      final @Nullable String userAgent) {
    final UUID uuid = serviceIdentifier.uuid();
    return Futures.zipWith(
            this.takeEC(uuid, deviceId),
            this.getEcSignedPreKey(uuid, deviceId),
            this.takePQ(uuid, deviceId),
            (maybeUnsignedEcPreKey, maybeSignedEcPreKey, maybePqPreKey) -> {

              Metrics.counter(GET_KEYS_COUNTER_NAME, Tags.of(
                      UserAgentTagUtil.getPlatformTag(userAgent),
                      Tag.of("identityType", serviceIdentifier.identityType().name()),
                      Tag.of("oneTimeEcKeyAvailable", String.valueOf(maybeUnsignedEcPreKey.isPresent())),
                      Tag.of("signedEcKeyAvailable", String.valueOf(maybeSignedEcPreKey.isPresent())),
                      Tag.of("pqKeyAvailable", String.valueOf(maybePqPreKey.isPresent()))))
                  .increment();

              // The pq prekey and signed EC prekey should never be null for an existing account. This should only happen
              // if the account or device has been removed and the read was split, so we can return empty in those cases.
              return Optionals.zipWith(maybeSignedEcPreKey, maybePqPreKey, (signedEcPreKey, pqPreKey) ->
                  new DevicePreKeys(signedEcPreKey, maybeUnsignedEcPreKey, pqPreKey));
            })
        .toCompletableFuture();
  }
}
