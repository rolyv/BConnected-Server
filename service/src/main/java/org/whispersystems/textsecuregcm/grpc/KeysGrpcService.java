/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.grpc;

import io.grpc.StatusRuntimeException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import org.signal.chat.errors.NotFound;
import org.signal.chat.keys.GetPreKeyCountRequest;
import org.signal.chat.keys.GetPreKeyCountResponse;
import org.signal.chat.keys.GetPreKeysRequest;
import org.signal.chat.keys.GetPreKeysResponse;
import org.signal.chat.keys.SetEcSignedPreKeyRequest;
import org.signal.chat.keys.SetKemLastResortPreKeyRequest;
import org.signal.chat.keys.SetOneTimeEcPreKeysRequest;
import org.signal.chat.keys.SetOneTimeKemSignedPreKeysRequest;
import org.signal.chat.keys.SetPreKeyResponse;
import org.signal.chat.keys.SimpleKeysGrpc;
import org.signal.libsignal.protocol.IdentityKey;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionKeyGuard;
import org.whispersystems.textsecuregcm.storage.AdmittedKeysPostgres;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticationUtil;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.RateLimitKeys;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.KeysManager;

public class KeysGrpcService extends SimpleKeysGrpc.KeysImplBase {

  private final AccountsManager accountsManager;
  private final KeysManager keysManager;
  private final RateLimiters rateLimiters;
  private final AdmissionEntitlementGate admissionGate;
  private final AdmittedKeysPostgres admittedKeys;

  private static final StatusRuntimeException INVALID_PUBLIC_KEY_EXCEPTION =
      GrpcExceptions.fieldViolation("pre_keys", "invalid public key");

  private static final StatusRuntimeException INVALID_SIGNATURE_EXCEPTION =
      GrpcExceptions.fieldViolation("pre_keys", "pre-key signature did not match account identity key");

  public KeysGrpcService(final AccountsManager accountsManager,
      final KeysManager keysManager,
      final RateLimiters rateLimiters) {

    this(accountsManager, keysManager, rateLimiters, null, null);
  }

  public KeysGrpcService(AccountsManager accountsManager, KeysManager keysManager, RateLimiters rateLimiters,
      AdmissionEntitlementGate admissionGate, AdmittedKeysPostgres admittedKeys) {
    this.admissionGate = admissionGate; this.admittedKeys = admittedKeys;
    this.accountsManager = accountsManager;
    this.keysManager = keysManager;
    this.rateLimiters = rateLimiters;
  }

  @Override
  public GetPreKeyCountResponse getPreKeyCount(final GetPreKeyCountRequest request) {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) return admitted(authenticatedDevice, guard -> {
      final var aci = admittedKeys.count(guard, IdentityType.ACI);
      final var pni = guard.account().getPhoneNumberIdentifier().isPresent()
          ? admittedKeys.count(guard, IdentityType.PNI)
          : CompletableFuture.completedFuture(new org.whispersystems.textsecuregcm.entities.PreKeyCount(0, 0));
      CompletableFuture.allOf(aci, pni).join();
      return GetPreKeyCountResponse.newBuilder().setAciEcPreKeyCount(aci.join().getCount())
          .setAciKemPreKeyCount(aci.join().getPqCount()).setPniEcPreKeyCount(pni.join().getCount())
          .setPniKemPreKeyCount(pni.join().getPqCount()).build();
    });

    final Account account = getAuthenticatedAccount(authenticatedDevice.accountIdentifier());

    final UUID aci = account.getAccountIdentifier();

    final CompletableFuture<Integer> aciEcKeyCountFuture =
        keysManager.getEcCount(aci, authenticatedDevice.deviceId());

    final CompletableFuture<Integer> pniEcKeyCountFuture = account.getPhoneNumberIdentifier()
        .map(pni -> keysManager.getEcCount(pni, authenticatedDevice.deviceId()))
        .orElseGet(() -> CompletableFuture.completedFuture(0));

    final CompletableFuture<Integer> aciKemKeyCountFuture =
        keysManager.getPqCount(aci, authenticatedDevice.deviceId());

    final CompletableFuture<Integer> pniKemKeyCountFuture = account.getPhoneNumberIdentifier()
        .map(pni -> keysManager.getPqCount(pni, authenticatedDevice.deviceId()))
        .orElseGet(() -> CompletableFuture.completedFuture(0));

    CompletableFuture.allOf(aciEcKeyCountFuture, pniEcKeyCountFuture, aciKemKeyCountFuture, pniKemKeyCountFuture).join();

    return GetPreKeyCountResponse.newBuilder()
        .setAciEcPreKeyCount(aciEcKeyCountFuture.resultNow())
        .setPniEcPreKeyCount(pniEcKeyCountFuture.resultNow())
        .setAciKemPreKeyCount(aciKemKeyCountFuture.resultNow())
        .setPniKemPreKeyCount(pniKemKeyCountFuture.resultNow())
        .build();
  }

  @Override
  public GetPreKeysResponse getPreKeys(final GetPreKeysRequest request) throws RateLimitExceededException {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) {
      try {
        final var source = AdmissionKeyGuard.grpc(admissionGate, authenticatedDevice);
        final var identifier = GrpcServiceIdentifierUtil.fromGrpcServiceIdentifier(request.getTargetIdentifier());
        if (request.hasDeviceId() && DeviceIdUtil.validate(request.getDeviceId()) != Device.PRIMARY_ID)
          return GetPreKeysResponse.newBuilder().setTargetNotFound(NotFound.getDefaultInstance()).build();
        final var cached = accountsManager.getByServiceIdentifier(identifier);
        if (cached.isEmpty()) return GetPreKeysResponse.newBuilder().setTargetNotFound(NotFound.getDefaultInstance()).build();
        final var guard = source.forTarget(cached.orElseThrow().getAccountIdentifier(), identifier);
        final var target = guard.account();
        final var registration = identifier.identityType() == IdentityType.ACI
            ? Optional.of(target.getPrimaryDevice().getAccountRegistrationId())
            : target.getPrimaryDevice().getPhoneNumberIdentityRegistrationId();
        rateLimiters.getPreKeysLimiter().validate(RateLimitKeys.preKeyLimiterKey(authenticatedDevice.accountIdentifier(),
            authenticatedDevice.deviceId(), identifier, request.hasDeviceId() ? Optional.of(Device.PRIMARY_ID) : Optional.empty(),
            request.hasDeviceId() ? registration : Optional.empty()));
        final var keys = admittedKeys.take(guard, identifier.identityType()).join();
        final var response = keys.map(bundle -> GetPreKeysResponse.newBuilder()
                .setPreKeys(KeysGrpcHelper.bundle(target, identifier, java.util.Map.of(Device.PRIMARY_ID, bundle))).build())
            .orElseGet(() -> GetPreKeysResponse.newBuilder().setTargetNotFound(NotFound.getDefaultInstance()).build());
        guard.requireCurrent();
        return response;
      } catch (AdmissionKeyGuard.Failure failure) { return fetchFailure(failure); }
      catch (java.util.concurrent.CompletionException failure) { return fetchFailure(AdmissionKeyGuard.failure(failure)); }
    }


    final ServiceIdentifier targetIdentifier =
        GrpcServiceIdentifierUtil.fromGrpcServiceIdentifier(request.getTargetIdentifier());


    final Optional<Account> maybeTargetAccount = accountsManager.getByServiceIdentifier(targetIdentifier);

    final byte deviceId = request.hasDeviceId()
        ? DeviceIdUtil.validate(request.getDeviceId())
        : KeysGrpcHelper.ALL_DEVICES;

    final Optional<Integer> targetRegistrationId = maybeTargetAccount
        .filter(_ -> request.hasDeviceId())
        .flatMap(targetAccount -> targetAccount.getDevice(deviceId))
        .flatMap(device -> switch (targetIdentifier.identityType()) {
          case ACI -> Optional.of(device.getAccountRegistrationId());
          case PNI -> device.getPhoneNumberIdentityRegistrationId();
        });

    final String rateLimitKey = RateLimitKeys.preKeyLimiterKey(
        authenticatedDevice.accountIdentifier(),
        authenticatedDevice.deviceId(),
        targetIdentifier,
        Optional.ofNullable(request.hasDeviceId() ? deviceId : null),
        targetRegistrationId);

    rateLimiters.getPreKeysLimiter().validate(rateLimitKey);

    return maybeTargetAccount
        .flatMap(targetAccount -> KeysGrpcHelper.getPreKeys(targetAccount, targetIdentifier, deviceId, keysManager))
        .map(accountPreKeyBundles -> GetPreKeysResponse.newBuilder()
            .setPreKeys(accountPreKeyBundles)
            .build())
        .orElseGet(() -> GetPreKeysResponse.newBuilder()
            .setTargetNotFound(NotFound.getDefaultInstance())
            .build());
  }

  @Override
  public SetPreKeyResponse setOneTimeEcPreKeys(final SetOneTimeEcPreKeysRequest request) {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) return admitted(authenticatedDevice, guard -> {
      final var identity = IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType());
      final var keys = request.getPreKeysList().stream()
          .map(key -> KeysGrpcHelper.checkEcPreKey(key, INVALID_PUBLIC_KEY_EXCEPTION)).toList();
      admittedKeys.publish(guard, identity, keys, null, null, null).join();
      return SetPreKeyResponse.getDefaultInstance();
    });


    storeOneTimePreKeys(authenticatedDevice.accountIdentifier(),
        request.getPreKeysList(),
        IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType()),
        (requestPreKey, _) -> KeysGrpcHelper.checkEcPreKey(requestPreKey, INVALID_PUBLIC_KEY_EXCEPTION),
        (identifier, preKeys) -> keysManager.storeEcOneTimePreKeys(identifier, authenticatedDevice.deviceId(), preKeys));

    return SetPreKeyResponse.getDefaultInstance();
  }

  @Override
  public SetPreKeyResponse setOneTimeKemSignedPreKeys(final SetOneTimeKemSignedPreKeysRequest request) {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) return admitted(authenticatedDevice, guard -> {
      final var identity = IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType());
      final var identityKey = identityKey(guard.account(), identity);
      final var keys = request.getPreKeysList().stream()
          .map(key -> KeysGrpcHelper.checkKemSignedPreKey(key, identityKey, INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION)).toList();
      admittedKeys.publish(guard, identity, null, null, keys, null).join();
      return SetPreKeyResponse.getDefaultInstance();
    });


    storeOneTimePreKeys(authenticatedDevice.accountIdentifier(),
        request.getPreKeysList(),
        IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType()),
        (preKey, identityKey) -> KeysGrpcHelper.checkKemSignedPreKey(preKey, identityKey, INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION),
        (identifier, preKeys) -> keysManager.storeKemOneTimePreKeys(identifier, authenticatedDevice.deviceId(), preKeys));

    return SetPreKeyResponse.getDefaultInstance();
  }

  private <K, R> void storeOneTimePreKeys(final UUID authenticatedAccountUuid,
      final List<R> requestPreKeys,
      final IdentityType identityType,
      final BiFunction<R, IdentityKey, K> extractPreKeyFunction,
      final BiFunction<UUID, List<K>, CompletableFuture<Void>> storeKeysFunction) {

    final Account account = getAuthenticatedAccount(authenticatedAccountUuid);

    final IdentityKey identityKey = switch (identityType) {
      case ACI -> account.getAccountIdentityKey();
      case PNI -> account.getPhoneNumberIdentityKey()
          .orElseThrow(() -> new IllegalArgumentException("Account does not have a PNI identity key"));
    };

    final UUID identifier = getIdentifier(account, identityType);

    final List<K> preKeys = requestPreKeys.stream()
        .map(requestPreKey -> extractPreKeyFunction.apply(requestPreKey, identityKey))
        .toList();

    storeKeysFunction.apply(identifier, preKeys).join();
  }

  @Override
  public SetPreKeyResponse setEcSignedPreKey(final SetEcSignedPreKeyRequest request) {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) return admitted(authenticatedDevice, guard -> {
      final var identity = IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType());
      final var key = KeysGrpcHelper.checkEcSignedPreKey(request.getSignedPreKey(), identityKey(guard.account(), identity),
          INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION);
      admittedKeys.publish(guard, identity, null, key, null, null).join();
      return SetPreKeyResponse.getDefaultInstance();
    });


    storeRepeatedUseKey(authenticatedDevice.accountIdentifier(),
        IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType()),
        request.getSignedPreKey(),
        (preKey, identityKey) -> KeysGrpcHelper.checkEcSignedPreKey(preKey, identityKey, INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION),
        (identifier, signedPreKey) -> keysManager.storeEcSignedPreKeys(identifier, authenticatedDevice.deviceId(), signedPreKey));

    return SetPreKeyResponse.getDefaultInstance();
  }

  @Override
  public SetPreKeyResponse setKemLastResortPreKey(final SetKemLastResortPreKeyRequest request) {
    final AuthenticatedDevice authenticatedDevice = AuthenticationUtil.requireAuthenticatedDevice();
    if (admissionGate != null) return admitted(authenticatedDevice, guard -> {
      final var identity = IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType());
      final var key = KeysGrpcHelper.checkKemSignedPreKey(request.getSignedPreKey(), identityKey(guard.account(), identity),
          INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION);
      admittedKeys.publish(guard, identity, null, null, null, key).join();
      return SetPreKeyResponse.getDefaultInstance();
    });


    storeRepeatedUseKey(authenticatedDevice.accountIdentifier(),
        IdentityTypeUtil.fromGrpcIdentityType(request.getIdentityType()),
        request.getSignedPreKey(),
        (preKey, identityKey) -> KeysGrpcHelper.checkKemSignedPreKey(preKey, identityKey, INVALID_PUBLIC_KEY_EXCEPTION, INVALID_SIGNATURE_EXCEPTION),
        (identifier, lastResortKey) -> keysManager.storePqLastResort(identifier, authenticatedDevice.deviceId(), lastResortKey));

    return SetPreKeyResponse.getDefaultInstance();
  }

  private <K, R> void storeRepeatedUseKey(final UUID authenticatedAccountUuid,
      final IdentityType identityType,
      final R storeKeyRequest,
      final BiFunction<R, IdentityKey, K> extractKeyFunction,
      final BiFunction<UUID, K, CompletableFuture<Void>> storeKeyFunction) {

    final Account account = getAuthenticatedAccount(authenticatedAccountUuid);
    final IdentityKey identityKey = switch (identityType) {
      case ACI -> account.getAccountIdentityKey();
      case PNI -> account.getPhoneNumberIdentityKey()
          .orElseThrow(() -> GrpcExceptions.invalidArguments("account does not have a PNI identity key"));
    };

    final UUID identifier = getIdentifier(account, identityType);
    final K key = extractKeyFunction.apply(storeKeyRequest, identityKey);

    storeKeyFunction.apply(identifier, key).join();
  }

  private static IdentityKey identityKey(Account account, IdentityType type) {
    return type == IdentityType.ACI ? account.getAccountIdentityKey() : account.getPhoneNumberIdentityKey()
        .orElseThrow(() -> GrpcExceptions.invalidArguments("Account has no PNI identity key"));
  }
  private static GetPreKeysResponse fetchFailure(AdmissionKeyGuard.Failure failure) {
    if (failure.targetDenied()) return GetPreKeysResponse.newBuilder().setTargetNotFound(NotFound.getDefaultInstance()).build();
    throw failure.grpc();
  }
  private <T> T admitted(AuthenticatedDevice principal, java.util.function.Function<AdmissionKeyGuard, T> operation) {
    try {
      final var guard = AdmissionKeyGuard.grpc(admissionGate, principal);
      final var result = operation.apply(guard);
      guard.requireCurrent();
      return result;
    } catch (AdmissionKeyGuard.Failure failure) { throw failure.grpc(); }
    catch (java.util.concurrent.CompletionException failure) { throw AdmissionKeyGuard.failure(failure).grpc(); }
  }

  private Account getAuthenticatedAccount(final UUID authenticatedAccountId) {
    return accountsManager.getByAccountIdentifier(authenticatedAccountId)
        .orElseThrow(() -> GrpcExceptions.invalidCredentials("invalid credentials"));
  }

  /// Get the identity of the requested `idenityType`, or throw an invalid arguments status if `account` does not
  /// contain that type.
  private static UUID getIdentifier(Account account, IdentityType identityType) {
    return switch (identityType) {
      case ACI -> account.getAccountIdentifier();
      case PNI -> account.getPhoneNumberIdentifier()
          .orElseThrow(() -> GrpcExceptions.invalidArguments("PNI identity type not allowed for an account without a phone number"));
    };
  }

}
