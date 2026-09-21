/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Objects;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.Pair;
import org.whispersystems.textsecuregcm.util.Util;

public class AccountAuthenticator implements Authenticator<BasicCredentials, AuthenticatedDevice> {

  private static final String AUTHENTICATION_COUNTER_NAME = name(AccountAuthenticator.class, "authentication");
  private static final String AUTHENTICATION_SUCCEEDED_TAG_NAME = "succeeded";
  private static final String AUTHENTICATION_FAILURE_REASON_TAG_NAME = "reason";

  private static final String DAYS_SINCE_LAST_SEEN_DISTRIBUTION_NAME = name(AccountAuthenticator.class, "daysSinceLastSeen");
  private static final String IS_PRIMARY_DEVICE_TAG = "isPrimary";

  @VisibleForTesting
  static final char DEVICE_ID_SEPARATOR = '.';

  private final AccountsManager accountsManager;
  private final Clock clock;
  private final AdmissionEntitlementGate admissionGate;

  public AccountAuthenticator(AccountsManager accountsManager) {
    this(accountsManager, Clock.systemUTC());
  }

  @VisibleForTesting
  public AccountAuthenticator(AccountsManager accountsManager, Clock clock) {
    this.accountsManager = accountsManager;
    this.clock = clock;
    this.admissionGate = null;
  }

  /**
   * The pilot has no cache-backed credential fallback and permits only its primary iPhone.
   * Activity writes are deliberately deferred: changing lastSeen/version would invalidate the
   * full-row authorization snapshot. Re-fetching entitlement after that write would silently
   * replace the original freshness budget. This also means idle/lastSeen consumers remain stale
   * until a separately guarded activity transition is implemented.
   */
  public static AccountAuthenticator withAdmission(final AdmissionEntitlementGate admissionGate) {
    return new AccountAuthenticator(Objects.requireNonNull(admissionGate));
  }

  private AccountAuthenticator(final AdmissionEntitlementGate admissionGate) {
    this.accountsManager = null;
    this.clock = Clock.systemUTC();
    this.admissionGate = admissionGate;
  }

  static Pair<String, Byte> getIdentifierAndDeviceId(final String basicUsername) {
    final String identifier;
    final byte deviceId;

    final int deviceIdSeparatorIndex = basicUsername.indexOf(DEVICE_ID_SEPARATOR);

    if (deviceIdSeparatorIndex == -1) {
      identifier = basicUsername;
      deviceId = Device.PRIMARY_ID;
    } else {
      identifier = basicUsername.substring(0, deviceIdSeparatorIndex);
      deviceId = Byte.parseByte(basicUsername.substring(deviceIdSeparatorIndex + 1));
    }

    return new Pair<>(identifier, deviceId);
  }

  @Override
  public Optional<AuthenticatedDevice> authenticate(BasicCredentials basicCredentials) {
    boolean succeeded = false;
    String failureReason = null;

    try {
      final UUID accountUuid;
      final byte deviceId;
      {
        final Pair<String, Byte> identifierAndDeviceId = getIdentifierAndDeviceId(basicCredentials.getUsername());

        accountUuid = UUID.fromString(identifierAndDeviceId.first());
        deviceId = identifierAndDeviceId.second();
      }

      if (admissionGate != null) {
        if (deviceId != Device.PRIMARY_ID) {
          failureReason = "pilotPrimaryDeviceRequired";
          return Optional.empty();
        }
        final AdmissionEntitlementGate.DeviceAuthorization authorization =
            admissionGate.authorizeDevice(accountUuid, deviceId, basicCredentials.getPassword());
        final AuthenticatedDevice principal = new AuthenticatedDevice(accountUuid, deviceId,
            authorization.primaryDeviceLastSeen(), authorization);
        // Principal construction and any intervening wait consume the same lease. Never renew it.
        principal.requireCurrentEntitlement();
        succeeded = true;
        return Optional.of(principal);
      }

      Optional<Account> account = accountsManager.getByAccountIdentifier(accountUuid);

      if (account.isEmpty()) {
        failureReason = "noSuchAccount";
        return Optional.empty();
      }

      Optional<Device> device = account.get().getDevice(deviceId);

      if (device.isEmpty()) {
        failureReason = "noSuchDevice";
        return Optional.empty();
      }

      SaltedTokenHash deviceSaltedTokenHash = device.get().getAuthTokenHash();
      if (deviceSaltedTokenHash.verify(basicCredentials.getPassword())) {
        succeeded = true;
        final Account authenticatedAccount = updateLastSeen(account.get(), device.get());
        return Optional.of(new AuthenticatedDevice(authenticatedAccount.getAccountIdentifier(),
            device.get().getId(),
            Instant.ofEpochMilli(authenticatedAccount.getPrimaryDevice().getLastSeen())));
      } else {
        failureReason = "incorrectPassword";
        return Optional.empty();
      }
    } catch (AdmissionEntitlementGate.UnavailableException | AdmissionServiceClient.AdmissionServiceException unavailable) {
      failureReason = "admissionUnavailable";
      // Remote DENIED also includes IAM errors and rate limits; it is not bad-device proof.
      throw new AuthenticationUnavailableException();
    } catch (AdmissionEntitlementGate.DeniedException denied) {
      failureReason = "admissionDenied";
      return Optional.empty();
    } catch (IllegalArgumentException | InvalidAuthorizationHeaderException iae) {
      failureReason = "invalidHeader";
      return Optional.empty();
    } finally {
      Tags tags = Tags.of(
          AUTHENTICATION_SUCCEEDED_TAG_NAME, String.valueOf(succeeded));

      if (StringUtils.isNotBlank(failureReason)) {
        tags = tags.and(AUTHENTICATION_FAILURE_REASON_TAG_NAME, failureReason);
      }

      Metrics.counter(AUTHENTICATION_COUNTER_NAME, tags).increment();
    }
  }

  @VisibleForTesting
  public Account updateLastSeen(Account account, Device device) {
    if (admissionGate != null) {
      throw new IllegalStateException("Pilot activity writes require a guarded admission transition");
    }
    // compute a non-negative integer between 0 and 86400.
    long n = Util.ensureNonNegativeLong(account.getAccountIdentifier().getLeastSignificantBits());
    final long lastSeenOffsetSeconds = n % ChronoUnit.DAYS.getDuration().toSeconds();

    // produce a truncated timestamp which is either today at UTC midnight
    // or yesterday at UTC midnight, based on per-user randomized offset used.
    final long todayInMillisWithOffset = Util.todayInMillisGivenOffsetFromNow(clock,
        Duration.ofSeconds(lastSeenOffsetSeconds).negated());

    // only update the device's last seen time when it falls behind the truncated timestamp.
    // this ensures a few things:
    //   (1) each account will only update last-seen at most once per day
    //   (2) these updates will occur throughout the day rather than all occurring at UTC midnight.
    if (device.getLastSeen() < todayInMillisWithOffset) {
      Metrics.summary(DAYS_SINCE_LAST_SEEN_DISTRIBUTION_NAME, IS_PRIMARY_DEVICE_TAG, String.valueOf(device.isPrimary()))
          .record(Duration.ofMillis(todayInMillisWithOffset - device.getLastSeen()).toDays());

      return accountsManager.updateDeviceLastSeen(account.getAccountIdentifier(), device, Util.todayInMillis(clock));
    }

    return account;
  }
}
