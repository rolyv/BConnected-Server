// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration;

import com.google.i18n.phonenumbers.Phonenumber;
import io.dropwizard.lifecycle.Managed;
import java.time.Duration;
import java.util.Optional;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.VerificationSessionRateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;

/** Phone possession verification behind the existing registration admission controls. */
public interface RegistrationService extends Managed {
  RegistrationServiceSession createRegistrationSession(Phonenumber.PhoneNumber phoneNumber, String sourceHost,
      boolean accountExistsWithPhoneNumber, @Nullable String clientMcc, @Nullable String clientMnc, Duration timeout)
      throws RateLimitExceededException;

  RegistrationServiceSession sendVerificationCode(byte[] sessionId, MessageTransport messageTransport,
      ClientType clientType, @Nullable String acceptLanguage, @Nullable String senderOverride, Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException,
      RegistrationServiceSenderException, RegistrationFraudException;

  RegistrationServiceSession checkVerificationCode(byte[] sessionId, String verificationCode, Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException;

  Optional<RegistrationServiceSession> getSession(byte[] sessionId, Duration timeout);
}
