// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.registration.telnyx;

import java.time.Duration;
import java.util.Optional;

/** Safe provider failure metadata. Deliberately excludes request/response bodies, phone numbers and credentials. */
public final class TelnyxVerifyException extends Exception {
  public enum Reason {
    RATE_LIMITED, AUTHENTICATION, NOT_FOUND, INVALID_REQUEST, REJECTED,
    PROVIDER_UNAVAILABLE, INVALID_RESPONSE, TRANSPORT_FAILURE
  }

  private final Reason reason;
  private final int httpStatus;
  private final Optional<Duration> retryAfter;
  private final Optional<String> providerCode;

  public TelnyxVerifyException(final Reason reason, final int httpStatus, final Optional<Duration> retryAfter,
      final Optional<String> providerCode) {
    super("Telnyx Verify " + reason.name() + " (HTTP " + httpStatus + ")");
    this.reason = reason;
    this.httpStatus = httpStatus;
    this.retryAfter = retryAfter;
    this.providerCode = providerCode;
  }

  public Reason reason() { return reason; }
  public int httpStatus() { return httpStatus; }
  public Optional<Duration> retryAfter() { return retryAfter; }
  public Optional<String> providerCode() { return providerCode; }
}
