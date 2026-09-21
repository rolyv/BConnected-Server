// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.auth;

import jakarta.ws.rs.ServiceUnavailableException;

/** Fail closed without telling the client to discard potentially valid device credentials. */
public final class AuthenticationUnavailableException extends ServiceUnavailableException {
  public AuthenticationUnavailableException() {
    super("Current authentication unavailable");
  }
}
