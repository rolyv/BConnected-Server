// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.gcp;

import com.google.auth.ServiceAccountSigner;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import java.io.IOException;
import java.util.List;

/** IAM signBlob only; callers cannot use this interface to mint impersonated access tokens. */
public final class IamBlobSigner {
  private IamBlobSigner() {}

  public static ServiceAccountSigner create(final String serviceAccount) throws IOException {
    if (serviceAccount == null || !serviceAccount.matches("[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.gserviceaccount\\.com")) {
      throw new IllegalArgumentException("A Google service-account signing identity is required");
    }
    final var scopes = List.of("https://www.googleapis.com/auth/cloud-platform");
    final var source = GoogleCredentials.getApplicationDefault().createScoped(scopes);
    final var credentials = ImpersonatedCredentials.create(source, serviceAccount, List.of(), scopes, 3600);
    return new ServiceAccountSigner() {
      @Override public String getAccount() { return credentials.getAccount(); }
      @Override public byte[] sign(final byte[] value) { return credentials.sign(value); }
    };
  }
}
