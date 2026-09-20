// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.StorageOptions;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.whispersystems.textsecuregcm.gcp.IamBlobSigner;
import org.whispersystems.textsecuregcm.media.GcsMediaDownloadService;

public record GcsMediaDownloadConfiguration(String avatarBucket, String attachmentBucket,
    String attachmentObjectPrefix, String signingServiceAccount, Duration validity) {
  public GcsMediaDownloadConfiguration {
    for (String bucket : new String[] {avatarBucket, attachmentBucket}) {
      if (bucket == null || !bucket.matches("[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")) {
        throw new IllegalArgumentException("Private media bucket names are required");
      }
    }
    if (attachmentObjectPrefix == null) attachmentObjectPrefix = "";
    if (!attachmentObjectPrefix.matches("(?:[a-zA-Z0-9_-]+/)*")) {
      throw new IllegalArgumentException("Media object prefix must contain only fixed path segments");
    }
    if (signingServiceAccount == null
        || !signingServiceAccount.matches("[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.gserviceaccount\\.com")) {
      throw new IllegalArgumentException("A media signing service account is required");
    }
    if (validity == null) validity = Duration.ofMinutes(5);
    if (validity.isZero() || validity.isNegative() || validity.compareTo(Duration.ofMinutes(5)) > 0 || validity.getNano() != 0) {
      throw new IllegalArgumentException("Media capability validity must be 1..300 whole seconds");
    }
  }

  public GcsMediaDownloadService build(Clock clock) throws IOException {
    var credentials = GoogleCredentials.getApplicationDefault().createScoped(List.of("https://www.googleapis.com/auth/cloud-platform"));
    var signer = IamBlobSigner.create(signingServiceAccount);
    var transport = StorageOptions.getDefaultHttpTransportOptions().toBuilder().setConnectTimeout(5000).setReadTimeout(15000).build();
    var storage = StorageOptions.newBuilder().setCredentials(credentials).setTransportOptions(transport).build().getService();
    return new GcsMediaDownloadService(storage, signer, this, clock);
  }
}
