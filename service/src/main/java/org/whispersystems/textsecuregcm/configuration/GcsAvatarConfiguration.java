// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.StorageOptions;
import java.io.IOException;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.Executor;
import org.whispersystems.textsecuregcm.avatars.GcsAvatarStorage;
import org.whispersystems.textsecuregcm.gcp.IamBlobSigner;

/** Uses attached/workload credentials for object access and IAM signBlob; accepts no exported private key. */
public record GcsAvatarConfiguration(String bucket, String signingServiceAccount) {
  public GcsAvatarConfiguration {
    if (bucket == null || !bucket.matches("[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")) {
      throw new IllegalArgumentException("A GCS avatar bucket name is required");
    }
    if (signingServiceAccount == null
        || !signingServiceAccount.matches("[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.gserviceaccount\\.com")) {
      throw new IllegalArgumentException("A GCS avatar signing service account email is required");
    }
  }

  public GcsAvatarStorage build(Executor executor, Clock clock) throws IOException {
    var scopes = List.of("https://www.googleapis.com/auth/cloud-platform");
    GoogleCredentials credentials = GoogleCredentials.getApplicationDefault().createScoped(scopes);
    var signer = IamBlobSigner.create(signingServiceAccount);
    var transport = StorageOptions.getDefaultHttpTransportOptions().toBuilder()
        .setConnectTimeout(5_000).setReadTimeout(15_000).build();
    var storage = StorageOptions.newBuilder().setCredentials(credentials).setTransportOptions(transport).build().getService();
    return new GcsAvatarStorage(storage, bucket, signer, executor, clock);
  }
}
