// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import java.time.Instant;
import org.whispersystems.textsecuregcm.entities.ProfileAvatarUploadAttributes;

/** Provider-specific signing with a common profile response. Algorithms explicitly identify multipart field names. */
@FunctionalInterface
public interface AvatarUploadPolicyGenerator {
  UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime);

  default UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime, Runnable requireCurrent) {
    throw new UnsupportedOperationException("Guarded avatar policy signing unavailable");
  }

  record UploadPolicy(String credential, String acl, String algorithm, String formattedTimestamp,
                      String encodedPolicy, String signature) {
    public ProfileAvatarUploadAttributes attributes(String objectName) {
      return new ProfileAvatarUploadAttributes(objectName, credential, acl, algorithm,
          formattedTimestamp, encodedPolicy, signature);
    }
  }
}
