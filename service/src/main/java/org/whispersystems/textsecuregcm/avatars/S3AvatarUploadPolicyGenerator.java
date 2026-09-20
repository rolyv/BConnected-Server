// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import java.time.Instant;
import java.util.Objects;
import org.whispersystems.textsecuregcm.s3.PostPolicyGenerator;

/** Preserves the upstream S3 signature and response fields exactly. */
public final class S3AvatarUploadPolicyGenerator implements AvatarUploadPolicyGenerator {
  private final PostPolicyGenerator delegate;

  public S3AvatarUploadPolicyGenerator(PostPolicyGenerator delegate) {
    this.delegate = Objects.requireNonNull(delegate);
  }

  @Override
  public UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime) {
    var signed = delegate.createFor(objectName, maxSizeInBytes, currentTime);
    return new UploadPolicy(signed.credential(), PostPolicyGenerator.ACL, PostPolicyGenerator.ALGORITHM,
        signed.formattedTimestamp(), signed.encodedPolicy(), signed.signature());
  }
}
