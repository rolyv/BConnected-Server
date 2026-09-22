// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.avatars;

import java.time.Instant;

/** Deterministic provider-neutral fixture for transport tests; never signs a usable capability. */
public final class TestAvatarUploadPolicyGenerator implements AvatarUploadPolicyGenerator {
  public static final TestAvatarUploadPolicyGenerator INSTANCE = new TestAvatarUploadPolicyGenerator();

  private TestAvatarUploadPolicyGenerator() {}

  @Override
  public UploadPolicy createFor(String objectName, int maxSizeInBytes, Instant currentTime) {
    return new UploadPolicy("fixture-credential", "", "TEST-POLICY", currentTime.toString(),
        objectName + ":" + maxSizeInBytes, "fixture-signature");
  }
}
