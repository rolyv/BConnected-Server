// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class DmAlphaEnrollmentTest {
  @Test void sourceUsesOnlyAnAlreadyResolvedConnectorAddress() {
    assertThat(DmAlphaEnrollment.trustedSource("192.0.2.1")).isEqualTo("192.0.2.1");
    assertThat(DmAlphaEnrollment.trustedSource("2001:db8::1")).isEqualTo("2001:db8::1");
    for (Object invalid : new Object[] {null, 1, "localhost", "192.0.2.1, 198.51.100.1", "for=192.0.2.1", ""})
      assertThrows(IllegalArgumentException.class, () -> DmAlphaEnrollment.trustedSource(invalid));
  }
}
