// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.admission.*;
import org.whispersystems.textsecuregcm.configuration.DmAlphaConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;

class DmAlphaPhoneAllowlistTest {
  private static final UUID FIRST = UUID.fromString("00000000-0000-4000-8000-000000000001");
  private static final UUID SECOND = UUID.fromString("00000000-0000-4000-8000-000000000002");
  // Independent HMAC vectors for synthetic +13055550123/124, 32 bytes of 0x01.
  private static final String FIRST_BINDING = "a54053b72e21ada14ea65e73b415a148ab08b275197cbebaf61c3c77404f1cc2";
  private static final String SECOND_BINDING = "ec4d6a964bfd148509e98935f65975f8c6ca0e6730ddbbc225275363a8541fce";

  private DmAlphaConfiguration config(Map<UUID, String> bindings) throws Exception {
    byte[] phoneKey = new byte[32]; Arrays.fill(phoneKey, (byte) 1);
    return new DmAlphaConfiguration(Set.of(FIRST, SECOND), bindings, new SecretBytes(new byte[32]),
        new SecretBytes(phoneKey), Map.of("test", Base64.getEncoder().encodeToString(
            KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded())));
  }

  @Test void phoneEligibilityIsExactPerMemberAndRejectsNoncanonicalInput() throws Exception {
    var config = config(Map.of(FIRST, FIRST_BINDING, SECOND, SECOND_BINDING));
    assertThat(config.allowsPhone(FIRST, "+13055550123")).isTrue();
    assertThat(config.allowsPhone(SECOND, "+13055550124")).isTrue();
    assertThat(config.allowsPhone(SECOND, "+13055550123")).isFalse();
    assertThat(config.allowsPhone(FIRST, "+13055550124")).isFalse();
    assertThat(config.allowsPhone(UUID.randomUUID(), "+13055550123")).isFalse();
    assertThat(config.allowsPhone(null, "+13055550123")).isFalse();
    for (String invalid : new String[] {null, "13055550123", "+1 305 555 0123", "+13055550123\n", "+03055550123"})
      assertThat(config.allowsPhone(FIRST, invalid)).isFalse();
  }

  @Test void configurationRejectsMissingMismatchedDuplicateOrMalformedBindings() {
    for (var bindings : List.of(Map.<UUID, String>of(), Map.of(FIRST, FIRST_BINDING),
        Map.of(FIRST, FIRST_BINDING, UUID.randomUUID(), SECOND_BINDING),
        Map.of(FIRST, FIRST_BINDING, SECOND, FIRST_BINDING),
        Map.of(FIRST, FIRST_BINDING, SECOND, SECOND_BINDING.toUpperCase(Locale.ROOT))))
      assertThrows(IllegalArgumentException.class, () -> config(bindings));
    assertThrows(IllegalArgumentException.class, () -> config(null));
  }

  @Test void disallowedNumberCannotReachStorageSmsOrAccountCreationOnAnyAction() throws Exception {
    var operations = mock(RegistrationOperations.class);
    var coordinator = mock(AdmissionRegistrationCoordinator.class);
    var creator = mock(AdmissionAccountCreator.class);
    var gate = mock(AdmissionEntitlementGate.class);
    var config = config(Map.of(FIRST, FIRST_BINDING, SECOND, SECOND_BINDING));
    var service = new MobileEnrollmentService(operations, coordinator, creator, gate, Duration.ofSeconds(3),
        config.memberIds(), config::allowsPhone);
    var wrong = new AdmissionRegistrationCoordinator.Input(FIRST, null, null, "+13055550124", null, null, null, null);
    for (var action : MobileEnrollmentParser.Operation.values()) {
      var response = service.execute(action, UUID.randomUUID(), wrong, "123456", "192.0.2.1", "en");
      assertThat(response.status()).isEqualTo(404);
      assertThat(((MobileEnrollmentResponse.Error) response.body()).code()).isEqualTo("ENROLLMENT_UNAVAILABLE");
    }
    verifyNoInteractions(operations, coordinator, creator, gate);
  }
}
