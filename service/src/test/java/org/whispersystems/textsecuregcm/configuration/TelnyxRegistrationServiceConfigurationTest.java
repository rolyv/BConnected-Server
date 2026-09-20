// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretStore;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretsModule;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationPolicy;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxVerifyConfiguration;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class TelnyxRegistrationServiceConfigurationTest {
  @AfterEach
  void clearTestSecretStore() { SecretsModule.INSTANCE.setSecretStore(new SecretStore(Map.of())); }

  @Test
  void discoversTelnyxFactoryAndRequiresExplicitPolicyAndPostgresWithoutSending() throws Exception {
    SecretsModule.INSTANCE.setSecretStore(new SecretStore(Map.of("collation",
        new SecretString(Base64.getEncoder().encodeToString(new byte[32])))));
    final String yaml = """
        type: telnyx
        verify:
          apiKeyEnvironmentVariable: TELNYX_API_KEY
          verifyProfileId: 00000000-0000-4000-8000-000000000001
          verificationTimeout: PT5M
        policy:
          sessionLifetime: PT10M
          quotaWindow: PT24H
          maxSessionsPerNumber: 10
          maxSessionsPerSource: 30
          maxSmsPerNumber: 5
          maxSmsPerSession: 3
          maxChecksPerNumber: 20
          maxChecksPerSession: 5
          smsCooldown: PT1M
          checkCooldown: PT1S
        collationKeySalt: secret://collation
        """;
    final RegistrationServiceClientFactory factory = SystemMapper.yamlMapper().readValue(yaml,
        RegistrationServiceClientFactory.class);
    assertThat(factory).isInstanceOf(TelnyxRegistrationServiceConfiguration.class);
    assertThat(((TelnyxRegistrationServiceConfiguration) factory).policy().maxSmsPerNumber()).isEqualTo(5);
    assertThrows(IllegalStateException.class, () -> factory.build(null, null));
    assertThrows(IllegalStateException.class, () -> factory.build(null, null, null, Clock.systemUTC()));
  }

  @Test
  void legacyFactoryStillUsesOriginalBuildContract() {
    final RegistrationServiceClient client = mock(RegistrationServiceClient.class);
    final RegistrationServiceClientFactory factory = (_, _) -> client;
    assertThat(factory.build(null, null, null, Clock.systemUTC())).isSameAs(client);
  }

  @Test
  void rejectsWeakKeysMissingPolicyAndInvalidLimits() {
    final TelnyxVerifyConfiguration verify = new TelnyxVerifyConfiguration("TELNYX_API_KEY", UUID.randomUUID(),
        Duration.ofMinutes(5));
    final TelnyxRegistrationPolicy policy = new TelnyxRegistrationPolicy(Duration.ofMinutes(10), Duration.ofDays(1),
        10, 30, 5, 3, 20, 5, Duration.ofMinutes(1), Duration.ofSeconds(1));
    assertThrows(IllegalArgumentException.class,
        () -> new TelnyxRegistrationServiceConfiguration(verify, policy, new SecretBytes(new byte[16])));
    assertThrows(NullPointerException.class,
        () -> new TelnyxRegistrationServiceConfiguration(verify, null, new SecretBytes(new byte[32])));
    assertThrows(IllegalArgumentException.class, () -> new TelnyxRegistrationPolicy(Duration.ofMinutes(10),
        Duration.ofDays(1), 0, 30, 5, 3, 20, 5, Duration.ofMinutes(1), Duration.ofSeconds(1)));
    assertThrows(IllegalArgumentException.class, () -> new TelnyxRegistrationPolicy(Duration.ofMinutes(10),
        Duration.ofMinutes(5), 10, 30, 5, 3, 20, 5, Duration.ofMinutes(1), Duration.ofSeconds(1)));
  }
}
