// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.validation.Validation;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretStore;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretsModule;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class GcpRuntimeConfigurationTest {
  private static final String PILOT = """
      runtimeMode: GCP_PILOT
      postgres:
        jdbcUrl: jdbc:postgresql://127.0.0.1:5432/example
        username: example
        maximumPoolSize: 2
        messageRetention: PT168H
        recoveryRetention: PT24H
      dynamicConfig:
        type: file
        path: /tmp/test-only-dynamic.yaml
      asnTable:
        type: file
        path: /tmp/test-only-asn.tsv.gz
      gcpAvatars:
        bucket: example-avatars
        signingServiceAccount: signal@example-project.iam.gserviceaccount.com
      gcpAttachments:
        domain: storage.googleapis.com
        email: signal@example-project.iam.gserviceaccount.com
        pathPrefix: /example-attachments
        useIamSigning: true
      registrationService:
        type: telnyx
        verify:
          verifyProfileId: 00000000-0000-4000-8000-000000000001
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

  @AfterEach
  void clearSecrets() { SecretsModule.INSTANCE.setSecretStore(new SecretStore(Map.of())); }

  @Test
  void modeDependenciesValidateWithoutAwsBillingBackupOrCallingConfiguration() throws Exception {
    final WhisperServerConfiguration configuration = read(PILOT);
    configuration.validateRuntimeConfiguration();
    assertThat(configuration.isGcpPilot()).isTrue();
    assertThat(configuration.getDynamoDbClientConfiguration()).isNull();
    assertThat(configuration.getDynamoDbTables()).isNull();
    assertThat(configuration.getCdnConfiguration()).isNull();
    assertThat(configuration.getKeyTransparencyServiceConfiguration()).isNull();
    assertThat(configuration.getMessageRetention()).isEqualTo(java.time.Duration.ofDays(7));
    assertThat(configuration.getRecoveryRetention()).isEqualTo(java.time.Duration.ofDays(1));
    try (var validation = Validation.buildDefaultValidatorFactory()) {
      for (String property : new String[] {"stripe", "braintree", "googlePlayBilling", "appleAppStore", "dynamoDbClient",
          "dynamoDbTables", "cdn", "cdn3StorageManager", "svrb", "turn", "tus", "foundationDbMessages",
          "keyTransparencyService", "runtimeConfigurationValid"}) {
        assertThat(validation.getValidator().validateProperty(configuration, property)).as(property).isEmpty();
      }
    }
  }

  @Test
  void absentModeRemainsLegacyAndRequiresLegacyDependencies() throws Exception {
    final WhisperServerConfiguration configuration = read(PILOT.replace("runtimeMode: GCP_PILOT\n", ""));
    assertThat(configuration.getRuntimeMode()).isEqualTo(RuntimeMode.LEGACY);
    assertThrows(IllegalArgumentException.class, configuration::validateRuntimeConfiguration);
  }

  @Test
  void pilotRejectsMissingNativeRetentionAndAwsMonitorSelection() throws Exception {
    final WhisperServerConfiguration noRetention = read(PILOT.replace("  messageRetention: PT168H\n", ""));
    assertThrows(IllegalArgumentException.class, noRetention::validateRuntimeConfiguration);
    final WhisperServerConfiguration s3Monitor = read(PILOT.replace("type: file", "type: default"));
    assertThrows(IllegalArgumentException.class, s3Monitor::validateRuntimeConfiguration);
  }

  @Test
  void pilotRequiresKeylessAttachmentsAndOwnedAvatarConfiguration() throws Exception {
    final WhisperServerConfiguration noIam = read(PILOT.replace("useIamSigning: true", "useIamSigning: false"));
    assertThrows(IllegalArgumentException.class, noIam::validateRuntimeConfiguration);
    final WhisperServerConfiguration noAvatars = read(PILOT.replace("""
        gcpAvatars:
          bucket: example-avatars
          signingServiceAccount: signal@example-project.iam.gserviceaccount.com
        """, ""));
    assertThrows(IllegalArgumentException.class, noAvatars::validateRuntimeConfiguration);
  }

  private static WhisperServerConfiguration read(final String yaml) throws Exception {
    SecretsModule.INSTANCE.setSecretStore(new SecretStore(Map.of("collation",
        new SecretString(Base64.getEncoder().encodeToString(new byte[32])))));
    return SystemMapper.yamlMapper().readValue(yaml, WhisperServerConfiguration.class);
  }
}
