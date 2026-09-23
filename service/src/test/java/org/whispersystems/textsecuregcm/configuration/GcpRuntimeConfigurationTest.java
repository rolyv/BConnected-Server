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
      grpc:
        port: 8080
        websocketPort: 8081
        h2c: true
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
    assertThat(configuration.getKeyTransparencyServiceConfiguration()).isNull();
    assertThat(configuration.enabledPushTypes()).isEmpty();
    assertThat(configuration.isStorageEnabled()).isFalse();
    assertThat(configuration.isSvr2Enabled()).isFalse();
    assertThat(configuration.getMessageRetention()).isEqualTo(java.time.Duration.ofDays(7));
    assertThat(configuration.getRecoveryRetention()).isEqualTo(java.time.Duration.ofDays(1));
    try (var validation = Validation.buildDefaultValidatorFactory()) {
      for (String property : new String[] {"stripe", "braintree", "googlePlayBilling", "appleAppStore", "dynamoDbClient",
          "dynamoDbTables", "cdn3StorageManager", "svrb", "turn", "tus", "foundationDbMessages",
          "keyTransparencyService", "tlsKeyStore", "apn", "fcm", "svr2", "storageService", "hlrLookup", "runtimeConfigurationValid"}) {
        assertThat(validation.getValidator().validateProperty(configuration, property)).as(property).isEmpty();
      }
    }
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {"apnsEnabled", "fcmEnabled", "storageEnabled", "svr2Enabled"})
  void enabledOwnedIntegrationsRequireTheirRealConfiguration(final String capability) throws Exception {
    final WhisperServerConfiguration configuration = read(PILOT + "\npilotIntegrations:\n  " + capability + ": true\n");
    assertThrows(IllegalArgumentException.class, configuration::validateRuntimeConfiguration);
  }

  @Test
  void pilotH2cNeedsNoUnusedKeystoreButTlsListenersStillRequireOne() throws Exception {
    read(PILOT).validateRuntimeConfiguration();
    final WhisperServerConfiguration tls = read(PILOT.replace("h2c: true", "h2c: false"));
    assertThrows(IllegalArgumentException.class, tls::validateRuntimeConfiguration);
    final WhisperServerConfiguration https = read(PILOT + """
        server:
          applicationConnectors:
            - type: https
              port: 8443
        """);
    assertThrows(IllegalArgumentException.class, https::validateRuntimeConfiguration);
  }

  @Test
  void ownedApnsCanBeEnabledIndependently() throws Exception {
    final WhisperServerConfiguration configuration = read(PILOT + """
        pilotIntegrations:
          apnsEnabled: true
        apn:
          teamId: secret://collation
          keyId: secret://collation
          signingKey: secret://collation
          bundleId: example.pilot
          sandbox: true
        """);
    configuration.validateRuntimeConfiguration();
    assertThat(configuration.isApnsEnabled()).isTrue();
    assertThat(configuration.isFcmEnabled()).isFalse();
    assertThat(configuration.isStorageEnabled()).isFalse();
    assertThat(configuration.isSvr2Enabled()).isFalse();
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
    assertThrows(com.fasterxml.jackson.databind.exc.InvalidTypeIdException.class,
        () -> read(PILOT.replace("type: file", "type: default")));
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

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {"LEGACY", "GCP_PILOT"})
  void everyModeRequiresNativeStorageAndExplicitRetention(final String mode) throws Exception {
    final String yaml = PILOT.replace("runtimeMode: GCP_PILOT", "runtimeMode: " + mode);
    for (String invalid : new String[] {
        yaml.replaceAll("(?s)postgres:.*?(?=dynamicConfig:)", ""),
        yaml.replace("  messageRetention: PT168H\n", ""),
        yaml.replace("  recoveryRetention: PT24H\n", "")}) {
      final var configuration = read(invalid);
      assertThat(assertThrows(IllegalArgumentException.class, configuration::validateRuntimeConfiguration))
          .hasMessageContaining("All runtime modes require PostgreSQL with explicit messageRetention and recoveryRetention");
    }
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {"LEGACY", "GCP_PILOT"})
  void everyModeRequiresGcsAvatarsAndRejectsObsoleteCdnInput(final String mode) throws Exception {
    final String yaml = PILOT.replace("runtimeMode: GCP_PILOT", "runtimeMode: " + mode);
    final var noAvatars = read(yaml.replaceAll("(?s)gcpAvatars:.*?(?=gcpAttachments:)", ""));
    assertThat(assertThrows(IllegalArgumentException.class, noAvatars::validateRuntimeConfiguration))
        .hasMessageContaining("All runtime modes require gcpAvatars");
    for (String value : new String[] {"{}", "null", "{bucket: obsolete-bucket}"}) {
      assertThat(assertThrows(com.fasterxml.jackson.databind.JsonMappingException.class,
          () -> read(yaml + "\ncdn: " + value + "\n")))
          .hasMessageContaining("Legacy cdn configuration is no longer supported; configure gcpAvatars");
    }
  }

  private static WhisperServerConfiguration read(final String yaml) throws Exception {
    byte[] phoneKey = new byte[32]; java.util.Arrays.fill(phoneKey, (byte) 1);
    SecretsModule.INSTANCE.setSecretStore(new SecretStore(Map.of("collation",
        new SecretString(Base64.getEncoder().encodeToString(new byte[32])), "alphaPhone",
        new SecretString(Base64.getEncoder().encodeToString(phoneKey)))));
    return SystemMapper.yamlMapper().readValue(yaml, WhisperServerConfiguration.class);
  }

  private static String alpha() throws Exception {
    var pin = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
    return """
        server:
          applicationConnectors:
            - type: h2c
              port: 8080
              bindHost: 127.0.0.1
              useForwardedHeaders: true
        dmAlpha:
          memberIds: [00000000-0000-4000-8000-000000000001, 00000000-0000-4000-8000-000000000002]
          requestCommitmentKey: secret://collation
          phoneBindingKey: secret://alphaPhone
          admissionPublicKeys:
            test: %s
        """.formatted(Base64.getEncoder().encodeToString(pin.getEncoded()));
  }

  @Test void dmAlphaIsAbsentByDefaultAndNeedsExplicitOwnedComposition() throws Exception {
    assertThat(read(PILOT).getDmAlpha()).isNull();
    var config = read(PILOT + alpha());
    config.validateRuntimeConfiguration();
    assertThat(config.getDmAlpha().memberIds()).hasSize(2);
    assertThat(config.getDmAlpha().permitKeys()).hasSize(1);
    assertThat(config.getDmAlpha().toString()).isEqualTo("DmAlphaConfiguration[redacted]");
  }

  @Test void dmAlphaCannotTrustAnExposedOrUnconfiguredForwarder() throws Exception {
    var alpha = alpha();
    for (String invalid : new String[] {alpha.replace("127.0.0.1", "0.0.0.0"),
        alpha.replace("useForwardedHeaders: true", "useForwardedHeaders: false")})
      assertThrows(IllegalArgumentException.class, () -> read(PILOT + invalid).validateRuntimeConfiguration());
  }

  @Test void dmAlphaCannotEnablePushOrReuseKeysOrChangeCohortSize() throws Exception {
    var alpha = alpha();
    assertThrows(Exception.class, () -> read(PILOT + alpha.replace("secret://alphaPhone", "secret://collation")));
    assertThrows(Exception.class, () -> read(PILOT + alpha.replace(", 00000000-0000-4000-8000-000000000002", "")));
    assertThrows(IllegalArgumentException.class, () -> read(PILOT + alpha + """
        pilotIntegrations:
          apnsEnabled: true
        """).validateRuntimeConfiguration());
  }
}
