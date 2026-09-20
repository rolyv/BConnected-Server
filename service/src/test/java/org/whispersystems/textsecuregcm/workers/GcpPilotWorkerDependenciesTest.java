// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.workers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.configuration.RuntimeMode;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class GcpPilotWorkerDependenciesTest {
  @ParameterizedTest
  @ValueSource(strings = {"backup-metrics", "backup-usage-recalculation", "remove-expired-backups",
      "clear-issued-receipt-redemptions", "notify-idle-devices", "process-idle-device-notification-jobs",
      "clear-expired-foundationdb-messages", "trim-oversized-fdb-message-queues", "clear-orphaned-foundationdb-queues",
      "regenerate-secondary-dynamodb-table-data", "start-push-notification-experiment", "unknown-plugin-worker"})
  void excludedWorkerFailsBeforeAnyEnvironmentOrCloudInitialization(final String name) throws Exception {
    final WhisperServerConfiguration configuration = SystemMapper.yamlMapper()
        .readValue("runtimeMode: GCP_PILOT", WhisperServerConfiguration.class);
    // No Environment, PostgreSQL settings, AWS credentials, or dynamic file exist. The capability check must be first.
    final UnsupportedOperationException failure = assertThrows(UnsupportedOperationException.class,
        () -> CommandDependencies.build(name, null, configuration));
    assertThat(failure).hasMessageContaining(name).hasMessageContaining("GCP_PILOT");
  }

  @ParameterizedTest
  @ValueSource(strings = {"message-persister-service", "scheduled-apn-sender", "rmuser", "unlink-device",
      "set-discoverability", "remove-expired-accounts", "remove-expired-username-holds", "remove-expired-devices",
      "unlink-devices-with-idle-primary"})
  void supportedNativeWorkerRemainsSelectable(final String name) {
    RuntimeMode.GCP_PILOT.requireWorker(name);
    RuntimeMode.LEGACY.requireWorker(name);
  }
}
