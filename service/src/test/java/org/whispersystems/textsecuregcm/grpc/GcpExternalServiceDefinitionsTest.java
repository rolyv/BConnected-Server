// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.signal.chat.credentials.ExternalServiceType;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.configuration.DirectoryV2ClientConfiguration;
import org.whispersystems.textsecuregcm.configuration.DirectoryV2Configuration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;

class GcpExternalServiceDefinitionsTest {
  @Test
  void disabledServicesDoNotReadConfigurationOrProduceCredentials() {
    final WhisperServerConfiguration config = mock(WhisperServerConfiguration.class);
    when(config.isGcpPilot()).thenReturn(true);
    when(config.getDirectoryV2Configuration()).thenReturn(new DirectoryV2Configuration(
        new DirectoryV2ClientConfiguration(new SecretBytes(new byte[32]), new SecretBytes(new byte[32]))));
    assertThat(ExternalServiceDefinitions.createExternalServiceList(config, Clock.systemUTC()))
        .containsOnlyKeys(ExternalServiceType.EXTERNAL_SERVICE_TYPE_DIRECTORY);
    verify(config, never()).getSvr2Configuration();
    verify(config, never()).getSecureStorageServiceConfiguration();
    verify(config, never()).getPaymentsServiceConfiguration();
  }
}
