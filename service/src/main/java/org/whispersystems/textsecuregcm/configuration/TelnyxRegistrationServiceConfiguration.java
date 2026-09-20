// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.core.setup.Environment;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import javax.sql.DataSource;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.registration.RegistrationService;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationPolicy;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxVerifyConfiguration;

@JsonTypeName("telnyx")
public record TelnyxRegistrationServiceConfiguration(
    @NotNull @Valid TelnyxVerifyConfiguration verify,
    @NotNull @Valid TelnyxRegistrationPolicy policy,
    @NotNull SecretBytes collationKeySalt) implements RegistrationServiceClientFactory {
  public TelnyxRegistrationServiceConfiguration {
    Objects.requireNonNull(verify, "Telnyx Verify configuration is required");
    Objects.requireNonNull(policy, "Explicit registration rate-limit policy is required");
    if (collationKeySalt == null || collationKeySalt.value().length < 32) {
      throw new IllegalArgumentException("Registration collation key must contain at least 32 bytes");
    }
    if (verify.verificationTimeout().compareTo(policy.sessionLifetime()) > 0) {
      throw new IllegalArgumentException("Verification lifetime must not exceed registration session lifetime");
    }
  }

  @Override
  public RegistrationService build(final Environment environment, final ScheduledExecutorService identityRefreshExecutor) {
    throw new IllegalStateException("Telnyx registration requires the PostgreSQL-backed factory overload");
  }

  @Override
  public RegistrationService build(final Environment environment, final ScheduledExecutorService identityRefreshExecutor,
      @Nullable final DataSource dataSource, final Clock clock) {
    if (dataSource == null) throw new IllegalStateException("Telnyx registration requires PostgreSQL persistence");
    final TelnyxRegistrationService service = new TelnyxRegistrationService(dataSource, verify.build(), policy,
        collationKeySalt.value(), clock);
    environment.lifecycle().scheduledExecutorService("telnyx-registration-expiry-%d").build()
        .scheduleWithFixedDelay(() -> {
          try { service.deleteExpired(1000); }
          catch (RuntimeException e) {
            LoggerFactory.getLogger(TelnyxRegistrationServiceConfiguration.class).error("Registration expiry cleanup failed", e);
          }
        }, 60, 60, TimeUnit.SECONDS);
    return service;
  }
}
