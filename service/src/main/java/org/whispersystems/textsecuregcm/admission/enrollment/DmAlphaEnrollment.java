// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import com.google.common.net.InetAddresses;
import io.dropwizard.lifecycle.Managed;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.*;
import org.whispersystems.textsecuregcm.configuration.DmAlphaConfiguration;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;
import org.whispersystems.textsecuregcm.registration.RegistrationService;
import org.whispersystems.textsecuregcm.registration.telnyx.TelnyxRegistrationService;

/** Compose once, only on the explicit owned REST listener; enrollment is never a WebSocket route. */
public final class DmAlphaEnrollment implements Managed {
  private final MobileEnrollmentBodyReader bodies;
  private final AdmissionConfirmationWorker confirmation;
  private final MobileEnrollmentController controller;

  public DmAlphaEnrollment(DmAlphaConfiguration configuration, DataSource dataSource, Clock clock,
      Duration recoveryRetention, AdmissionServiceClient admission, AdmissionEntitlementGate gate,
      RegistrationService registration) {
    Objects.requireNonNull(configuration);
    if (!(registration instanceof TelnyxRegistrationService nativeRegistration))
      throw new IllegalArgumentException("Owned native registration required for alpha");
    var operations = new RegistrationOperations(dataSource, clock,
        new RegistrationRequestCommitment(configuration.requestCommitmentKey().value()));
    var coordinator = new AdmissionRegistrationCoordinator(operations, admission, nativeRegistration,
        new AdmissionPermitVerifier(configuration.permitKeys(), clock), configuration.phoneBindingKey().value());
    var creator = new AdmissionAccountCreator(dataSource, clock, operations, recoveryRetention);
    var service = new MobileEnrollmentService(operations, coordinator, creator, gate,
        Duration.ofSeconds(15), configuration.memberIds());
    bodies = new MobileEnrollmentBodyReader(Duration.ofSeconds(5), 8);
    controller = new MobileEnrollmentController(service, bodies, request ->
        trustedSource(request.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME)));
    confirmation = new AdmissionConfirmationWorker(new AdmissionConfirmationOutbox(
        dataSource, admission, Set.copyOf(configuration.memberIds())));
  }

  static String trustedSource(Object address) {
    // The servlet filter reads the connector's address. Never consult client headers here.
    // Runtime validation requires a loopback listener behind the owned header-replacing proxy.
    if (!(address instanceof String value) || !InetAddresses.isInetAddress(value))
      throw new IllegalArgumentException("Trusted REST source unavailable");
    return InetAddresses.toAddrString(InetAddresses.forString(value));
  }

  public MobileEnrollmentController controller() { return controller; }
  @Override public void start() { confirmation.start(); }
  @Override public void stop() {
    try { confirmation.stop(); } finally { bodies.close(); }
  }
}
