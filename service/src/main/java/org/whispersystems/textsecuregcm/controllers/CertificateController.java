/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.auth.Auth;
import io.micrometer.core.instrument.Metrics;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredentialResponse;
import org.whispersystems.textsecuregcm.admission.AdmissionCapabilityGuard;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.CertificateGenerator;
import org.whispersystems.textsecuregcm.auth.RedemptionRange;
import org.whispersystems.textsecuregcm.entities.DeliveryCertificate;
import org.whispersystems.textsecuregcm.entities.GroupCredentials;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;

@Path("/v1/certificate")
@Tag(name = "Certificate")
public class CertificateController {
  private final boolean callsEnabled;
  private final boolean requireCurrentMembership;

  private final AccountsManager accountsManager;
  private final CertificateGenerator certificateGenerator;
  private final ServerZkAuthOperations serverZkAuthOperations;
  private final GenericServerSecretParams genericServerSecretParams;
  private final GenericServerSecretParams genericServerSecretParamsPreV101;
  private final Clock clock;

  @VisibleForTesting
  public static final Duration MAX_REDEMPTION_DURATION = Duration.ofDays(7);
  private static final String GENERATE_DELIVERY_CERTIFICATE_COUNTER_NAME = name(CertificateController.class, "generateCertificate");
  private static final String INCLUDE_E164_TAG_NAME = "includeE164";

  public CertificateController(
      final AccountsManager accountsManager,
      @Nonnull CertificateGenerator certificateGenerator,
      @Nonnull ServerZkAuthOperations serverZkAuthOperations,
      @Nonnull GenericServerSecretParams genericServerSecretParams,
      @Nonnull GenericServerSecretParams genericServerSecretParamsPreV101,
      @Nonnull Clock clock) {

    this(accountsManager, certificateGenerator, serverZkAuthOperations, genericServerSecretParams,
        genericServerSecretParamsPreV101, clock, true);
  }

  public CertificateController(final AccountsManager accountsManager, final CertificateGenerator certificateGenerator,
      final ServerZkAuthOperations serverZkAuthOperations, final GenericServerSecretParams genericServerSecretParams,
      final GenericServerSecretParams genericServerSecretParamsPreV101, final Clock clock, final boolean callsEnabled) {

    this(accountsManager, certificateGenerator, serverZkAuthOperations, genericServerSecretParams,
        genericServerSecretParamsPreV101, clock, callsEnabled, false);
  }

  public CertificateController(final AccountsManager accountsManager, final CertificateGenerator certificateGenerator,
      final ServerZkAuthOperations serverZkAuthOperations, final GenericServerSecretParams genericServerSecretParams,
      final GenericServerSecretParams genericServerSecretParamsPreV101, final Clock clock, final boolean callsEnabled,
      final boolean requireCurrentMembership) {

    this.accountsManager = accountsManager;
    this.certificateGenerator = Objects.requireNonNull(certificateGenerator);
    this.serverZkAuthOperations = Objects.requireNonNull(serverZkAuthOperations);
    this.genericServerSecretParams = genericServerSecretParams;
    this.genericServerSecretParamsPreV101 = genericServerSecretParamsPreV101;
    this.clock = Objects.requireNonNull(clock);
    this.callsEnabled = callsEnabled;
    this.requireCurrentMembership = requireCurrentMembership;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/delivery")
  public DeliveryCertificate getDeliveryCertificate(@Auth AuthenticatedDevice auth,
      @QueryParam("includeE164") @DefaultValue("true") boolean includeE164) {

    final AdmissionCapabilityGuard guard = AdmissionCapabilityGuard.http(auth, requireCurrentMembership);
    guard.run();

    Metrics.counter(GENERATE_DELIVERY_CERTIFICATE_COUNTER_NAME, INCLUDE_E164_TAG_NAME, String.valueOf(includeE164))
        .increment();

    final Account account = guard.accountForCredentialIssuance(() ->
        accountsManager.getByAccountIdentifier(auth.accountIdentifier())
            .orElseThrow(() -> new WebApplicationException(Response.Status.UNAUTHORIZED)));

    try {
      guard.run();
      final DeliveryCertificate certificate =
          new DeliveryCertificate(certificateGenerator.createFor(account, auth.deviceId(), includeE164));
      guard.run();
      return certificate;
    } catch (final IllegalArgumentException _) {
      throw new BadRequestException();
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/auth/group")
  public GroupCredentials getGroupAuthenticationCredentials(
      @Auth AuthenticatedDevice auth,
      @QueryParam("redemptionStartSeconds") long startSeconds,
      @QueryParam("redemptionEndSeconds") long endSeconds,
      @Parameter(description = "Whether to use libsignal v0.101.0+ secret params")
      @QueryParam("v101") boolean v101) {

    final AdmissionCapabilityGuard guard = AdmissionCapabilityGuard.http(auth, requireCurrentMembership);
    guard.run();

    final RedemptionRange redemptionRange;
    try {
      final Instant redemptionStart = Instant.ofEpochSecond(startSeconds);
      final Instant redemptionEnd = Instant.ofEpochSecond(endSeconds);
      redemptionRange = RedemptionRange.inclusive(clock, redemptionStart, redemptionEnd);
    } catch (IllegalArgumentException e) {
      throw new BadRequestException(e.getCause());
    }

    final Account account = guard.accountForCredentialIssuance(() ->
        accountsManager.getByAccountIdentifier(auth.accountIdentifier())
            .orElseThrow(() -> new WebApplicationException(Response.Status.UNAUTHORIZED)));

    final List<GroupCredentials.GroupCredential> credentials = new ArrayList<>();
    final List<GroupCredentials.CallLinkAuthCredential> callLinkAuthCredentials = new ArrayList<>();

    final ServiceId.Aci aci = new ServiceId.Aci(account.getAccountIdentifier());
    final Optional<ServiceId.Pni> maybePni = account.getPhoneNumberIdentifier().map(ServiceId.Pni::new);

    for (Instant redemption : redemptionRange) {
      guard.run();
      final AuthCredentialWithPniResponse authCredentialWithPni =
          maybePni.map(pni -> serverZkAuthOperations.issueAuthCredentialWithPniZkc(aci, pni, redemption))
              .orElseGet(() -> serverZkAuthOperations.issueAuthCredentialZkcWithoutPni(aci,
                  account.getAuthCredentialSalt()
                      .orElseThrow(() -> new IllegalStateException("account without PNI must have auth credential salt")),
                  redemption));
      credentials.add(new GroupCredentials.GroupCredential(
          authCredentialWithPni.serialize(),
          (int) redemption.getEpochSecond()));

      guard.run();

      if (callsEnabled) callLinkAuthCredentials.add(new GroupCredentials.CallLinkAuthCredential(
          CallLinkAuthCredentialResponse.issueCredential(aci, redemption, v101 ? genericServerSecretParams : genericServerSecretParamsPreV101).serialize(),
          redemption.getEpochSecond()));
    }

    guard.run();
    return new GroupCredentials(credentials, callLinkAuthCredentials, maybePni.map(ServiceId.Pni::getRawUUID).orElse(null));
  }
}
