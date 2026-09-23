// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionKeyGuard;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Device;

/**
 * Resolve an ACI shared directly by an alumnus, without publishing a member list or phone number.
 * This is a fresh recipient observation, not a reusable authorization or identity verification.
 * Key fetch, send and delivery retain their own current admission checks.
 */
@Path("/v1/bconnected/recipients")
@Produces(MediaType.APPLICATION_JSON)
public final class BConnectedRecipientController {
  private final AdmissionEntitlementGate gate;
  private final RateLimiters rates;

  public BConnectedRecipientController(AdmissionEntitlementGate gate, RateLimiters rates) {
    this.gate = Objects.requireNonNull(gate);
    this.rates = Objects.requireNonNull(rates);
  }

  public record Recipient(UUID aci, byte deviceId) {
    @Override public String toString() { return "BConnectedRecipient[redacted]"; }
  }

  @GET @Path("/{aci}")
  public Response resolve(@Auth AuthenticatedDevice principal, @PathParam("aci") String rawAci)
      throws RateLimitExceededException {
    try {
      // Retain the credential-verified caller before parsing, throttling or target lookup.
      var caller = AdmissionKeyGuard.http(gate, principal);
      final UUID aci;
      try {
        aci = UUID.fromString(rawAci);
        if (!aci.toString().equals(rawAci) || aci.equals(new UUID(0, 0)))
          return response(400, null);
      } catch (IllegalArgumentException | NullPointerException invalid) {
        return response(400, null);
      }
      // The existing caller-keyed prekey budget also bounds invitation resolution.
      rates.getPreKeysLimiter().validate(principal.accountIdentifier());
      var recipient = caller.forTarget(aci, new AciServiceIdentifier(aci));
      var result = response(200, new Recipient(aci, Device.PRIMARY_ID));
      recipient.requireCurrent(); // Includes both original proofs after response construction.
      return result;
    } catch (RuntimeException failure) {
      throw AdmissionKeyGuard.failure(failure).http();
    }
  }

  private static Response response(int status, Object entity) {
    return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store").entity(entity).build();
  }
}
