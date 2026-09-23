// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionKeyGuard;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.entities.InitialPreKeyPublication;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.AdmittedKeysPostgres;

/** Owned, initial-only publication. Existing /v2/keys replacement semantics are deliberately unchanged. */
@Path("/v1/bconnected/keys/initial")
public final class InitialPreKeyPublicationController {
  private final AdmissionEntitlementGate gate;
  private final AdmittedKeysPostgres keys;
  private final RateLimiters rates;
  public InitialPreKeyPublicationController(AdmissionEntitlementGate gate, AdmittedKeysPostgres keys, RateLimiters rates) {
    this.gate = gate; this.keys = keys; this.rates = rates;
  }
  @PUT @Path("/{operationId}") @Consumes(MediaType.APPLICATION_JSON)
  public Response publish(@Auth AuthenticatedDevice principal, @PathParam("operationId") String operationId,
      @QueryParam("identity") String namespace, InputStream body) throws RateLimitExceededException {
    final AdmissionKeyGuard guard;
    try { guard = AdmissionKeyGuard.http(gate, principal); }
    catch (RuntimeException failure) { throw AdmissionKeyGuard.failure(failure).http(); }
    rates.getPreKeysLimiter().validate(principal.accountIdentifier());
    final UUID operation;
    final IdentityType identity;
    final InitialPreKeyPublication publication;
    try {
      operation = UUID.fromString(operationId);
      if (!operation.toString().equalsIgnoreCase(operationId)) throw new IllegalArgumentException();
      identity = switch (namespace == null ? "" : namespace) {
        case "aci" -> IdentityType.ACI;
        case "pni" -> IdentityType.PNI;
        default -> throw new IllegalArgumentException();
      };
    } catch (IllegalArgumentException invalid) { return Response.status(400).build(); }
    try {
      var account = guard.account();
      var identityKey = identity == IdentityType.ACI ? account.getAccountIdentityKey()
          : account.getPhoneNumberIdentityKey().orElseThrow(() -> new WebApplicationException(400));
      publication = InitialPreKeyPublication.parse(body, identityKey);
    } catch (IOException | IllegalArgumentException invalid) { return Response.status(400).build(); }
    catch (AdmissionKeyGuard.Failure failure) { throw failure.http(); }
    try {
      boolean appliedOrReplayed = keys.publishInitial(guard, identity, operation, publication).join();
      guard.requireCurrent(); // Same request proof after commit, connection close and dispatcher wait.
      return Response.status(appliedOrReplayed ? 204 : 409).build();
    } catch (RuntimeException failure) { throw AdmissionKeyGuard.failure(failure).http(); }
  }
}
