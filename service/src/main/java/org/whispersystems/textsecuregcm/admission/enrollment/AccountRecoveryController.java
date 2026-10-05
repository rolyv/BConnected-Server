// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.io.InputStream;
import java.util.UUID;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ManagedAsync;
import org.whispersystems.textsecuregcm.admission.AccountRecoveryService;

/** Recovery is opt-in REST only; opaque IDs never substitute for the frozen new credential. */
@Path("/v1/bconnected/recovery")
@Produces(MediaType.APPLICATION_JSON)
public final class AccountRecoveryController {
  private final AccountRecoveryService service;
  private final MobileEnrollmentBodyReader bodies;
  private final MobileEnrollmentController.TrustedSourceAddress source;

  public AccountRecoveryController(
      AccountRecoveryService service,
      MobileEnrollmentBodyReader bodies,
      MobileEnrollmentController.TrustedSourceAddress source) {
    this.service = service;
    this.bodies = bodies;
    this.source = source;
  }

  @POST
  @Path("/begin")
  @ManagedAsync
  public Response begin(@Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.BEGIN, null, request, body);
  }

  @POST
  @Path("/{id}/send-code")
  @ManagedAsync
  public Response send(
      @PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.SEND_CODE, id, request, body);
  }

  @POST
  @Path("/{id}/check-code")
  @ManagedAsync
  public Response check(
      @PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.CHECK_CODE, id, request, body);
  }

  @POST
  @Path("/{id}/status")
  @ManagedAsync
  public Response status(
      @PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.STATUS, id, request, body);
  }

  @POST
  @Path("/{id}/complete")
  @ManagedAsync
  public Response complete(
      @PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.COMPLETE, id, request, body);
  }

  private Response handle(
      MobileEnrollmentParser.Operation action,
      String rawId,
      ContainerRequest request,
      InputStream body) {
    Result result;
    try {
      UUID id = rawId == null ? null : UUID.fromString(rawId);
      if (rawId != null && (!rawId.equals(id.toString()) || id.equals(new UUID(0, 0))))
        throw new IllegalArgumentException();
      var headers = request.getRequestHeader("Authorization");
      var credentials =
          headers == null || headers.size() != 1
              ? null
              : MobileEnrollmentController.credentials(headers.getFirst());
      if (credentials == null) result = error(Code.INVALID_CREDENTIALS);
      else if (request.getMediaType() == null
          || !MediaType.APPLICATION_JSON_TYPE.isCompatible(request.getMediaType()))
        result = error(Code.INVALID_REQUEST);
      else {
        var parsed =
            bodies.parse(
                body,
                input ->
                    MobileEnrollmentParser.parseRecovery(input, action, credentials.getUsername()));
        result =
            service.execute(
                action,
                id,
                new AccountRecoveryService.Input(
                    parsed.registrationAttemptId(),
                    credentials.getUsername(),
                    credentials.getPassword(),
                    parsed.registrationRequest(),
                    parsed.originalSignalAgent(),
                    parsed.originalUserAgent()),
                parsed.code(),
                action == MobileEnrollmentParser.Operation.BEGIN ? source.resolve(request) : null,
                request.getHeaderString("Accept-Language"));
      }
    } catch (IllegalArgumentException malformed) {
      result = error(Code.INVALID_REQUEST);
    } catch (RuntimeException unavailable) {
      result = error(Code.TEMPORARILY_UNAVAILABLE);
    }
    var response =
        Response.status(result.status())
            .type(MediaType.APPLICATION_JSON_TYPE)
            .header("Cache-Control", "no-store")
            .entity(result.body());
    if (result.body() instanceof MobileEnrollmentResponse.Error e && e.retryAfterSeconds() != null)
      response.header("Retry-After", e.retryAfterSeconds());
    return response.build();
  }
}
