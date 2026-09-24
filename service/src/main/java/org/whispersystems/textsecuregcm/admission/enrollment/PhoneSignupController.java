// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.io.InputStream;
import java.util.Objects;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ManagedAsync;

/** Phone verification only. Approval and native account enrollment remain separate gates. */
@Path("/v1/bconnected/signup")
@Produces(MediaType.APPLICATION_JSON)
public final class PhoneSignupController {
  private final PhoneSignupService service;
  private final MobileEnrollmentBodyReader reader;
  private final MobileEnrollmentController.TrustedSourceAddress source;

  public PhoneSignupController(PhoneSignupService service, MobileEnrollmentBodyReader reader,
      MobileEnrollmentController.TrustedSourceAddress source) {
    this.service = Objects.requireNonNull(service); this.reader = Objects.requireNonNull(reader);
    this.source = Objects.requireNonNull(source);
  }
  @POST @Path("/begin") @ManagedAsync
  public Response begin(@Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.BEGIN, null, request, body);
  }
  @POST @Path("/{id}/send-code") @ManagedAsync
  public Response send(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.SEND_CODE, id, request, body);
  }
  @POST @Path("/{id}/check-code") @ManagedAsync
  public Response check(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.CHECK_CODE, id, request, body);
  }
  @POST @Path("/{id}/status") @ManagedAsync
  public Response status(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.STATUS, id, request, body);
  }

  @POST @Path("/{id}/supersede") @ManagedAsync
  public Response supersede(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return supersession(id, request, body, false);
  }
  @POST @Path("/{id}/supersession-status") @ManagedAsync
  public Response supersessionStatus(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return supersession(id, request, body, true);
  }

  private Response supersession(String id, ContainerRequest request, InputStream body, boolean statusOnly) {
    Result result;
    try {
      if (request.getMediaType() == null || !MediaType.APPLICATION_JSON_TYPE.isCompatible(request.getMediaType()))
        throw new IllegalArgumentException();
      var parsed = reader.parse(body, PhoneSignupSupersessionRequest::parse);
      if (!parsed.applicationId().toString().equals(id)) throw new IllegalArgumentException();
      result = service.supersede(parsed, statusOnly);
    } catch (IllegalArgumentException invalid) { result = error(Code.INVALID_REQUEST); }
    catch (RuntimeException unavailable) { result = error(Code.TEMPORARILY_UNAVAILABLE); }
    return Response.status(result.status()).type(MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store").entity(result.body()).build();
  }

  private Response handle(MobileEnrollmentParser.Operation action, String id, ContainerRequest request,
      InputStream body) {
    Result result;
    try {
      if (request.getMediaType() == null || !MediaType.APPLICATION_JSON_TYPE.isCompatible(request.getMediaType()))
        throw new IllegalArgumentException();
      var parsed = reader.parse(body, input -> PhoneSignupRequest.parse(input, action));
      if (id != null && !parsed.applicationId().toString().equals(id)) throw new IllegalArgumentException();
      result = service.execute(action, parsed.applicationId(), parsed.enrollmentNonce(), parsed.phoneNumber(),
          parsed.code(), action == MobileEnrollmentParser.Operation.BEGIN ? source.resolve(request) : null,
          request.getHeaderString("Accept-Language"));
    } catch (IllegalArgumentException invalid) { result = error(Code.INVALID_REQUEST); }
    catch (RuntimeException unavailable) { result = error(Code.TEMPORARILY_UNAVAILABLE); }
    var response = Response.status(result.status()).type(MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store").entity(result.body());
    if (result.body() instanceof MobileEnrollmentResponse.Error error && error.retryAfterSeconds() != null)
      response.header("Retry-After", error.retryAfterSeconds());
    return response.build();
  }
}
