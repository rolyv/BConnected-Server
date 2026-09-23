// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import io.dropwizard.auth.basic.BasicCredentials;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ManagedAsync;
import org.whispersystems.textsecuregcm.admission.AdmissionRegistrationCoordinator;

/** Registered only by explicit DM-alpha composition on the owned REST listener with a trusted resolver. */
@Path("/v1/bconnected/enrollment")
@Produces(MediaType.APPLICATION_JSON)
public final class MobileEnrollmentController {
  @FunctionalInterface public interface TrustedSourceAddress {
    String resolve(ContainerRequest request);
  }

  private final MobileEnrollmentService service;
  private final MobileEnrollmentBodyReader bodies;
  private final TrustedSourceAddress source;

  public MobileEnrollmentController(MobileEnrollmentService service, MobileEnrollmentBodyReader bodies,
      TrustedSourceAddress source) {
    this.service = Objects.requireNonNull(service);
    this.bodies = Objects.requireNonNull(bodies);
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
  @POST @Path("/{id}/complete") @ManagedAsync
  public Response complete(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.COMPLETE, id, request, body);
  }
  @POST @Path("/{id}/status") @ManagedAsync
  public Response status(@PathParam("id") String id, @Context ContainerRequest request, InputStream body) {
    return handle(MobileEnrollmentParser.Operation.STATUS, id, request, body);
  }

  private Response handle(MobileEnrollmentParser.Operation operation, String id, ContainerRequest request,
      InputStream body) {
    try {
      UUID operationId = id == null ? null : UUID.fromString(id);
      if (id != null && !operationId.toString().equals(id)) return response(error(Code.INVALID_REQUEST));
      var headers = request.getRequestHeader("Authorization");
      if (headers == null || headers.size() != 1) return response(error(Code.INVALID_CREDENTIALS));
      BasicCredentials credentials = credentials(headers.getFirst());
      if (credentials == null) return response(error(Code.INVALID_CREDENTIALS));
      if (request.getMediaType() == null || !MediaType.APPLICATION_JSON_TYPE.isCompatible(request.getMediaType()))
        return response(error(Code.INVALID_REQUEST));
      var parsed = bodies.read(body, operation, credentials.getUsername());
      var input = new AdmissionRegistrationCoordinator.Input(parsed.memberId(), parsed.registrationAttemptId(),
          parsed.bindingChallenge(), credentials.getUsername(), credentials.getPassword(), parsed.registrationRequest(),
          parsed.originalSignalAgent(), parsed.originalUserAgent());
      String trustedAddress = operation == MobileEnrollmentParser.Operation.BEGIN ? source.resolve(request) : null;
      return response(service.execute(operation, operationId, input, parsed.code(), trustedAddress,
          request.getHeaderString("Accept-Language")));
    } catch (IllegalArgumentException invalid) {
      return response(error(Code.INVALID_REQUEST));
    } catch (RuntimeException unavailable) {
      return response(error(Code.TEMPORARILY_UNAVAILABLE));
    }
  }

  private static BasicCredentials credentials(String header) {
    try {
      if (header == null || header.length() > 1024 || !header.regionMatches(true, 0, "Basic ", 0, 6)) return null;
      byte[] decoded = Base64.getDecoder().decode(header.substring(6));
      String raw = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(decoded)).toString();
      java.util.Arrays.fill(decoded, (byte) 0);
      int colon = raw.indexOf(':');
      if (colon < 0) return null;
      String number = raw.substring(0, colon), password = raw.substring(colon + 1);
      if (!number.matches("\\+[1-9][0-9]{1,14}") || password.isEmpty()
          || password.getBytes(StandardCharsets.UTF_8).length > 256
          || password.codePoints().anyMatch(Character::isISOControl)) return null;
      return new BasicCredentials(number, password);
    } catch (Exception invalid) { return null; }
  }

  private static Response response(Result result) {
    var response = Response.status(result.status()).type(MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store").entity(result.body());
    if (result.body() instanceof MobileEnrollmentResponse.Error error && error.retryAfterSeconds() != null)
      response.header("Retry-After", error.retryAfterSeconds());
    return response.build();
  }
}
