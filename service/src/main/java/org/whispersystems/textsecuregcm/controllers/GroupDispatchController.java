// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.groups.GroupDispatchRequest;
import org.whispersystems.textsecuregcm.groups.GroupDispatchService;

/** Exact public REST routes, intentionally absent from the production Jersey registration. */
@Path("/v1/bconnected")
public final class GroupDispatchController {
  private final GroupDispatchService dispatch;
  public GroupDispatchController(GroupDispatchService dispatch) { this.dispatch = dispatch; }

  @POST @Path("/groups")
  public Response create(@Auth AuthenticatedDevice principal, @HeaderParam("Content-Type") String type,
      @HeaderParam("Content-Encoding") String encoding, @Context UriInfo uri, InputStream body) {
    if (hasQuery(uri)) return error(400);
    return post(principal, "/v1/bconnected/groups", type, encoding, body);
  }
  @POST @Path("/groups/{groupId}/state")
  public Response state(@Auth AuthenticatedDevice principal, @PathParam("groupId") String groupId,
      @HeaderParam("Content-Type") String type, @HeaderParam("Content-Encoding") String encoding,
      @Context UriInfo uri, InputStream body) {
    if (hasQuery(uri)) return error(400);
    return post(principal, "/v1/bconnected/groups/" + groupId + "/state", type, encoding, body);
  }
  @POST @Path("/groups/{groupId}/changes")
  public Response change(@Auth AuthenticatedDevice principal, @PathParam("groupId") String groupId,
      @HeaderParam("Content-Type") String type, @HeaderParam("Content-Encoding") String encoding,
      @Context UriInfo uri, InputStream body) {
    if (hasQuery(uri)) return error(400);
    return post(principal, "/v1/bconnected/groups/" + groupId + "/changes", type, encoding, body);
  }
  @GET @Path("/group-operations/{requestId}")
  public Response outcome(@Auth AuthenticatedDevice principal, @PathParam("requestId") String requestId,
      @HeaderParam("Content-Type") String type, @HeaderParam("Content-Encoding") String encoding,
      @HeaderParam("Content-Length") String length, @HeaderParam("Transfer-Encoding") String transferEncoding,
      @Context UriInfo uri, InputStream body) {
    if (hasQuery(uri)) return error(400);
    // Reject framed GET entities before reading; some HTTP containers wait for an absent EOF.
    if (transferEncoding != null || (length != null && !"0".equals(length))) return error(400);
    try { return run(principal, "GET", "/v1/bconnected/group-operations/" + requestId, type, encoding,
        body == null ? new byte[0] : bounded(body)); }
    catch (TooLarge oversized) { return error(413); }
    catch (IOException unavailable) { return error(503); }
  }
  @HEAD @Path("/groups") public Response noHeadCreate() { return error(405); }
  @HEAD @Path("/groups/{groupId}/state") public Response noHeadState() { return error(405); }
  @HEAD @Path("/groups/{groupId}/changes") public Response noHeadChange() { return error(405); }
  @HEAD @Path("/group-operations/{requestId}") public Response noHeadOutcome() { return error(405); }
  @OPTIONS @Path("/groups") public Response noOptionsCreate() { return error(405); }
  @OPTIONS @Path("/groups/{groupId}/state") public Response noOptionsState() { return error(405); }
  @OPTIONS @Path("/groups/{groupId}/changes") public Response noOptionsChange() { return error(405); }
  @OPTIONS @Path("/group-operations/{requestId}") public Response noOptionsOutcome() { return error(405); }
  private static boolean hasQuery(UriInfo uri) { return uri.getRequestUri().getRawQuery() != null; }
  private Response post(AuthenticatedDevice principal, String path, String type, String encoding, InputStream input) {
    if (input == null) return error(400);
    try { return run(principal, "POST", path, type, encoding, bounded(input)); }
    catch (TooLarge oversized) { return error(413); }
    catch (IOException unavailable) { return error(503); }
  }
  private Response run(AuthenticatedDevice principal, String method, String path, String type, String encoding, byte[] body) {
    try {
      var result = dispatch.execute(principal, method, path, type, encoding, body);
      return Response.status(result.status()).type("application/json").entity(result.json()).header("Cache-Control", "no-store").build();
    } catch (GroupDispatchService.Failure failure) { return error(failure.status()); }
  }
  private static byte[] bounded(InputStream input) throws IOException {
    var out = new ByteArrayOutputStream();
    byte[] chunk = new byte[4096]; int read;
    while ((read = input.read(chunk)) != -1) {
      if (read > GroupDispatchRequest.MAX_BODY_BYTES - out.size()) throw new TooLarge();
      out.write(chunk, 0, read);
    }
    return out.toByteArray();
  }
  private static Response error(int code) {
    return Response.status(code).type("application/json").entity("{\"error\":\"group_unavailable\"}")
        .header("Cache-Control", "no-store").build();
  }
  private static final class TooLarge extends IOException {}
}
