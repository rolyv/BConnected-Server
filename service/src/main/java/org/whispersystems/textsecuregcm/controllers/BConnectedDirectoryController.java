// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.auth.Auth;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.glassfish.jersey.server.ManagedAsync;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionKeyGuard;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.limits.RateLimiters;

/** Approved-member labels, with queries in bounded request bodies rather than URL access logs. */
@Path("/v1/bconnected/directory")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class BConnectedDirectoryController {
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2).maxStringLength(512)
          .maxNumberLength(10).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final AdmissionEntitlementGate gate;
  private final RateLimiters rates;

  public BConnectedDirectoryController(AdmissionEntitlementGate gate, RateLimiters rates) {
    this.gate = Objects.requireNonNull(gate); this.rates = Objects.requireNonNull(rates);
  }

  @POST @Path("/search") @ManagedAsync
  public Response search(@Auth AuthenticatedDevice principal, InputStream input) throws RateLimitExceededException {
    return directory(principal, input, false);
  }

  @POST @Path("/resolve") @ManagedAsync
  public Response resolve(@Auth AuthenticatedDevice principal, InputStream input) throws RateLimitExceededException {
    return directory(principal, input, true);
  }

  private Response directory(AuthenticatedDevice principal, InputStream input, boolean resolve)
      throws RateLimitExceededException {
    try {
      var caller = AdmissionKeyGuard.http(gate, principal);
      final Request request;
      try { request = parse(input, resolve); }
      catch (IllegalArgumentException invalid) { return response(400, null); }
      rates.getPreKeysLimiter().validate(principal.accountIdentifier());
      caller.requireCurrent(); // Rate-limit/queue waits never refresh the original device proof.
      var authorization = gate.directory(principal.admissionAuthorization(), principal.accountIdentifier(),
          principal.deviceId(), request.query(), request.offset(), request.aci());
      var page = authorization.page();
      var result = resolve
          ? response(page.members().isEmpty() ? 404 : 200, page.members().isEmpty() ? null : page.members().getFirst())
          : response(200, page);
      authorization.requireCurrent();
      return result;
    } catch (AdmissionKeyGuard.Failure failure) { throw failure.http(); }
    catch (AdmissionEntitlementGate.DeniedException denied) { return response(401, null); }
    catch (AdmissionServiceClient.AdmissionServiceException unavailable) {
      return response(unavailable.failure() == AdmissionServiceClient.Failure.DENIED ? 401 : 503, null);
    } catch (RuntimeException unavailable) { return response(503, null); }
  }

  private record Request(String query, Integer offset, UUID aci) {
    @Override public String toString() { return "DirectoryRequest[redacted]"; }
  }

  private static Request parse(InputStream input, boolean resolve) {
    try {
      byte[] bytes = input.readNBytes(2049);
      if (bytes.length == 0 || bytes.length > 2048) throw new IllegalArgumentException();
      var body = JSON.readTree(StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString());
      if (body == null || !body.isObject()) throw new IllegalArgumentException();
      var fields = new HashSet<String>(); body.fieldNames().forEachRemaining(fields::add);
      if (!fields.equals(resolve ? Set.of("aci") : Set.of("query", "offset"))) throw new IllegalArgumentException();
      if (resolve) {
        String value = text(body, "aci");
        var aci = UUID.fromString(value);
        if (!aci.toString().equals(value) || aci.equals(new UUID(0, 0))) throw new IllegalArgumentException();
        return new Request(null, null, aci);
      }
      String query = text(body, "query");
      if (query.codePointCount(0, query.length()) > 100 || query.codePoints().anyMatch(value ->
          Character.isISOControl(value) || (value >= 0xd800 && value <= 0xdfff))) throw new IllegalArgumentException();
      var offset = body.get("offset");
      if (!offset.isIntegralNumber() || !offset.canConvertToInt() || offset.intValue() < 0 || offset.intValue() > 10000)
        throw new IllegalArgumentException();
      return new Request(query, offset.intValue(), null);
    } catch (Exception invalid) { throw new IllegalArgumentException("Invalid directory request"); }
  }

  private static String text(JsonNode body, String field) {
    var value = body.get(field);
    if (value == null || !value.isTextual()) throw new IllegalArgumentException();
    return value.textValue();
  }

  private static Response response(int status, Object entity) {
    return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).header("Cache-Control", "no-store")
        .entity(entity).build();
  }
}
