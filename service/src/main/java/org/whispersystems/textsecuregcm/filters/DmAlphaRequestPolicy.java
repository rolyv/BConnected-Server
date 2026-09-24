// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.filters;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.net.URI;
import java.util.Objects;

/**
 * Exact request allowlist for the one-to-one messaging alpha. This filter is an opt-in route
 * boundary, not an authentication or account-entitlement check. The owning runtime must install it
 * on each relevant Jersey surface; enrollment should be enabled on REST only.
 */
@Provider
@PreMatching
public final class DmAlphaRequestPolicy implements ContainerRequestFilter {
  private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
  private static final String ACI = UUID;
  private static final String OPERATION = UUID;
  private static final String PROFILE_VERSION = "[0-9a-f]{64}";
  // ProfileController decodes this route component with HexFormat.parseHex.
  private static final String CREDENTIAL_REQUEST = "(?:[0-9a-fA-F]{2}){1,1024}";

  private final boolean allowEnrollment;

  /** Jersey's default construction is deny-by-default for first-account enrollment. */
  public DmAlphaRequestPolicy() {
    this(false);
  }

  /**
   * @param allowEnrollment true only for the explicitly owned REST endpoint; pass false for
   *     WebSocket/Jersey surfaces.
   */
  public DmAlphaRequestPolicy(boolean allowEnrollment) {
    this.allowEnrollment = allowEnrollment;
  }

  @Override
  public void filter(ContainerRequestContext request) throws IOException {
    Objects.requireNonNull(request);
    URI uri = request.getUriInfo().getRequestUri();
    String path = uri.getRawPath();
    String method = request.getMethod();
    String query = uri.getRawQuery();

    if (allowed(method, path, query)) return;

    request.abortWith(Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .header("Cache-Control", "no-store")
        .build());
  }

  private boolean allowed(String method, String path, String query) {
    if (method == null || path == null) return false;

    if (allowEnrollment && "POST".equals(method)
        && ("/v1/bconnected/enrollment/begin".equals(path)
            || "/v1/bconnected/signup/begin".equals(path)
            || path.matches("/v1/bconnected/signup/" + OPERATION + "/(?:send-code|check-code|status|supersede|supersession-status)")
            || path.matches("/v1/bconnected/enrollment/" + OPERATION
                + "/(?:send-code|check-code|complete|status)"))) {
      return noQuery(query);
    }

    if ("PUT".equals(method)
        && path.matches("/v1/bconnected/keys/initial/" + OPERATION)) {
      return oneOf(query, "identity=aci", "identity=pni");
    }

    if ("GET".equals(method) && path.matches("/v1/bconnected/recipients/" + ACI)) {
      return noQuery(query);
    }

    if ("GET".equals(method) && "/v1/accounts/whoami".equals(path)) {
      return noQuery(query);
    }
    if ("PUT".equals(method) && "/v1/accounts/attributes/".equals(path)) {
      return noQuery(query);
    }

    if ("PUT".equals(method) && ("/v1/profile".equals(path) || "/v1/profile/".equals(path))) {
      return noQuery(query);
    }
    if ("GET".equals(method) && path.matches("/v1/profile/" + ACI)) {
      return noQuery(query);
    }
    if ("GET".equals(method)
        && path.matches("/v1/profile/" + ACI + "/" + PROFILE_VERSION)) {
      return noQuery(query);
    }
    if ("GET".equals(method)
        && path.matches("/v1/profile/" + ACI + "/" + PROFILE_VERSION + "/" + CREDENTIAL_REQUEST)) {
      return oneOf(query, "credentialType=expiringProfileKey");
    }

    if ("GET".equals(method) && "/v2/keys".equals(path)) {
      return noQuery(query) || oneOf(query, "identity=aci", "identity=pni");
    }
    if ("PUT".equals(method) && "/v2/keys".equals(path)) {
      return noQuery(query) || oneOf(query, "identity=aci", "identity=pni");
    }
    if ("GET".equals(method) && path.matches("/v2/keys/" + ACI + "/1")) {
      return noQuery(query);
    }

    // Remote config is authenticated and has no query parameters in this controller.
    if ("GET".equals(method) && "/v2/config".equals(path)) {
      return noQuery(query);
    }

    // The current message REST controller only sends a single-recipient PUT. Incoming delivery
    // and acknowledgements use the authenticated WebSocket/gRPC stream, not REST GET/DELETE paths.
    if ("PUT".equals(method) && path.matches("/v1/messages/" + ACI)) {
      return noQuery(query) || oneOf(query, "story=false");
    }

    if ("GET".equals(method) && "/v1/keepalive".equals(path)) {
      return noQuery(query);
    }

    return false;
  }

  private static boolean noQuery(String query) {
    return query == null;
  }

  /** Exact raw query matching rejects duplicates, unknown keys, encodings, and reordered extras. */
  private static boolean oneOf(String query, String... allowed) {
    if (query == null) return false;
    for (String candidate : allowed) {
      if (candidate.equals(query)) return true;
    }
    return false;
  }
}
