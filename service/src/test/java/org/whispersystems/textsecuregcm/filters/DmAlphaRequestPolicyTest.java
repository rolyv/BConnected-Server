// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.filters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DmAlphaRequestPolicyTest {
  private static final String ACI = "8f816ea8-4f47-4fce-a8e1-544f4c1e77bc";
  private static final String OPERATION = "80e5a3b0-7a89-4e43-ae40-ec9ff4aad1e7";
  private static final String PROFILE_VERSION = "7a".repeat(32);

  @Test
  void allowsOnlyCurrentSingleDeviceDmRoutes() throws Exception {
    DmAlphaRequestPolicy policy = new DmAlphaRequestPolicy(false);
    for (Request request : new Request[] {
        new Request("PUT", "/v1/bconnected/keys/initial/" + OPERATION + "?identity=aci"),
        new Request("GET", "/v1/bconnected/recipients/" + ACI),
        new Request("GET", "/v1/accounts/whoami"),
        new Request("PUT", "/v1/accounts/attributes/"),
        new Request("PUT", "/v1/profile"),
        new Request("PUT", "/v1/profile/"),
        new Request("GET", "/v1/profile/" + ACI),
        new Request("GET", "/v1/profile/" + ACI + "/" + PROFILE_VERSION),
        new Request("GET", "/v1/profile/" + ACI + "/" + PROFILE_VERSION
            + "/a1b2c3d4?credentialType=expiringProfileKey"),
        new Request("GET", "/v2/keys?identity=pni"),
        new Request("PUT", "/v2/keys"),
        new Request("GET", "/v2/keys/" + ACI + "/1"),
        new Request("GET", "/v2/config"),
        new Request("PUT", "/v1/messages/" + ACI + "?story=false"),
        new Request("GET", "/v1/keepalive")
    }) {
      ContainerRequestContext context = context(request);
      policy.filter(context);
      verify(context, never()).abortWith(any(Response.class));
    }
  }

  @Test
  void enrollmentRequiresExplicitRestOptInAndExactActions() throws Exception {
    String base = "/v1/bconnected/enrollment/";
    for (String path : new String[] {
        base + "begin",
        base + OPERATION + "/send-code",
        base + OPERATION + "/check-code",
        base + OPERATION + "/complete",
        base + OPERATION + "/status"
    }) {
      assertAllowed(new DmAlphaRequestPolicy(true), new Request("POST", path));
      assertDenied(new DmAlphaRequestPolicy(false), new Request("POST", path));
    }
    assertDenied(new DmAlphaRequestPolicy(true), new Request("GET", base + "begin"));
    assertDenied(new DmAlphaRequestPolicy(true), new Request("POST", base + OPERATION + "/send-code/extra"));
    assertDenied(new DmAlphaRequestPolicy(true), new Request("POST", base + OPERATION + "/send-code?x=1"));
  }

  @Test
  void deniesStoriesMultiRecipientAndUnknownOrExpandedRoutes() throws Exception {
    DmAlphaRequestPolicy policy = new DmAlphaRequestPolicy(true);
    for (Request request : new Request[] {
        new Request("PUT", "/v1/messages/" + ACI + "?story=true"),
        new Request("PUT", "/v1/messages/multi_recipient"),
        new Request("GET", "/v1/messages"),
        new Request("DELETE", "/v1/messages/" + UUID.randomUUID()),
        new Request("GET", "/v2/keys/" + ACI + "/*"),
        new Request("GET", "/v2/keys/" + ACI + "/2"),
        new Request("GET", "/v2/keys?identity=aci&identity=aci"),
        new Request("GET", "/v2/keys?identity=aci&extra=1"),
        new Request("PUT", "/v1/bconnected/keys/initial/" + OPERATION),
        new Request("POST", "/v1/bconnected/enrollment/" + OPERATION + "/verify"),
        new Request("POST", "/v1/stories"),
        new Request("GET", "/v1/groups"),
        new Request("GET", "/v1/attachments"),
        new Request("POST", "/v1/accounts/username_hash/reserve")
    }) {
      assertDenied(policy, request);
    }
  }

  private static void assertAllowed(DmAlphaRequestPolicy policy, Request request) throws Exception {
    ContainerRequestContext context = context(request);
    policy.filter(context);
    verify(context, never()).abortWith(any(Response.class));
  }

  private static void assertDenied(DmAlphaRequestPolicy policy, Request request) throws Exception {
    ContainerRequestContext context = context(request);
    policy.filter(context);
    var response = org.mockito.ArgumentCaptor.forClass(Response.class);
    verify(context).abortWith(response.capture());
    assertThat(response.getValue().getStatus()).isEqualTo(503);
    assertThat(response.getValue().getHeaderString("Cache-Control")).isEqualTo("no-store");
  }

  private static ContainerRequestContext context(Request request) {
    ContainerRequestContext context = mock(ContainerRequestContext.class);
    UriInfo uriInfo = mock(UriInfo.class);
    when(context.getMethod()).thenReturn(request.method());
    when(context.getUriInfo()).thenReturn(uriInfo);
    when(uriInfo.getRequestUri()).thenReturn(URI.create("https://alpha.example" + request.target()));
    return context;
  }

  private record Request(String method, String target) {}
}
