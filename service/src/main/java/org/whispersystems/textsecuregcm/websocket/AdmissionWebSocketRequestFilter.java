// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.websocket;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import org.whispersystems.textsecuregcm.auth.AuthenticationUnavailableException;
import org.whispersystems.websocket.WebSocketResourceProvider;
import org.whispersystems.websocket.WebSocketSecurityContext;

/** Installed globally on the pilot chat WebSocket Jersey application, including Optional-auth routes. */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public final class AdmissionWebSocketRequestFilter implements ContainerRequestFilter {
  private final AdmissionWebSocketSessionManager sessions;

  public AdmissionWebSocketRequestFilter(AdmissionWebSocketSessionManager sessions) {
    this.sessions = sessions;
  }

  @Override
  public void filter(ContainerRequestContext request) {
    try {
      if (!(request.getSecurityContext() instanceof WebSocketSecurityContext socket)) {
        request.abortWith(Response.status(401).build());
        return;
      }
      // The provider's original upgrade principal does not renew. Replace only this request's
      // injection property with the exact proof just checked; never reread it from mutable context.
      var admitted = sessions.authorizeRequest(socket.getSessionContext());
      var current = admitted.principal();
      request.setProperty(WebSocketResourceProvider.REUSABLE_AUTH_PROPERTY, Optional.of(current));
      request.setSecurityContext(new AdmittedSecurityContext(socket.getSessionContext(), admitted));
    } catch (AuthenticationUnavailableException unavailable) {
      request.abortWith(Response.status(503).build());
    } catch (jakarta.ws.rs.NotAuthorizedException denied) {
      request.abortWith(Response.status(401).build());
    }
  }

  /** Jersey invokes this hook after ManagedAsync dispatch and parameter validation. */
  private static final class AdmittedSecurityContext extends WebSocketSecurityContext
      implements org.glassfish.jersey.server.SubjectSecurityContext {
    private final AdmissionWebSocketSessionManager.RequestAuthorization admitted;

    AdmittedSecurityContext(org.whispersystems.websocket.session.WebSocketSessionContext context,
        AdmissionWebSocketSessionManager.RequestAuthorization admitted) {
      super(new org.whispersystems.websocket.session.ContextPrincipal(context));
      this.admitted = admitted;
    }

    @Override public java.security.Principal getUserPrincipal() { return admitted.principal(); }

    @Override public Object doAsSubject(java.security.PrivilegedAction action) {
      admitted.requireCurrent();
      return action.run();
    }
  }
}
