// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.Auth;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.util.HeaderUtils;

@ExtendWith(DropwizardExtensionsSupport.class)
class AccountAuthenticatorHttpTest {
  static final AccountAuthenticator AUTHENTICATOR = mock(AccountAuthenticator.class);
  static final AtomicInteger CALLS = new AtomicInteger();
  static final ResourceExtension RESOURCES = ResourceExtension.builder()
      .addProvider(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
          .setAuthenticator(AUTHENTICATOR).buildAuthFilter()))
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new Probe()).build();

  @Path("/auth-probe")
  public static class Probe {
    @GET
    public Response read(@Auth AuthenticatedDevice principal) {
      CALLS.incrementAndGet();
      return Response.ok().build();
    }
  }

  @BeforeEach
  void resetFixture() {
    reset(AUTHENTICATOR);
    CALLS.set(0);
  }

  Response request() {
    return RESOURCES.target("/auth-probe").request()
        .header("Authorization", HeaderUtils.basicAuthHeader(UUID.randomUUID().toString(), "fixture"))
        .get();
  }

  @Test
  void unavailableMembershipReturns503WithoutInvokingResource() {
    when(AUTHENTICATOR.authenticate(any())).thenThrow(new AuthenticationUnavailableException());
    try (var response = request()) {
      assertThat(response.getStatus()).isEqualTo(503);
    }
    assertThat(CALLS.get()).isZero();
  }

  @Test
  void definitiveInvalidCredentialsReturn401WithoutInvokingResource() {
    when(AUTHENTICATOR.authenticate(any())).thenReturn(Optional.empty());
    try (var response = request()) {
      assertThat(response.getStatus()).isEqualTo(401);
    }
    assertThat(CALLS.get()).isZero();
  }

  @Test
  void authenticatedPrincipalReachesResource() {
    when(AUTHENTICATOR.authenticate(any())).thenReturn(Optional.of(
        new AuthenticatedDevice(UUID.randomUUID(), (byte) 1, Instant.EPOCH)));
    try (var response = request()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    assertThat(CALLS.get()).isEqualTo(1);
  }
}
