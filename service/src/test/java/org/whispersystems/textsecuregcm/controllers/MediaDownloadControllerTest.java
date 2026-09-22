// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.media.GcsMediaDownloadService;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;

@ExtendWith(DropwizardExtensionsSupport.class)
class MediaDownloadControllerTest {
  private static final String KEY = "profiles/AAAAAAAAAAAAAAAAAAAAAA==";
  private static final GcsMediaDownloadService DOWNLOADS = mock(GcsMediaDownloadService.class);
  private static final RateLimiter LIMITER = mock(RateLimiter.class);
  private static final org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.DeviceAuthorization PROOF =
      mock(org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate.DeviceAuthorization.class);
  private static final ResourceExtension RESOURCES = ResourceExtension.builder()
      .addProvider(new io.dropwizard.auth.AuthDynamicFeature(
          new io.dropwizard.auth.basic.BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
              .setRealm("fixture").setAuthenticator(credentials ->
                  AuthHelper.VALID_UUID.toString().equals(credentials.getUsername())
                      && AuthHelper.VALID_PASSWORD.equals(credentials.getPassword())
                      ? java.util.Optional.of(new AuthenticatedDevice(AuthHelper.VALID_UUID, (byte) 1,
                          java.time.Instant.now(), PROOF)) : java.util.Optional.empty()).buildAuthFilter()))
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .addProvider(new RateLimitExceededExceptionMapper())
      .setMapper(SystemMapper.jsonMapper()).setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(controller()).build();

  private static MediaDownloadController controller() {
    var limiters = mock(RateLimiters.class);
    when(limiters.getProfileLimiter()).thenReturn(LIMITER);
    return new MediaDownloadController(DOWNLOADS, limiters);
  }

  @BeforeEach void resetMocks() { reset(DOWNLOADS, LIMITER); }

  private Response request(String key, boolean authenticated) {
    var request = RESOURCES.getJerseyTest().target("/v1/media/download").request();
    if (authenticated) request.header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD));
    return request.post(Entity.json(new MediaDownloadController.DownloadRequest(0, key)));
  }

  @Test void unauthenticatedRequestCannotMintCapability() {
    try (var response = request(KEY, false)) { assertThat(response.getStatus()).isEqualTo(401); }
    verifyNoInteractions(DOWNLOADS, LIMITER);
  }

  @Test void authorizedAccountReceivesNoStoreCapability() throws Exception {
    when(DOWNLOADS.issue(eq(0), eq(KEY), any())).thenReturn(new GcsMediaDownloadService.DownloadCapability("https://storage.googleapis.com/fixture", 123, 1024));
    try (var response = request(KEY, true)) {
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getHeaderString("Cache-Control")).contains("no-store");
      assertThat(response.getHeaderString("Pragma")).isEqualTo("no-cache");
      assertThat(response.readEntity(String.class)).contains("\"expiresAt\":123", "\"contentLength\":1024");
    }
    verify(LIMITER).validate(AuthHelper.VALID_UUID);
    verify(DOWNLOADS).issue(eq(0), eq(KEY), any());
  }

  @Test void invalidKeyCannotReachStorage() {
    try (var response = request("../another-bucket/object", true)) { assertThat(response.getStatus()).isEqualTo(400); }
    verifyNoInteractions(DOWNLOADS);
  }

  @Test void providerFailureIsSanitizedAndMissingIs404() {
    when(DOWNLOADS.issue(eq(0), eq(KEY), any())).thenThrow(new IllegalStateException("secret-policy-provider-url"));
    try (var response = request(KEY, true)) {
      assertThat(response.getStatus()).isEqualTo(503);
      assertThat(response.readEntity(String.class)).doesNotContain("secret-policy-provider-url");
    }
    doThrow(new GcsMediaDownloadService.MissingMediaException()).when(DOWNLOADS).issue(eq(0), eq(KEY), any());
    try (var response = request(KEY, true)) { assertThat(response.getStatus()).isEqualTo(404); }
  }

  @Test void rateLimitedAccountCannotReachStorage() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(10))).when(LIMITER).validate(AuthHelper.VALID_UUID);
    try (var response = request(KEY, true)) { assertThat(response.getStatus()).isEqualTo(429); }
    verifyNoInteractions(DOWNLOADS);
  }
}
