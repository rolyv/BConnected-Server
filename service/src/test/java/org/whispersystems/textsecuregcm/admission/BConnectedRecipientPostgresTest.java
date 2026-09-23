// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import java.net.URI;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.controllers.BConnectedRecipientController;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Real SQL/account authentication and Jersey dispatch; synthetic private entitlement only. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class BConnectedRecipientPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  ApplicationHandler jersey;
  UUID recipient;
  RateLimiter limiter;
  AuthenticatedDevice original;
  boolean retainOriginal;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    // Reuse only the synthetic two-account fixture setup, with no queue or push collaborators.
    var pair = new AdmissionSendPostgresTest();
    pair.fixture = fixture; pair.recipientAci = recipient = UUID.randomUUID(); pair.cloneRecipient();
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    original = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    var rates = mock(RateLimiters.class); limiter = mock(RateLimiter.class);
    when(rates.getPreKeysLimiter()).thenReturn(limiter);
    var live = AccountAuthenticator.withAdmission(fixture.gate);
    var auth = mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call -> retainOriginal
        ? Optional.of(original) : live.authenticate(call.getArgument(0)));
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new org.whispersystems.textsecuregcm.filters.DmAlphaRequestPolicy(false))
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
            .setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .register(new BConnectedRecipientController(fixture.gate, rates)));
  }

  @AfterEach void close() throws Exception {
    if (jersey != null) jersey.onShutdown(null);
    if (fixture != null) fixture.close();
  }

  ContainerResponse lookup(String target, boolean authenticated) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"),
        URI.create("http://localhost/v1/bconnected/recipients/" + target), "GET",
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), jersey.getConfiguration());
    if (authenticated) request.header("Authorization",
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }

  @Test void resolvesOnlyTheSharedAciWithNoPhoneOrMemberMetadata() throws Exception {
    var response = lookup(recipient.toString(), true);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
    assertThat(SystemMapper.jsonMapper().writeValueAsString(response.getEntity()))
        .isEqualTo("{\"aci\":\"" + recipient + "\",\"deviceId\":1}");
    verify(limiter).validate(fixture.aci);
  }

  @Test void anonymousLookupNeverReachesTargetOrLimiter() throws Exception {
    int before = fixture.requests.get();
    assertThat(lookup(recipient.toString(), false).getStatus()).isEqualTo(401);
    assertThat(fixture.requests.get()).isEqualTo(before);
    verifyNoInteractions(limiter);
  }

  @ParameterizedTest @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", "00000000-0000-0000-0000-000000000000",
      "ABCDEF00-0000-0000-0000-000000000001", "PNI:00000000-0000-0000-0000-000000000001"})
  void rejectsNonCanonicalAci(String target) throws Exception {
    assertThat(lookup(target, true).getStatus()).isEqualTo(target.equals(new UUID(0, 0).toString()) ? 400 : 503);
    verifyNoInteractions(limiter);
  }

  @Test void unknownAndSuspendedRecipientsAreUnavailable() throws Exception {
    assertThat(lookup(UUID.randomUUID().toString(), true).getStatus()).isEqualTo(404);
    fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + recipient + "'");
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(404);
  }

  @Test void targetProviderOutageDoesNotMasqueradeAsMissingRecipient() throws Exception {
    retainOriginal = true; fixture.httpStatus = 503;
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(503);
  }

  @Test void limiterWaitCannotRefreshExpiredCaller() throws Exception {
    retainOriginal = true;
    doAnswer(_ -> { fixture.flow.http.advance(4000); return null; }).when(limiter).validate(any(UUID.class));
    int before = fixture.requests.get();
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(503);
    assertThat(fixture.requests.get()).isEqualTo(before);
  }

  @Test void recipientWaitCannotRefreshExpiredCaller() throws Exception {
    retainOriginal = true;
    fixture.duringHttp = () -> fixture.flow.http.advance(4000);
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(503);
  }

  @Test void callerSuspensionDuringRecipientLookupSuppressesResult() throws Exception {
    retainOriginal = true;
    fixture.duringHttp = () -> fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + fixture.aci + "'");
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(401);
  }

  @Test void recipientSuspensionDuringLookupSuppressesResult() throws Exception {
    retainOriginal = true;
    fixture.duringHttp = () -> fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp() WHERE aci='" + recipient + "'");
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(404);
  }

  @Test void missingConfirmationCannotResolve() throws Exception {
    fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL WHERE permit_id="
        + "(SELECT permit_id FROM signal.admissions WHERE aci='" + recipient + "')");
    assertThat(lookup(recipient.toString(), true).getStatus()).isEqualTo(404);
  }
}
