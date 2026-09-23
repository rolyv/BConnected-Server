// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol;
import org.whispersystems.textsecuregcm.groups.GroupDispatchService;
import org.whispersystems.textsecuregcm.groups.GroupOriginalProofRegistry;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Exercises Jersey route matching, Basic authentication and the original-proof dispatch together. */
@ExtendWith(DropwizardExtensionsSupport.class)
class GroupDispatchControllerTest {
  private final UUID aci = AuthHelper.VALID_UUID;
  private final AdmissionEntitlementGate.DeviceAuthorization proof = mock(AdmissionEntitlementGate.DeviceAuthorization.class);
  private final GroupOriginalProofRegistry registry = new GroupOriginalProofRegistry(16);
  private final List<String> handles = new ArrayList<>();
  private final List<byte[]> bodies = new ArrayList<>();
  private final AtomicBoolean revokeAfterDispatch = new AtomicBoolean();
  private final AdmissionServiceClient.Binding originalBinding = new AdmissionServiceClient.Binding(UUID.randomUUID(), 1,
      UUID.randomUUID(), GroupBridgeProtocol.encode(new byte[32]), aci);
  private final GroupDispatchService dispatcher = new GroupDispatchService(registry, (method, path, body, handle, deadline, current) -> {
    current.run();
    handles.add(handle); bodies.add(body);
    if (revokeAfterDispatch.get())
      when(proof.groupOperationBinding()).thenReturn(new AdmissionServiceClient.Binding(UUID.randomUUID(), 2,
          UUID.randomUUID(), GroupBridgeProtocol.encode(new byte[32]), aci));
    final String json;
    if (path.endsWith("/state")) {
      try {
        String nonce = SystemMapper.jsonMapper().readTree(body).get("requestNonce").textValue();
        json = "{\"requestNonce\":\"" + nonce + "\",\"nativeGroup\":\"AQ\",\"manifest\":\"AQ.AQ.AQ\"}";
      } catch (Exception invalid) { throw new AssertionError(invalid); }
    } else {
      final String groupId;
      if (path.equals("/v1/bconnected/groups")) {
        try {
          byte[] params = java.util.Base64.getUrlDecoder().decode(SystemMapper.jsonMapper().readTree(body)
              .get("groupPublicParams").textValue());
          groupId = GroupBridgeProtocol.encode(new org.signal.libsignal.zkgroup.groups.GroupPublicParams(params)
              .getGroupIdentifier().serialize());
        } catch (Exception invalid) { throw new AssertionError(invalid); }
      } else if (path.endsWith("/changes")) {
        groupId = path.substring("/v1/bconnected/groups/".length(), path.length() - "/changes".length());
      } else groupId = GroupBridgeProtocol.encode(new byte[32]);
      json = "{\"groupId\":\"" + groupId + "\",\"revision\":1,\"nativeSha256\":\"" + groupId + "\"}";
    }
    return CompletableFuture.completedFuture(new GroupDispatchService.GatewayResult(200,
        json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  });
  final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(new io.dropwizard.auth.AuthDynamicFeature(
          new io.dropwizard.auth.basic.BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
              .setRealm("fixture").setAuthenticator(credentials ->
                  aci.toString().equals(credentials.getUsername()) && AuthHelper.VALID_PASSWORD.equals(credentials.getPassword())
                      ? java.util.Optional.of(new AuthenticatedDevice(aci, (byte) 1, Instant.now(), proof))
                      : java.util.Optional.empty()).buildAuthFilter()))
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper()).setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new GroupDispatchController(dispatcher)).build();

  GroupDispatchControllerTest() {
    when(proof.remainingNanos()).thenReturn(3_900_000_000L);
    when(proof.accountProjection()).thenReturn(new AdmissionEntitlementGate.AccountProjection(aci, UUID.randomUUID(),
        "+15555550100", (byte) 1));
    when(proof.groupOperationBinding()).thenReturn(originalBinding);
  }
  @AfterEach void close() { registry.close(); }

  private jakarta.ws.rs.client.Invocation.Builder request(String path, boolean authenticated) {
    var builder = resources.getJerseyTest().target(path).request();
    if (authenticated) builder.header("Authorization", AuthHelper.getAuthHeader(aci, AuthHelper.VALID_PASSWORD));
    return builder;
  }
  private String stateBody(String nonce, String params) {
    return "{\"requestNonce\":\"" + nonce + "\",\"groupPublicParams\":\"" + params
        + "\",\"groupAuthPresentation\":\"AQ\"}";
  }
  @Test void authenticatedStateRouteRetainsExactBodyAndFreshHandleForIdenticalRetry() {
    var group = GroupSecretParams.generate().getPublicParams();
    String id = GroupBridgeProtocol.encode(group.getGroupIdentifier().serialize());
    String body = stateBody(UUID.randomUUID().toString(), GroupBridgeProtocol.encode(group.serialize()));
    String path = "/v1/bconnected/groups/" + id + "/state";
    for (int i = 0; i < 2; i++) {
      try (var response = request(path, true).post(Entity.entity(body, "application/json"))) {
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
      }
    }
    assertThat(handles).hasSize(2).doesNotHaveDuplicates();
    assertThat(bodies).allSatisfy(b -> assertThat(new String(b, java.nio.charset.StandardCharsets.UTF_8)).isEqualTo(body));
  }
  @Test void missingAuthenticationCannotReachDispatcher() {
    try (var response = request("/v1/bconnected/group-operations/" + UUID.randomUUID(), false).get()) {
      assertThat(response.getStatus()).isEqualTo(401);
    }
    assertThat(handles).isEmpty();
  }
  @Test void createAndOnlyFirstTwoChangeVariantsReachExactRoutes() {
    var group = GroupSecretParams.generate().getPublicParams();
    String id = GroupBridgeProtocol.encode(group.getGroupIdentifier().serialize());
    String params = GroupBridgeProtocol.encode(group.serialize());
    String requestId = UUID.randomUUID().toString();
    String create = "{\"requestId\":\"" + requestId + "\",\"groupPublicParams\":\"" + params
        + "\",\"groupAuthPresentation\":\"AQ\",\"nativeGroup\":\"AQ\"}";
    try (var response = request("/v1/bconnected/groups", true).post(Entity.entity(create, "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    String common = "{\"requestId\":\"" + UUID.randomUUID() + "\",\"expectedRevision\":1,"
        + "\"groupPublicParams\":\"" + params + "\",\"groupAuthPresentation\":\"AQ\",\"kind\":\"";
    try (var response = request("/v1/bconnected/groups/" + id + "/changes", true)
        .post(Entity.entity(common + "ANNOUNCEMENTS\",\"enabled\":true}", "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    try (var response = request("/v1/bconnected/groups/" + id + "/changes", true)
        .post(Entity.entity(common + "TERMINATE\"}", "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    try (var response = request("/v1/bconnected/groups/" + id + "/changes", true)
        .post(Entity.entity(common + "INVITE\"}", "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    assertThat(handles).hasSize(3);
  }
  @Test void wrongGroupBindingAndUnknownFieldsFailBeforeHandleMinting() {
    var group = GroupSecretParams.generate().getPublicParams();
    String body = stateBody(UUID.randomUUID().toString(), GroupBridgeProtocol.encode(group.serialize()));
    try (var response = request("/v1/bconnected/groups/" + GroupBridgeProtocol.encode(new byte[32]) + "/state", true)
        .post(Entity.entity(body, "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    try (var response = request("/v1/bconnected/groups/" + GroupBridgeProtocol.encode(group.getGroupIdentifier().serialize()) + "/state", true)
        .post(Entity.entity(body.substring(0, body.length() - 1) + ",\"actorAci\":\"" + aci + "\"}", "application/json"))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    assertThat(handles).isEmpty();
  }
  @Test void outcomeUsesAuthenticatedGetAndRejectsNoncanonicalId() {
    String id = UUID.randomUUID().toString();
    try (var response = request("/v1/bconnected/group-operations/" + id, true).get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    try (var response = request("/v1/bconnected/group-operations/" + id.toUpperCase(), true).get()) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    assertThat(handles).hasSize(1);
    assertThat(bodies.getFirst()).isEmpty();
  }
  @Test void outcomeRejectsQueryBodyAndImplicitMethodsAtRealRoute() throws Exception {
    String path = "/v1/bconnected/group-operations/" + UUID.randomUUID();
    try (var response = request(path + "?actorAci=" + aci, true).get()) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    var raw = java.net.http.HttpRequest.newBuilder(resources.getJerseyTest().target(path).getUri())
        .header("Authorization", AuthHelper.getAuthHeader(aci, AuthHelper.VALID_PASSWORD))
        .timeout(java.time.Duration.ofSeconds(3))
        .method("GET", java.net.http.HttpRequest.BodyPublishers.ofString("x")).build();
    var bodyResponse = java.net.http.HttpClient.newBuilder().version(java.net.http.HttpClient.Version.HTTP_1_1)
        .build().send(raw, java.net.http.HttpResponse.BodyHandlers.ofString());
    assertThat(bodyResponse.statusCode()).isEqualTo(400);
    try (var head = request(path, true).method("HEAD")) { assertThat(head.getStatus()).isEqualTo(405); }
    try (var options = request(path, true).options()) { assertThat(options.getStatus()).isEqualTo(405); }
    assertThat(handles).isEmpty();
  }
  @Test void changedOriginalBindingAfterPrivateResultSuppressesResponse() {
    revokeAfterDispatch.set(true);
    try (var response = request("/v1/bconnected/group-operations/" + UUID.randomUUID(), true).get()) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.readEntity(String.class)).doesNotContain("groupId", "nativeSha256");
    }
    assertThat(handles).hasSize(1);
  }
  @Test void accountRateIsBoundedAcrossRepeatedRequests() {
    var principal = new AuthenticatedDevice(aci, (byte) 1, Instant.now(), proof);
    for (int i = 0; i < 10; i++)
      dispatcher.execute(principal, "GET", "/v1/bconnected/group-operations/" + UUID.randomUUID(), null, null, new byte[0]);
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> dispatcher.execute(principal, "GET",
        "/v1/bconnected/group-operations/" + UUID.randomUUID(), null, null, new byte[0]))
        .isInstanceOf(GroupDispatchService.Failure.class)
        .satisfies(failure -> assertThat(((GroupDispatchService.Failure) failure).status()).isEqualTo(429));
  }
}
