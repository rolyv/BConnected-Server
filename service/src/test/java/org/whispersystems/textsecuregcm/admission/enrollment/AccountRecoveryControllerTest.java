// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import java.io.*;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.whispersystems.textsecuregcm.admission.AccountRecoveryService;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.VirtualExecutorServiceProvider;

class AccountRecoveryControllerTest {
  AccountRecoveryService service;
  MobileEnrollmentBodyReader bodies;
  ApplicationHandler jersey;
  ObjectNode body;
  UUID id = UUID.randomUUID();
  String auth;

  @BeforeEach
  void setup() throws Exception {
    service = mock(AccountRecoveryService.class);
    bodies = new MobileEnrollmentBodyReader(Duration.ofSeconds(2), 4);
    try (var source = getClass().getResourceAsStream("/admission/mobile-enrollment-v1.json")) {
      body = (ObjectNode) SystemMapper.jsonMapper().readTree(source);
    }
    body.set("recoveryAttemptId", body.remove("registrationAttemptId"));
    body.remove("memberId");
    body.remove("bindingChallenge");
    auth =
        "Basic "
            + Base64.getEncoder()
                .encodeToString(
                    "+13055550123:new-password".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    when(service.execute(any(), any(), any(), any(), any(), any()))
        .thenReturn(
            new Result(
                200,
                new AccountRecoveryService.Observation(
                    id, "verification", false, 0L, null, 600, false, null, null, null, null)));
    jersey =
        new ApplicationHandler(
            new ResourceConfig()
                .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
                .register(new VirtualExecutorServiceProvider("recovery-rest-test", 4))
                .register(new AccountRecoveryController(service, bodies, request -> "192.0.2.1")));
  }

  @AfterEach
  void close() {
    if (jersey != null) jersey.onShutdown(null);
    if (bodies != null) bodies.close();
  }

  record Reply(int status, JsonNode body, String retry) {}

  Reply post(String suffix, String header) throws Exception {
    var request =
        new ContainerRequest(
            URI.create("http://localhost/"),
            URI.create("http://localhost/v1/bconnected/recovery/" + suffix),
            "POST",
            null,
            new MapPropertiesDelegate(),
            null);
    if (header != null) request.header("Authorization", header);
    request.header("Content-Type", "application/json");
    request.setEntityStream(
        new ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(body)));
    var bytes = new ByteArrayOutputStream();
    var response = jersey.apply(request, bytes).get(10, TimeUnit.SECONDS);
    assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
    return new Reply(
        response.getStatus(),
        SystemMapper.jsonMapper().readTree(bytes.toByteArray()),
        response.getHeaderString("Retry-After"));
  }

  @Test
  void exactUniformWireResponseContainsAllNullableFields() throws Exception {
    var reply = post("begin", auth);
    assertThat(reply.status).isEqualTo(200);
    var fields = new HashSet<String>();
    reply.body.fieldNames().forEachRemaining(fields::add);
    assertThat(fields)
        .containsExactlyInAnyOrder(
            "recoveryId",
            "state",
            "phoneVerified",
            "nextSmsSeconds",
            "nextCheckSeconds",
            "expiresInSeconds",
            "registrationAuthorized",
            "memberId",
            "account",
            "fullName",
            "graduationYear");
    assertThat(reply.body.get("account").isNull()).isTrue();
    verify(service)
        .execute(
            eq(MobileEnrollmentParser.Operation.BEGIN),
            isNull(),
            argThat(
                value ->
                    value.password().equals("new-password")
                        && value.number().equals("+13055550123")
                        && value.attempt().equals(body.get("recoveryAttemptId").asText())),
            isNull(),
            eq("192.0.2.1"),
            isNull());
  }

  @Test
  void malformedCredentialsAndCapabilityFieldsCannotReachService() throws Exception {
    assertThat(post("begin", null).status).isEqualTo(401);
    body.put("memberId", UUID.randomUUID().toString());
    assertThat(post("begin", auth).status).isEqualTo(400);
    verifyNoInteractions(service);
  }

  @Test
  void statusSelectsCanonicalOperationAndNeverPassesUntrustedSource() throws Exception {
    assertThat(post(id + "/status", auth).status).isEqualTo(200);
    verify(service)
        .execute(
            eq(MobileEnrollmentParser.Operation.STATUS),
            eq(id),
            any(),
            isNull(),
            isNull(),
            isNull());
  }

  @Test
  void typedRetryResponseMatchesStandardContract() throws Exception {
    when(service.execute(any(), any(), any(), any(), any(), any()))
        .thenReturn(error(Code.RATE_LIMITED, 12L));
    var reply = post(id + "/send-code", auth);
    assertThat(reply.status).isEqualTo(429);
    assertThat(reply.body.get("code").asText()).isEqualTo("RATE_LIMITED");
    assertThat(reply.retry).isEqualTo("12");
  }
}
