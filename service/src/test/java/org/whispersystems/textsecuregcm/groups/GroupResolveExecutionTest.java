// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.whispersystems.textsecuregcm.groups.GroupResolveTestSupport.*;

import com.google.auth.oauth2.TokenVerifier;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.*;

class GroupResolveExecutionTest {
  final AdmissionEntitlementGate.DeviceAuthorization proof = mock(AdmissionEntitlementGate.DeviceAuthorization.class);
  final UUID aci = UUID.randomUUID();
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final Operation operation = new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary);
  GroupResolveExecutionTest() {
    when(proof.remainingNanos()).thenReturn(3_900_000_000L);
    when(proof.accountProjection()).thenReturn(new AdmissionEntitlementGate.AccountProjection(aci, UUID.randomUUID(), "+15555550100", (byte) 1));
    when(proof.groupOperationBinding()).thenReturn(new AdmissionServiceClient.Binding(UUID.randomUUID(), 1, UUID.randomUUID(), binary, aci));
  }
  byte[] call(GroupResolveEndpoint endpoint, GroupOriginalProofRegistry.Ticket ticket) throws Exception {
    return endpoint.resolve("POST", GroupBridgeProtocol.RESOLVE_PATH, "application/json", null, token(),
        GroupBridgeProtocol.encode(new ResolveRequest(ticket.handle(), binary, operation)));
  }
  static void awaitIgnoringInterrupts(CountDownLatch release) {
    boolean interrupted = false;
    while (true) {
      try { release.await(); break; } catch (InterruptedException ignored) { interrupted = true; }
    }
    if (interrupted) Thread.currentThread().interrupt();
  }
  @Test void lateProviderCannotConsumeHandleAndCancelledQueueDoesNotAccumulate() throws Exception {
    var release = new CountDownLatch(1);
    var finished = new CountDownLatch(1);
    var verifier = mock(TokenVerifier.class);
    when(verifier.verify(anyString())).thenAnswer(invocation -> {
      awaitIgnoringInterrupts(release);
      try { return verifier().verify(invocation.getArgument(0)); } finally { finished.countDown(); }
    });
    try (var registry = new GroupOriginalProofRegistry(1);
         var endpoint = new GroupResolveEndpoint(registry, ORIGIN, SUBJECT, verifier, CLOCK, Duration.ofMillis(100), 1, 1);
         var ticket = registry.retain(proof, operation)) {
      for (int i = 0; i < 3; i++) {
        assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class);
        assertThat(endpoint.queuedVerifications()).isZero();
      }
      verify(verifier, times(1)).verify(anyString());
      release.countDown(); assertThat(finished.await(1, TimeUnit.SECONDS)).isTrue();
      assertThat(registry.retainedCount()).isEqualTo(1);
      assertThat(resolve(registry, new ResolveRequest(ticket.handle(), binary, operation)).membership().aci()).isEqualTo(aci);
    } finally { release.countDown(); }
  }
  @Test void saturationRejectsImmediatelyAndShutdownReleasesWaiters() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
    var verifier = mock(TokenVerifier.class);
    when(verifier.verify(anyString())).thenAnswer(invocation -> {
      entered.countDown(); awaitIgnoringInterrupts(release); return verifier().verify(invocation.getArgument(0));
    });
    try (var registry = new GroupOriginalProofRegistry(1);
         var endpoint = new GroupResolveEndpoint(registry, ORIGIN, SUBJECT, verifier, CLOCK, Duration.ofSeconds(1), 1, 1);
         var ticket = registry.retain(proof, operation);
         var callers = Executors.newVirtualThreadPerTaskExecutor()) {
      var first = callers.submit(() -> assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class));
      assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
      var second = callers.submit(() -> assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class));
      long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
      while (endpoint.queuedVerifications() == 0 && System.nanoTime() < until) Thread.sleep(1);
      assertThat(endpoint.queuedVerifications()).isEqualTo(1);
      org.junit.jupiter.api.Assertions.assertTimeout(Duration.ofMillis(200),
          () -> assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class));
      endpoint.close(); first.get(200, TimeUnit.MILLISECONDS); second.get(200, TimeUnit.MILLISECONDS);
      assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class);
      verify(verifier, times(1)).verify(anyString());
      assertThat(registry.retainedCount()).isEqualTo(1);
    } finally { release.countDown(); }
  }
  @Test void malformedBodyDoesNotStartKeyFetch() throws Exception {
    var verifier = mock(TokenVerifier.class);
    try (var registry = new GroupOriginalProofRegistry(1);
         var endpoint = new GroupResolveEndpoint(registry, ORIGIN, SUBJECT, verifier, CLOCK)) {
      assertThatThrownBy(() -> endpoint.resolve("POST", GroupBridgeProtocol.RESOLVE_PATH, "application/json", null,
          token(), "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8))).isInstanceOf(IllegalArgumentException.class);
      verifyNoInteractions(verifier);
    }
  }
  @Test void verificationDoesNotRefreshExpiredOriginalProof() throws Exception {
    var verifier = mock(TokenVerifier.class);
    when(verifier.verify(anyString())).thenAnswer(invocation -> {
      doThrow(new SecurityException("expired")).when(proof).requireCurrent(aci, (byte) 1);
      return verifier().verify(invocation.getArgument(0));
    });
    try (var registry = new GroupOriginalProofRegistry(1);
         var endpoint = new GroupResolveEndpoint(registry, ORIGIN, SUBJECT, verifier, CLOCK);
         var ticket = registry.retain(proof, operation)) {
      assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class);
    }
  }
  @Test void shutdownDrainsAlreadyAdmittedResolutionAndSuppressesItsResult() throws Exception {
    var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
    try (var registry = new GroupOriginalProofRegistry(1);
         var endpoint = endpoint(registry);
         var ticket = registry.retain(proof, operation);
         var callers = Executors.newVirtualThreadPerTaskExecutor()) {
      try {
        doAnswer(_ -> { entered.countDown(); awaitIgnoringInterrupts(release); return null; })
            .when(proof).requireCurrent(aci, (byte) 1);
        var callback = callers.submit(() -> assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class));
        assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
        var stopped = callers.submit(endpoint::close);
        long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
        while (!endpoint.isClosed() && System.nanoTime() < until) Thread.sleep(1);
        assertThat(endpoint.isClosed()).isTrue(); assertThat(stopped.isDone()).isFalse();
        release.countDown(); callback.get(1, TimeUnit.SECONDS); stopped.get(1, TimeUnit.SECONDS);
        assertThatThrownBy(() -> call(endpoint, ticket)).isInstanceOf(SecurityException.class);
      } finally { release.countDown(); }
    } finally { release.countDown(); }
  }
}
