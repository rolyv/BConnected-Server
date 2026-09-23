// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.whispersystems.textsecuregcm.groups.GroupResolveTestSupport.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.admission.AdmissionEntitlementGate;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.*;

class GroupResolveEndpointTest {
  final GroupOriginalProofRegistry registry = new GroupOriginalProofRegistry(1);
  final AdmissionEntitlementGate.DeviceAuthorization proof = mock(AdmissionEntitlementGate.DeviceAuthorization.class);
  final UUID aci = UUID.randomUUID();
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final Operation operation = new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary);
  GroupResolveEndpointTest() {
    when(proof.remainingNanos()).thenReturn(3_900_000_000L);
    when(proof.accountProjection()).thenReturn(new AdmissionEntitlementGate.AccountProjection(aci, UUID.randomUUID(), "+15555550100", (byte) 1));
    when(proof.groupOperationBinding()).thenReturn(new AdmissionServiceClient.Binding(UUID.randomUUID(), 1, UUID.randomUUID(), binary, aci));
  }
  ResolveRequest request(GroupOriginalProofRegistry.Ticket ticket) { return new ResolveRequest(ticket.handle(), binary, operation); }
  @org.junit.jupiter.api.AfterEach void cleanup() { registry.close(); }
  @Test void idleExpiredProofIsEvictedWithoutAnotherRequestAndShutdownClosesCapacity() throws Exception {
    when(proof.remainingNanos()).thenReturn(100_000_000L);
    registry.retain(proof, operation);
    long until = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(1);
    while (registry.retainedCount() != 0 && System.nanoTime() < until) Thread.sleep(10);
    assertThat(registry.retainedCount()).isZero();
    registry.close(); assertThatThrownBy(() -> registry.retain(proof, operation)).isInstanceOf(IllegalStateException.class);
  }
  @Test void signedPinnedPrincipalResolvesOriginalExactlyOnceAndDoesNotRenew() throws Exception {
    try (var ticket = registry.retain(proof, operation)) {
      var r = resolve(registry, request(ticket));
      assertThat(r.operation()).isEqualTo(operation); assertThat(r.membership().aci()).isEqualTo(aci);
      assertThat(r.remainingNanos()).isPositive().isLessThan(3_900_000_000L);
      assertThatThrownBy(() -> resolve(registry, request(ticket))).isInstanceOf(SecurityException.class);
      ticket.requireCurrent(); verify(proof, atLeast(3)).requireCurrent(aci, (byte) 1);
    }
  }
  @ParameterizedTest @ValueSource(strings = {"subject", "audience", "issuer", "expired", "future", "signature", "missing"})
  void rejectsWrongServiceIdentityWithoutConsumingHandle(String failure) throws Exception {
    try (var ticket = registry.retain(proof, operation)) {
      long now = CLOCK.instant().getEpochSecond();
      String bearer = failure.equals("missing") ? null : token(failure.equals("issuer") ? "https://evil.test" : ISSUER,
          failure.equals("audience") ? "https://wrong.test" : ORIGIN.toString(), failure.equals("subject") ? "operator" : SUBJECT,
          failure.equals("future") ? now + 20 : now - 10, failure.equals("expired") ? now - 1 : now + 3500,
          failure.equals("signature") ? keys() : KEYS);
      assertThatThrownBy(() -> endpoint(registry).resolve("POST", GroupBridgeProtocol.RESOLVE_PATH,
          "application/json", null, bearer, GroupBridgeProtocol.encode(request(ticket)))).isInstanceOf(SecurityException.class);
      assertThat(resolve(registry, request(ticket)).membership().aci()).isEqualTo(aci);
    }
  }
  @Test void capacityCloseForgeryBindingAndCompressionAreClosed() throws Exception {
    var ticket = registry.retain(proof, operation);
    assertThatThrownBy(() -> registry.retain(proof, operation)).isInstanceOf(IllegalStateException.class);
    var wrong = new ResolveRequest(ticket.handle(), binary, new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary));
    assertThatThrownBy(() -> resolve(registry, wrong)).isInstanceOf(SecurityException.class);
    assertThatThrownBy(() -> resolve(registry, request(ticket))).isInstanceOf(SecurityException.class);
    var active = registry.retain(proof, operation);
    assertThatThrownBy(() -> endpoint(registry).resolve("POST", GroupBridgeProtocol.RESOLVE_PATH,
        "application/json", "gzip", token(), GroupBridgeProtocol.encode(request(active)))).isInstanceOf(SecurityException.class);
    active.close(); assertThatThrownBy(() -> resolve(registry, request(active))).isInstanceOf(SecurityException.class);
    assertThatThrownBy(() -> resolve(registry, new ResolveRequest(binary, binary, operation))).isInstanceOf(SecurityException.class);
  }
  @Test void changedBindingAndSecondaryCannotMint() {
    when(proof.accountProjection()).thenReturn(new AdmissionEntitlementGate.AccountProjection(aci, UUID.randomUUID(), "+15555550100", (byte) 2));
    assertThatThrownBy(() -> registry.retain(proof, operation)).isInstanceOf(SecurityException.class);
  }
}
