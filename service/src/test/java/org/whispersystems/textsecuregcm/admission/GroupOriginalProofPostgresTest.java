// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.*;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.groups.*;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.*;

/** Native original device proof is retained across the cryptographically verified callback. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class GroupOriginalProofPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  final GroupOriginalProofRegistry registry = new GroupOriginalProofRegistry(2);
  final String binary = GroupBridgeProtocol.encode(new byte[32]);
  final Operation operation = new Operation("POST", Kind.STATE, binary, UUID.randomUUID(), binary);
  @BeforeEach void setup() throws Exception { fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup(); }
  @AfterEach void cleanup() throws Exception { registry.close(); if (fixture != null) fixture.close(); }
  GroupOriginalProofRegistry.Ticket retain() {
    return registry.retain(fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password()), operation);
  }
  Resolution resolve(GroupOriginalProofRegistry.Ticket ticket) throws Exception {
    return GroupResolveTestSupport.resolve(registry, new ResolveRequest(ticket.handle(), binary, operation));
  }
  @Test void nativeAuthenticatedBindingSurvivesNoRenewal() throws Exception {
    try (var ticket = retain()) {
      var r = resolve(ticket); assertThat(r.membership().aci()).isEqualTo(fixture.aci);
      assertThat(r.deviceId()).isEqualTo(1); assertThat(r.remainingNanos()).isPositive().isLessThanOrEqualTo(4_000_000_000L);
      ticket.requireCurrent();
    }
  }
  @ParameterizedTest @ValueSource(strings = {"suspend", "account", "expire"})
  void originalChangeDuringCallbackCannotAdoptFreshProof(String change) throws Exception {
    try (var ticket = retain()) {
      if (change.equals("suspend")) fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
      else if (change.equals("account")) fixture.sql("UPDATE signal.accounts SET version=version+1");
      else fixture.flow.http.advance(4000);
      assertThatThrownBy(() -> resolve(ticket)).isInstanceOf(RuntimeException.class);
      assertThatThrownBy(ticket::requireCurrent).isInstanceOf(RuntimeException.class);
    }
  }
}
