// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Kind;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Operation;

/** Bounds the Signal projection shape; native/JWS semantic validity is proven in storage/client suites. */
class GroupDispatchResultTest {
  @Test void documentedMaximumNativeAndManifestPayloadShapeFitsTwentyMegabyteEnvelope() {
    var operation = new Operation("POST", Kind.STATE, GroupBridgeProtocol.encode(new byte[32]),
        UUID.randomUUID(), GroupBridgeProtocol.encode(new byte[32]));
    String nativeState = GroupBridgeProtocol.encode(new byte[8 * 1024 * 1024]);
    String manifestPayload = GroupBridgeProtocol.encode(new byte[4 * 1024 * 1024]);
    byte[] response = ("{\"requestNonce\":\"" + operation.requestId() + "\",\"nativeGroup\":\""
        + nativeState + "\",\"manifest\":\"AQ." + manifestPayload + ".AQ\"}").getBytes(StandardCharsets.UTF_8);
    assertThatCode(() -> GroupDispatchResult.requireExact(operation, response)).doesNotThrowAnyException();
    byte[] oversized = java.util.Arrays.copyOf(response, 20 * 1024 * 1024 + 1);
    assertThatThrownBy(() -> GroupDispatchResult.requireExact(operation, oversized))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
