// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashSet;
import java.util.Set;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Kind;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Operation;

/** Private response projection: never pass arbitrary Groups JSON through to an owned client. */
public final class GroupDispatchResult {
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2).maxStringLength(20 * 1024 * 1024)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private GroupDispatchResult() {}

  public static void requireExact(Operation operation, byte[] body) {
    try {
      if (body == null || body.length == 0 || body.length > 20 * 1024 * 1024) throw invalid();
      JsonNode n = JSON.readTree(body);
      if (operation.kind() == Kind.STATE) {
        keys(n, "requestNonce", "nativeGroup", "manifest");
        if (!operation.requestId().equals(GroupBridgeProtocol.uuid(string(n, "requestNonce")))) throw invalid();
        binary(string(n, "nativeGroup"), 8 * 1024 * 1024);
        String jws = string(n, "manifest");
        if (jws.length() > 6 * 1024 * 1024 || !jws.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"))
          throw invalid();
      } else {
        keys(n, "groupId", "revision", "nativeSha256");
        String id = string(n, "groupId"); GroupBridgeProtocol.binary(id, 32);
        if (operation.kind() != Kind.OUTCOME && !id.equals(operation.groupId())) throw invalid();
        JsonNode revision = n.get("revision");
        if (!revision.isIntegralNumber() || !revision.canConvertToLong() || revision.longValue() < 0
            || revision.longValue() > 0xffff_ffffL) throw invalid();
        GroupBridgeProtocol.binary(string(n, "nativeSha256"), 32);
      }
    } catch (Exception ignored) { throw invalid(); }
  }
  private static void keys(JsonNode n, String... names) {
    if (n == null || !n.isObject()) throw invalid();
    Set<String> found = new HashSet<>(); n.fieldNames().forEachRemaining(found::add);
    if (!found.equals(Set.of(names))) throw invalid();
  }
  private static String string(JsonNode n, String key) {
    JsonNode v = n.get(key); if (v == null || !v.isTextual()) throw invalid(); return v.textValue();
  }
  private static void binary(String s, int max) {
    if (s.isEmpty() || s.length() > (max * 8 + 5) / 6 || !s.matches("[A-Za-z0-9_-]+")) throw invalid();
    byte[] value = java.util.Base64.getUrlDecoder().decode(s);
    if (value.length > max || !GroupBridgeProtocol.encode(value).equals(s)) throw invalid();
  }
  private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid private group result"); }
}
