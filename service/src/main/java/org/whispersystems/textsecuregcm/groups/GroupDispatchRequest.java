// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Kind;
import org.whispersystems.textsecuregcm.groups.GroupBridgeProtocol.Operation;

/** The public request shape needed to bind a private original proof. Native ZK validation stays in Groups. */
public final class GroupDispatchRequest {
  public static final int MAX_BODY_BYTES = 64 * 1024;
  private static final String GROUPS = "/v1/bconnected/groups";
  private static final String OUTCOMES = "/v1/bconnected/group-operations/";
  private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2).maxStringLength(MAX_BODY_BYTES)
          .maxNumberLength(20).build()).build()).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  private GroupDispatchRequest() {}

  public static Operation parse(String method, String path, String contentType, String contentEncoding, byte[] body) {
    if (body == null || body.length > MAX_BODY_BYTES || contentEncoding != null || path == null) throw invalid();
    if ("GET".equals(method) && path.startsWith(OUTCOMES)) {
      if (body.length != 0 || contentType != null) throw invalid();
      return new Operation("GET", Kind.OUTCOME, "", GroupBridgeProtocol.uuid(path.substring(OUTCOMES.length())),
          GroupBridgeProtocol.digest(body));
    }
    if (!"POST".equals(method) || !"application/json".equals(contentType) || body.length == 0) throw invalid();
    try {
      JsonNode n = JSON.readTree(body);
      Kind kind;
      String suppliedId = null;
      if (GROUPS.equals(path)) {
        kind = Kind.CREATE;
        keys(n, "requestId", "groupPublicParams", "groupAuthPresentation", "nativeGroup");
      } else {
        if (!path.startsWith(GROUPS + "/")) throw invalid();
        String[] suffix = path.substring(GROUPS.length() + 1).split("/", -1);
        if (suffix.length != 2) throw invalid();
        suppliedId = suffix[0];
        GroupBridgeProtocol.binary(suppliedId, 32);
        if ("state".equals(suffix[1])) {
          kind = Kind.STATE;
          keys(n, "requestNonce", "groupPublicParams", "groupAuthPresentation");
        } else if ("changes".equals(suffix[1])) {
          kind = Kind.valueOf(string(n, "kind"));
          if (kind == Kind.ANNOUNCEMENTS) {
            keys(n, "requestId", "expectedRevision", "groupPublicParams", "groupAuthPresentation", "kind", "enabled");
            if (!n.get("enabled").isBoolean()) throw invalid();
          } else if (kind == Kind.TERMINATE) {
            keys(n, "requestId", "expectedRevision", "groupPublicParams", "groupAuthPresentation", "kind");
          } else throw invalid();
          JsonNode revision = n.get("expectedRevision");
          if (!revision.isIntegralNumber() || !revision.canConvertToLong() || revision.longValue() < 0
              || revision.longValue() > 0xffff_ffffL) throw invalid();
        } else throw invalid();
      }
      var requestId = GroupBridgeProtocol.uuid(string(n, kind == Kind.STATE ? "requestNonce" : "requestId"));
      byte[] paramsBytes = binary(n, "groupPublicParams", 1024);
      String derivedId = GroupBridgeProtocol.encode(new GroupPublicParams(paramsBytes).getGroupIdentifier().serialize());
      if (suppliedId != null && !suppliedId.equals(derivedId)) throw invalid();
      binary(n, "groupAuthPresentation", 4096);
      if (kind == Kind.CREATE) binary(n, "nativeGroup", MAX_BODY_BYTES);
      return new Operation(method, kind, derivedId, requestId, GroupBridgeProtocol.digest(body));
    } catch (Exception ignored) { throw invalid(); }
  }

  private static void keys(JsonNode n, String... names) {
    if (n == null || !n.isObject()) throw invalid();
    Set<String> found = new HashSet<>(); n.fieldNames().forEachRemaining(found::add);
    if (!found.equals(Set.of(names))) throw invalid();
  }
  private static String string(JsonNode n, String key) {
    JsonNode value = n.get(key);
    if (value == null || !value.isTextual()) throw invalid();
    return value.textValue();
  }
  private static byte[] binary(JsonNode n, String key, int max) {
    String value = string(n, key);
    if (value.isEmpty() || value.length() > (max * 8 + 5) / 6 || !value.matches("[A-Za-z0-9_-]+")) throw invalid();
    byte[] bytes = Base64.getUrlDecoder().decode(value);
    if (bytes.length > max || !GroupBridgeProtocol.encode(bytes).equals(value)) throw invalid();
    return bytes;
  }
  private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid group gateway request"); }
}
