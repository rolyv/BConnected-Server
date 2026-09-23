// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.google.auth.oauth2.TokenVerifier;
import java.net.URI;
import java.time.Clock;
import java.util.Objects;

/** Deliberately unregistered callback. IAM invocation alone is never an account proof. */
public final class GroupResolveEndpoint {
  private static final String ISSUER = "https://accounts.google.com";
  private final GroupOriginalProofRegistry registry;
  private final TokenVerifier verifier;
  private final String audience;
  private final String subject;
  private final Clock clock;

  public GroupResolveEndpoint(GroupOriginalProofRegistry registry, URI fixedAudience, String groupsSubject) {
    this(registry, fixedAudience, groupsSubject, TokenVerifier.newBuilder().setIssuer(ISSUER)
        .setAudience(origin(fixedAudience)).build(), Clock.systemUTC());
  }
  GroupResolveEndpoint(GroupOriginalProofRegistry registry, URI fixedAudience, String groupsSubject,
      TokenVerifier verifier, Clock clock) {
    this.registry = Objects.requireNonNull(registry); this.audience = origin(fixedAudience);
    if (groupsSubject == null || !groupsSubject.matches("[0-9]{6,32}")) throw new IllegalArgumentException("Pinned Groups subject required");
    subject = groupsSubject; this.verifier = Objects.requireNonNull(verifier); this.clock = Objects.requireNonNull(clock);
  }

  /** Transport must pass exact method/path and reject redirects, compression and unimplemented variants. */
  public byte[] resolve(String method, String path, String contentType, String contentEncoding, String bearer, byte[] body) {
    if (!"POST".equals(method) || !GroupBridgeProtocol.RESOLVE_PATH.equals(path)
        || !"application/json".equals(contentType) || contentEncoding != null
        || body == null || body.length > GroupBridgeProtocol.MAX_WIRE_BYTES) throw denied();
    authenticate(bearer);
    return GroupBridgeProtocol.encode(registry.resolve(GroupBridgeProtocol.request(body)));
  }
  private void authenticate(String bearer) {
    if (bearer == null || !bearer.startsWith("Bearer ") || bearer.length() > 8192) throw denied();
    try {
      var jwt = verifier.verify(bearer.substring(7));
      var p = jwt.getPayload(); long now = clock.instant().getEpochSecond();
      // Explicit checks also constrain alternate verifier implementations supplied by tests.
      if (!"RS256".equals(jwt.getHeader().getAlgorithm()) || !ISSUER.equals(p.getIssuer())
          || !audience.equals(p.getAudience()) || !subject.equals(p.getSubject())
          || p.getIssuedAtTimeSeconds() == null || p.getExpirationTimeSeconds() == null
          || p.getIssuedAtTimeSeconds() > now || p.getExpirationTimeSeconds() <= now
          || p.getExpirationTimeSeconds() - p.getIssuedAtTimeSeconds() > 3600) throw denied();
    } catch (Exception ignored) { throw denied(); }
  }
  private static String origin(URI uri) {
    if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getPort() != -1
        || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null || !uri.getPath().isEmpty())
      throw new IllegalArgumentException("Fixed HTTPS verifier origin required");
    return uri.toString();
  }
  private static SecurityException denied() { return new SecurityException("Group authorization unavailable"); }
}
