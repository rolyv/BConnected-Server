// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

/** Public synthetic keys only; exercises real RSA signature verification without Google network I/O. */
public final class GroupResolveTestSupport {
  static final URI ORIGIN = URI.create("https://verifier.example.test");
  static final String SUBJECT = "123456789012345678901";
  static final String ISSUER = "https://accounts.google.com";
  static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-23T00:00:00Z"), ZoneOffset.UTC);
  static final KeyPair KEYS = keys();
  static KeyPair keys() {
    try { var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); return generator.generateKeyPair(); }
    catch (Exception e) { throw new AssertionError(e); }
  }
  static GroupResolveEndpoint endpoint(GroupOriginalProofRegistry registry) {
    return new GroupResolveEndpoint(registry, ORIGIN, SUBJECT, verifier(), CLOCK);
  }
  static TokenVerifier verifier() {
    return TokenVerifier.newBuilder().setIssuer(ISSUER).setAudience(ORIGIN.toString())
        .setPublicKey(KEYS.getPublic()).setClock(CLOCK::millis).build();
  }
  static String token(String issuer, String audience, String subject, long issued, long expiry, KeyPair keys) throws Exception {
    var h = new JsonWebSignature.Header().setAlgorithm("RS256").setKeyId("synthetic");
    var p = new JsonWebToken.Payload().setIssuer(issuer).setAudience(audience).setSubject(subject)
        .setIssuedAtTimeSeconds(issued).setExpirationTimeSeconds(expiry);
    return "Bearer " + JsonWebSignature.signUsingRsaSha256(keys.getPrivate(), GsonFactory.getDefaultInstance(), h, p);
  }
  static String token() throws Exception { long now = CLOCK.instant().getEpochSecond(); return token(ISSUER, ORIGIN.toString(), SUBJECT, now, now + 3600, KEYS); }
  public static GroupBridgeProtocol.Resolution resolve(GroupOriginalProofRegistry registry, GroupBridgeProtocol.ResolveRequest request) throws Exception {
    try (var endpoint = endpoint(registry)) {
      return GroupBridgeProtocol.resolution(endpoint.resolve("POST", GroupBridgeProtocol.RESOLVE_PATH,
          "application/json", null, token(), GroupBridgeProtocol.encode(request)));
    }
  }
}
