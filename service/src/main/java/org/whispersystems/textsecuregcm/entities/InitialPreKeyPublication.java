// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.whispersystems.textsecuregcm.storage.KeyIdUtil;

/** Strict owned wire contract and immutable, canonical decoded-key snapshot. */
public final class InitialPreKeyPublication {
  private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());
  private final List<ECPreKey> ec;
  private final List<KEMSignedPreKey> kem;
  private final byte[] digest;
  private final byte[] signingIdentity;

  private InitialPreKeyPublication(List<ECPreKey> ec, List<KEMSignedPreKey> kem, IdentityKey identity) {
    this.ec = List.copyOf(ec); this.kem = List.copyOf(kem); signingIdentity = identity.serialize();
    try {
      var bytes = new ByteArrayOutputStream();
      try (var out = new DataOutputStream(bytes)) {
        out.write("BConnected.initial-prekeys.v1\0".getBytes(StandardCharsets.US_ASCII));
        out.writeInt(ec.size());
        for (var key : ec) { out.writeInt((int) key.keyId()); field(out, key.serializedPublicKey()); }
        out.writeInt(kem.size());
        for (var key : kem) { out.writeInt((int) key.keyId()); field(out, key.serializedPublicKey()); field(out, key.signature()); }
      }
      digest = MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
    } catch (IOException | NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
  }
  private static void field(DataOutputStream out, byte[] value) throws IOException { out.writeInt(value.length); out.write(value); }
  public static InitialPreKeyPublication parse(InputStream input, IdentityKey identity) throws IOException {
    if (input == null || identity == null) throw new IllegalArgumentException("Missing publication");
    byte[] body = input.readNBytes(512 * 1024 + 1);
    if (body.length > 512 * 1024) throw new IllegalArgumentException("Publication too large");
    final JsonNode root;
    try (var parser = MAPPER.createParser(body)) {
      root = MAPPER.readTree(parser);
      if (parser.nextToken() != null) throw new IllegalArgumentException("Trailing publication data");
    }
    fields(root, Set.of("preKeys", "pqPreKeys"));
    var ec = new ArrayList<ECPreKey>(); var kem = new ArrayList<KEMSignedPreKey>();
    var ecIds = new HashSet<Long>(); var kemIds = new HashSet<Long>();
    try {
      for (var entry : batch(root.get("preKeys"))) {
        fields(entry, Set.of("keyId", "publicKey")); long id = id(entry, ecIds);
        byte[] encoded = decoded(entry.get("publicKey")); var key = new ECPublicKey(encoded);
        if (!Arrays.equals(encoded, key.serialize())) throw new IllegalArgumentException("Noncanonical EC key");
        ec.add(new ECPreKey(id, key));
      }
      for (var entry : batch(root.get("pqPreKeys"))) {
        fields(entry, Set.of("keyId", "publicKey", "signature")); long id = id(entry, kemIds);
        byte[] encoded = decoded(entry.get("publicKey")); var key = new KEMPublicKey(encoded);
        byte[] signature = decoded(entry.get("signature"));
        if (!Arrays.equals(encoded, key.serialize()) || signature.length != 64
            || !identity.getPublicKey().verifySignature(encoded, signature)) throw new IllegalArgumentException("Invalid PQ key signature");
        kem.add(new KEMSignedPreKey(id, key, signature));
      }
    } catch (InvalidKeyException invalid) { throw new IllegalArgumentException("Invalid public key", invalid); }
    ec.sort(Comparator.comparingLong(ECPreKey::keyId)); kem.sort(Comparator.comparingLong(KEMSignedPreKey::keyId));
    return new InitialPreKeyPublication(ec, kem, identity);
  }
  private static JsonNode batch(JsonNode node) {
    if (node == null || !node.isArray() || node.isEmpty() || node.size() > 100) throw new IllegalArgumentException("Invalid key batch");
    return node;
  }
  private static void fields(JsonNode node, Set<String> expected) {
    if (node == null || !node.isObject()) throw new IllegalArgumentException("Expected object");
    var actual = new HashSet<String>(); node.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(expected)) throw new IllegalArgumentException("Unexpected publication fields");
  }
  private static long id(JsonNode entry, Set<Long> seen) {
    var node = entry.get("keyId");
    if (!node.isIntegralNumber() || !node.canConvertToLong() || !KeyIdUtil.keyIdValid(node.longValue())
        || !seen.add(node.longValue())) throw new IllegalArgumentException("Invalid or duplicate key ID");
    return node.longValue();
  }
  private static byte[] decoded(JsonNode node) {
    if (!node.isTextual()) throw new IllegalArgumentException("Expected base64 public material");
    return Base64.getDecoder().decode(node.textValue());
  }
  public List<ECPreKey> ec() { return ec; }
  public List<KEMSignedPreKey> kem() {
    return kem.stream().map(key -> new KEMSignedPreKey(key.keyId(), key.publicKey(), key.signature().clone())).toList();
  }
  public boolean signedFor(IdentityKey identity) { return identity != null && Arrays.equals(signingIdentity, identity.serialize()); }
  public byte[] digest() { return digest.clone(); }
  @Override public String toString() { return "InitialPreKeyPublication[redacted]"; }
}
