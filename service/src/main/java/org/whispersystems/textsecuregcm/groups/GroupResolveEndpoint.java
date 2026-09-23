// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.groups;

import com.google.auth.oauth2.TokenVerifier;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Deliberately unregistered callback. IAM invocation alone is never an account proof. */
public final class GroupResolveEndpoint implements AutoCloseable {
  private static final String ISSUER = "https://accounts.google.com";
  private final GroupOriginalProofRegistry registry;
  private final TokenVerifier verifier;
  private final String audience;
  private final String subject;
  private final Clock clock;
  private final ThreadPoolExecutor verificationWorkers;
  private final long verificationNanos;
  private final Set<FutureTask<Void>> pending = ConcurrentHashMap.newKeySet();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final ReentrantReadWriteLock resolutions = new ReentrantReadWriteLock();

  public GroupResolveEndpoint(GroupOriginalProofRegistry registry, URI fixedAudience, String groupsSubject) {
    this(registry, fixedAudience, groupsSubject, TokenVerifier.newBuilder().setIssuer(ISSUER)
        .setAudience(origin(fixedAudience)).build(), Clock.systemUTC());
  }
  GroupResolveEndpoint(GroupOriginalProofRegistry registry, URI fixedAudience, String groupsSubject,
      TokenVerifier verifier, Clock clock) {
    this(registry, fixedAudience, groupsSubject, verifier, clock, Duration.ofSeconds(1), 2, 8);
  }
  GroupResolveEndpoint(GroupOriginalProofRegistry registry, URI fixedAudience, String groupsSubject,
      TokenVerifier verifier, Clock clock, Duration wait, int workers, int queueCapacity) {
    this.registry = Objects.requireNonNull(registry); this.audience = origin(fixedAudience);
    if (groupsSubject == null || !groupsSubject.matches("[0-9]{6,32}")) throw new IllegalArgumentException("Pinned Groups subject required");
    subject = groupsSubject; this.verifier = Objects.requireNonNull(verifier); this.clock = Objects.requireNonNull(clock);
    if (wait.isNegative() || wait.isZero() || wait.compareTo(Duration.ofSeconds(1)) > 0
        || workers < 1 || workers > 2 || queueCapacity < 1 || queueCapacity > 8)
      throw new IllegalArgumentException("Bounded verification required");
    verificationNanos = wait.toNanos();
    verificationWorkers = new ThreadPoolExecutor(workers, workers, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(queueCapacity), Thread.ofPlatform().daemon().name("group-oidc-", 0).factory(),
        new ThreadPoolExecutor.AbortPolicy());
  }

  /** Transport must pass exact method/path and reject redirects, compression and unimplemented variants. */
  public byte[] resolve(String method, String path, String contentType, String contentEncoding, String bearer, byte[] body) {
    if (!"POST".equals(method) || !GroupBridgeProtocol.RESOLVE_PATH.equals(path)
        || !"application/json".equals(contentType) || contentEncoding != null
        || body == null || body.length > GroupBridgeProtocol.MAX_WIRE_BYTES) throw denied();
    var request = GroupBridgeProtocol.request(body);
    authenticate(bearer);
    resolutions.readLock().lock();
    try {
      if (closed.get()) throw denied();
      byte[] result = GroupBridgeProtocol.encode(registry.resolve(request));
      if (closed.get()) throw denied();
      return result;
    } finally { resolutions.readLock().unlock(); }
  }
  private void authenticate(String bearer) {
    if (closed.get() || bearer == null || !bearer.startsWith("Bearer ") || bearer.length() > 8192) throw denied();
    long deadline = System.nanoTime() + verificationNanos;
    var task = new FutureTask<Void>(() -> { verifyIdentity(bearer); return null; });
    pending.add(task);
    try {
      if (closed.get()) throw denied();
      verificationWorkers.execute(task);
      long remaining = deadline - System.nanoTime();
      if (remaining <= 0) throw denied();
      task.get(remaining, TimeUnit.NANOSECONDS);
      if (closed.get() || deadline - System.nanoTime() <= 0) throw denied();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw denied();
    } catch (Exception ignored) {
      throw denied();
    } finally {
      // A provider may ignore interruption. It keeps only its bounded worker slot, never the registry handle.
      task.cancel(true);
      verificationWorkers.remove(task);
      pending.remove(task);
    }
  }
  private void verifyIdentity(String bearer) {
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
  @Override public void close() {
    closed.set(true);
    pending.forEach(task -> task.cancel(true));
    verificationWorkers.shutdownNow();
    // Drain already admitted resolutions without serializing concurrent account checks.
    // Token/key providers never hold this lock; their cancellation remains best effort.
    resolutions.writeLock().lock();
    resolutions.writeLock().unlock();
  }
  int queuedVerifications() { return verificationWorkers.getQueue().size(); }
  boolean isClosed() { return closed.get(); }
  private static String origin(URI uri) {
    if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getPort() != -1
        || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null || !uri.getPath().isEmpty())
      throw new IllegalArgumentException("Fixed HTTPS verifier origin required");
    return uri.toString();
  }
  private static SecurityException denied() { return new SecurityException("Group authorization unavailable"); }
}
