// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.signal.libsignal.zkgroup.backups.BackupCredentialType;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.Util;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Scheduler;

/**
 * Native account rows and uniqueness constraints; never translates SQL into DynamoDB operations.
 */
public final class AccountsPostgres implements AccountStore {
  private final DataSource dataSource;
  private final Clock clock;
  private final Executor executor;

  public AccountsPostgres(DataSource dataSource, Clock clock, Executor executor) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.clock = Objects.requireNonNull(clock);
    this.executor = Objects.requireNonNull(executor);
  }

  @FunctionalInterface
  private interface Work<T> {
    T run(Connection connection) throws SQLException;
  }

  private static final class SqlFailure extends RuntimeException {
    SqlFailure(SQLException cause) {
      super("PostgreSQL account operation failed", cause);
    }

    boolean isUnique() {
      return "23505".equals(((SQLException) getCause()).getSQLState());
    }
  }

  private static final class Unavailable extends RuntimeException {}

  private <T> T transaction(Work<T> work) {
    try (Connection c = dataSource.getConnection()) {
      c.setAutoCommit(false);
      c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      try {
        T result = work.run(c);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException | Error e) {
        try {
          c.rollback();
        } catch (SQLException rollback) {
          e.addSuppressed(rollback);
        }
        throw e;
      }
    } catch (SQLException e) {
      if (List.of("40001", "40P01", "55P03").contains(e.getSQLState()))
        throw new ContestedOptimisticLockException();
      throw new SqlFailure(e);
    }
  }

  private static PreparedStatement statement(Connection c, String sql, Object... values)
      throws SQLException {
    PreparedStatement s = c.prepareStatement(sql);
    try {
      for (int i = 0; i < values.length; i++) s.setObject(i + 1, values[i]);
      return s;
    } catch (SQLException e) {
      s.close();
      throw e;
    }
  }

  private static int execute(Connection c, String sql, Object... values) throws SQLException {
    try (var s = statement(c, sql, values)) {
      return s.executeUpdate();
    }
  }

  private static String encode(Account a) {
    try {
      return SystemMapper.jsonMapper().writeValueAsString(a);
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot serialize account", e);
    }
  }

  private static Account decode(ResultSet r) throws SQLException {
    try {
      Account a = SystemMapper.jsonMapper().readValue(r.getString("data"), Account.class);
      a.setAccountIdentifier(r.getObject("aci", UUID.class));
      a.setNumber(r.getString("number"), r.getObject("pni", UUID.class));
      a.setVersion(r.getInt("version"));
      a.setUsernameHash(r.getBytes("username_hash"));
      a.setUsernameLinkHandle(r.getObject("username_link", UUID.class));
      return a;
    } catch (IOException e) {
      throw new IllegalStateException("Cannot deserialize account", e);
    }
  }

  private static Optional<Account> query(Connection c, String sql, Object... values)
      throws SQLException {
    try (var s = statement(c, sql, values);
        var r = s.executeQuery()) {
      return r.next() ? Optional.of(decode(r)) : Optional.empty();
    }
  }

  private Optional<Account> lookup(String condition, Object value) {
    return transaction(c -> query(c, "SELECT * FROM signal.accounts WHERE " + condition, value));
  }

  private static Account lock(Connection c, Account expected) throws SQLException {
    Account current =
        query(
                c,
                "SELECT * FROM signal.accounts WHERE aci=? FOR UPDATE",
                expected.getAccountIdentifier())
            .orElseThrow(ContestedOptimisticLockException::new);
    if (current.getVersion() != expected.getVersion()) throw new ContestedOptimisticLockException();
    return current;
  }

  private static void write(Connection c, Account a, boolean changeIdentity) throws SQLException {
    String identity = changeIdentity ? ",number=?,pni=?" : "";
    var values = new ArrayList<Object>(List.of(encode(a)));
    values.add(a.getUsernameHash().orElse(null));
    values.add(a.getUsernameLinkHandle());
    if (changeIdentity) {
      values.add(a.getNumber().orElse(null));
      values.add(a.getPhoneNumberIdentifier().orElse(null));
    }
    values.add(a.getAccountIdentifier());
    values.add(a.getVersion());
    if (execute(
            c,
            "UPDATE signal.accounts SET"
                + " data=?::jsonb,username_hash=?,username_link=?,version=version+1"
                + identity
                + " WHERE aci=? AND version=?",
            values.toArray())
        != 1) throw new ContestedOptimisticLockException();
  }

  @Override
  public boolean createWithMutations(Account a, Collection<AccountMutation> mutations)
      throws AccountAlreadyExistsException {
    return createWithMutations(a, mutations, false);
  }

  /** Admission enrollment must never reuse a recently deleted phone identity. */
  public boolean createFreshWithMutations(Account a, Collection<AccountMutation> mutations)
      throws AccountAlreadyExistsException {
    return createWithMutations(a, mutations, true);
  }

  private boolean createWithMutations(
      Account a, Collection<AccountMutation> mutations, boolean freshOnly)
      throws AccountAlreadyExistsException {
    if (a.getNumber().isEmpty() || a.getPhoneNumberIdentifier().isEmpty())
      throw new IllegalArgumentException("Phone registration requires a number and PNI");
    try {
      transaction(
          c -> {
            execute(
                c,
                "INSERT INTO"
                    + " signal.accounts(aci,number,pni,version,data,username_hash,username_link)"
                    + " VALUES(?,?,?,?,?::jsonb,?,?)",
                a.getAccountIdentifier(),
                a.getNumber().orElseThrow(),
                a.getPhoneNumberIdentifier().orElseThrow(),
                a.getVersion(),
                encode(a),
                a.getUsernameHash().orElse(null),
                a.getUsernameLinkHandle());
            if (freshOnly) {
              // Check AFTER INSERT: it may have waited for deletion of an older account.
              // Its tombstone must not be consumed by a first-enrollment flow.
              try (var tombstone =
                      statement(
                          c,
                          "SELECT 1 FROM signal.deleted_accounts WHERE pni=? FOR SHARE",
                          a.getPhoneNumberIdentifier().orElseThrow());
                  var rows = tombstone.executeQuery()) {
                if (rows.next()) throw new IllegalStateException("Phone recovery is unavailable");
              }
            } else {
              execute(
                  c,
                  "DELETE FROM signal.deleted_accounts WHERE pni=?",
                  a.getPhoneNumberIdentifier().orElseThrow());
            }
            AccountMutation.executeSql(c, mutations);
            return null;
          });
      return true;
    } catch (SqlFailure e) {
      if (!e.isUnique()) throw e;
      Optional<Account> sameAci = getByAccountIdentifier(a.getAccountIdentifier());
      if (sameAci.isPresent()) {
        if (!sameAci.orElseThrow().getPhoneNumberIdentifier().equals(a.getPhoneNumberIdentifier()))
          throw new IllegalArgumentException(
              "Account identifier already exists with a different PNI");
        throw new AccountAlreadyExistsException(sameAci.orElseThrow());
      }
      Optional<Account> existing =
          getByE164(a.getNumber().orElseThrow())
              .or(() -> getByPhoneNumberIdentifier(a.getPhoneNumberIdentifier().orElseThrow()));
      if (existing.isPresent()) throw new AccountAlreadyExistsException(existing.get());
      throw new ContestedOptimisticLockException();
    }
  }

  @Override
  public boolean createWithMutations(
      Account a,
      ReceiptCredentialPresentation receipt,
      byte[] password,
      Collection<AccountMutation> mutations) {
    // Paid/numberless account creation requires receipt redemption in the same transaction.
    // It must remain unavailable until that optional feature has a native implementation.
    throw new UnsupportedOperationException(
        "PostgreSQL pilot supports phone registration only; receipt registration is disabled");
  }

  @Override
  public void update(Account a) {
    updateWithMutations(a, List.of());
  }

  @Override
  public void updateWithMutations(Account a, Collection<AccountMutation> mutations) {
    transaction(
        c -> {
          Account current = lock(c, a);
          if (!current.getNumber().equals(a.getNumber())
              || !current.getPhoneNumberIdentifier().equals(a.getPhoneNumberIdentifier()))
            throw new IllegalArgumentException(
                "Identity changes require changeNumberWithMutations");
          write(c, a, false);
          AccountMutation.executeSql(c, mutations);
          return null;
        });
    a.setVersion(a.getVersion() + 1);
  }

  @Override
  public CompletionStage<Void> reclaimWithMutations(
      Account previous, Account replacement, Collection<AccountMutation> mutations) {
    if (!previous.getAccountIdentifier().equals(replacement.getAccountIdentifier())
        || previous.getNumber().isPresent() != replacement.getNumber().isPresent()
        || !previous.getPhoneNumberIdentifier().equals(replacement.getPhoneNumberIdentifier()))
      throw new IllegalArgumentException("Reclaimed accounts must match");
    if (previous.getNumber().isPresent()
        && !Util.getAlternateForms(previous.getNumber().orElseThrow())
            .contains(replacement.getNumber().orElseThrow()))
      throw new IllegalArgumentException("Reclaimed phone numbers must be equivalent");
    return CompletableFuture.runAsync(
        () -> {
          Account next = AccountUtil.cloneAccountAsNotStale(replacement);
          next.setVersion(previous.getVersion());
          next.setBackupCredentialRequests(
              previous.getBackupCredentialRequest(BackupCredentialType.MESSAGES).orElse(null),
              previous.getBackupCredentialRequest(BackupCredentialType.MEDIA).orElse(null));
          next.setBackupVoucher(previous.getBackupVoucher());
          next.setBadges(clock, previous.getBadges());
          next.setZkCredentialKey(previous.getZkCredentialKey().orElse(null));
          next.setZkCredentialKeyRotationId(previous.getZkCredentialKeyRotationId());
          next.setMfaKeys(new HashMap<>(previous.getMfaKeys()));
          if (previous.getReservedUsernameHash().isPresent()
              && previous.getUsernameLinkHandle() != null
              && previous.getUsernameHash().isEmpty()
              && previous.getEncryptedUsername().isEmpty()) {
            next.setReservedUsernameHash(previous.getReservedUsernameHash().orElseThrow());
            next.setUsernameLinkHandle(previous.getUsernameLinkHandle());
          } else if (previous.getUsernameHash().isPresent()) {
            next.setReservedUsernameHash(previous.getUsernameHash().orElseThrow());
            next.setUsernameLinkHandle(previous.getUsernameLinkHandle());
          }
          transaction(
              c -> {
                Account current =
                    query(
                            c,
                            "SELECT * FROM signal.accounts WHERE aci=? FOR UPDATE",
                            previous.getAccountIdentifier())
                        .orElseThrow(ContestedOptimisticLockException::new);
                if (!current.getNumber().equals(previous.getNumber()))
                  throw new UnexpectedExistingPhoneNumberException();
                if (current.getVersion() != previous.getVersion())
                  throw new ContestedOptimisticLockException();
                if (previous.getUsernameHash().isPresent()) {
                  int written =
                      execute(
                          c,
                          """
                          INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,false,true,?)
                          ON CONFLICT(hash) DO UPDATE SET aci=EXCLUDED.aci,confirmed=false,reclaimable=true,expires_at=EXCLUDED.expires_at
                          WHERE signal.usernames.aci=EXCLUDED.aci OR signal.usernames.expires_at < ?
                          """,
                          previous.getUsernameHash().orElseThrow(),
                          next.getAccountIdentifier(),
                          now() + Duration.ofDays(3).toSeconds(),
                          now());
                  if (written != 1) throw new ContestedOptimisticLockException();
                }
                write(c, next, true);
                AccountMutation.executeSql(c, mutations);
                return null;
              });
          replacement.setVersion(next.getVersion() + 1);
          replacement.setBackupCredentialRequests(
              next.getBackupCredentialRequest(BackupCredentialType.MESSAGES).orElse(null),
              next.getBackupCredentialRequest(BackupCredentialType.MEDIA).orElse(null));
          replacement.setBackupVoucher(next.getBackupVoucher());
          replacement.setBadges(clock, next.getBadges());
          replacement.setZkCredentialKey(next.getZkCredentialKey().orElse(null));
          replacement.setZkCredentialKeyRotationId(next.getZkCredentialKeyRotationId());
          replacement.setMfaKeys(next.getMfaKeys());
          replacement.setReservedUsernameHash(next.getReservedUsernameHash().orElse(null));
          replacement.setUsernameLinkHandle(next.getUsernameLinkHandle());
        },
        executor);
  }

  @Override
  public void changeNumberWithMutations(
      Account a,
      String number,
      UUID pni,
      Optional<UUID> displaced,
      Collection<AccountMutation> mutations) {
    UUID originalPni =
        a.getPhoneNumberIdentifier()
            .orElseThrow(() -> new IllegalArgumentException("Account has no PNI"));
    Account next = AccountUtil.cloneAccountAsNotStale(a);
    next.setNumber(number, pni);
    transaction(
        c -> {
          Account current = lock(c, a);
          if (!current.getNumber().equals(a.getNumber())
              || !current.getPhoneNumberIdentifier().equals(a.getPhoneNumberIdentifier()))
            throw new ContestedOptimisticLockException();
          write(c, next, true);
          execute(c, "DELETE FROM signal.deleted_accounts WHERE pni=?", pni);
          if (displaced.isPresent()) putDeleted(c, displaced.orElseThrow(), originalPni);
          AccountMutation.executeSql(c, mutations);
          return null;
        });
    a.setNumber(number, pni);
    a.setVersion(a.getVersion() + 1);
  }

  private void putDeleted(Connection c, UUID aci, UUID pni) throws SQLException {
    execute(
        c,
        "INSERT INTO signal.deleted_accounts(pni,aci,expires_at) VALUES(?,?,?) ON CONFLICT(pni) DO"
            + " UPDATE SET aci=EXCLUDED.aci,expires_at=EXCLUDED.expires_at",
        pni,
        aci,
        now() + Duration.ofDays(30).toSeconds());
  }

  @Override
  public void deleteWithMutations(UUID aci, Collection<AccountMutation> mutations) {
    for (int attempt = 0; attempt < 3; attempt++) {
      try {
        deleteOnce(aci, mutations);
        return;
      } catch (ContestedOptimisticLockException e) {
        if (attempt == 2) throw new OptimisticLockRetryLimitExceededException();
      }
    }
  }

  private void deleteOnce(UUID aci, Collection<AccountMutation> mutations) {
    transaction(
        c -> {
          Optional<Account> existing =
              query(c, "SELECT * FROM signal.accounts WHERE aci=? FOR UPDATE", aci);
          if (existing.isEmpty()) return null;
          Account a = existing.orElseThrow();
          execute(c, "DELETE FROM signal.accounts WHERE aci=?", aci);
          if (a.getPhoneNumberIdentifier().isPresent())
            putDeleted(c, aci, a.getPhoneNumberIdentifier().orElseThrow());
          if (a.getUsernameHash().isPresent())
            execute(
                c,
                "DELETE FROM signal.usernames WHERE hash=? AND aci=?",
                a.getUsernameHash().orElseThrow(),
                aci);
          AccountMutation.executeSql(c, mutations);
          return null;
        });
  }

  @Override
  public AccountMutation linkDeviceMutation(String token, Duration ttl) {
    final byte[] hash;
    try {
      hash = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
    long expires = clock.instant().plus(ttl).getEpochSecond();
    return new AccountMutation.Sql(
        c -> {
          if (execute(
                  c,
                  "INSERT INTO signal.used_link_tokens(hash,expires_at) VALUES(?,?) ON CONFLICT DO"
                      + " NOTHING",
                  hash,
                  expires)
              != 1) throw new DeviceLinkTokenConflictException();
        });
  }

  private long now() {
    return clock.instant().getEpochSecond();
  }

  private record Username(UUID owner, boolean confirmed, boolean reclaimable, Long expiration) {}

  private static Optional<Username> username(Connection c, byte[] hash) throws SQLException {
    try (var s =
            statement(
                c,
                "SELECT aci,confirmed,reclaimable,expires_at FROM signal.usernames WHERE hash=? FOR"
                    + " UPDATE",
                hash);
        var r = s.executeQuery()) {
      return r.next()
          ? Optional.of(
              new Username(
                  r.getObject(1, UUID.class),
                  r.getBoolean(2),
                  r.getBoolean(3),
                  (Long) r.getObject(4)))
          : Optional.empty();
    }
  }

  @Override
  public void reserveUsernameHash(Account a, byte[] hash, Duration ttl)
      throws UsernameHashNotAvailableException {
    Objects.requireNonNull(hash);
    Account next = AccountUtil.cloneAccountAsNotStale(a);
    next.setReservedUsernameHash(hash);
    try {
      transaction(
          c -> {
            lock(c, a);
            if (execute(
                    c,
                    """
                    INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,false,false,?)
                    ON CONFLICT(hash) DO UPDATE SET aci=EXCLUDED.aci,confirmed=false,reclaimable=false,
                      expires_at=CASE WHEN signal.usernames.aci=EXCLUDED.aci AND NOT signal.usernames.confirmed
                        THEN GREATEST(signal.usernames.expires_at,EXCLUDED.expires_at) ELSE EXCLUDED.expires_at END
                    WHERE signal.usernames.expires_at < ? OR (signal.usernames.aci=EXCLUDED.aci AND NOT signal.usernames.confirmed)
                    """,
                    hash,
                    a.getAccountIdentifier(),
                    clock.instant().plus(ttl).getEpochSecond(),
                    now())
                != 1) throw new Unavailable();
            write(c, next, false);
            return null;
          });
    } catch (Unavailable e) {
      throw new UsernameHashNotAvailableException();
    }
    a.setReservedUsernameHash(hash);
    a.setVersion(a.getVersion() + 1);
  }

  private Optional<byte[]> addHold(Account a, byte[] hash, long operationTime) {
    var holds = new ArrayList<>(a.getUsernameHolds());
    holds.removeIf(
        h ->
            h.expirationSecs() < operationTime
                || Arrays.equals(h.usernameHash(), hash)
                || a.getUsernameHash()
                    .map(current -> Arrays.equals(current, h.usernameHash()))
                    .orElse(false));
    holds.add(new Account.UsernameHold(hash, operationTime + Duration.ofDays(7).toSeconds()));
    Optional<byte[]> remove =
        holds.size() > 3 ? Optional.of(holds.removeFirst().usernameHash()) : Optional.empty();
    a.setUsernameHolds(holds);
    return remove;
  }

  private void hold(Connection c, UUID aci, byte[] hash, long operationTime) throws SQLException {
    if (execute(
            c,
            """
            INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,false,false,?)
            ON CONFLICT(hash) DO UPDATE SET aci=EXCLUDED.aci,confirmed=false,reclaimable=false,expires_at=EXCLUDED.expires_at
            WHERE signal.usernames.aci=EXCLUDED.aci OR signal.usernames.expires_at < ?
            """,
            hash,
            aci,
            operationTime + Duration.ofDays(7).toSeconds(),
            operationTime)
        != 1) throw new ContestedOptimisticLockException();
  }

  private void releaseHold(Connection c, UUID aci, byte[] hash) throws SQLException {
    Optional<Username> existing = username(c, hash);
    if (existing.isEmpty()) return;
    Username u = existing.orElseThrow();
    if (!(u.expiration() != null && u.expiration() < now())
        && (!u.owner().equals(aci) || u.confirmed())) throw new ContestedOptimisticLockException();
    execute(c, "DELETE FROM signal.usernames WHERE hash=?", hash);
  }

  @Override
  public void confirmUsernameHash(Account a, byte[] hash, byte[] encrypted)
      throws UsernameHashNotAvailableException {
    Objects.requireNonNull(hash);
    Account next = AccountUtil.cloneAccountAsNotStale(a);
    next.setUsernameHash(hash);
    next.setReservedUsernameHash(null);
    long operationTime = now();
    Optional<byte[]> release =
        a.getUsernameHash().flatMap(old -> addHold(next, old, operationTime));
    try {
      transaction(
          c -> {
            lock(c, a);
            Optional<Username> old = username(c, hash);
            UUID handle =
                a.getUsernameLinkHandle() != null && old.map(Username::reclaimable).orElse(false)
                    ? a.getUsernameLinkHandle()
                    : UUID.randomUUID();
            next.setUsernameLinkDetails(encrypted == null ? null : handle, encrypted);
            if (execute(
                    c,
                    """
                    INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,true,false,NULL)
                    ON CONFLICT(hash) DO UPDATE SET aci=EXCLUDED.aci,confirmed=true,reclaimable=false,expires_at=NULL
                    WHERE signal.usernames.expires_at < ? OR (signal.usernames.aci=EXCLUDED.aci AND NOT signal.usernames.confirmed)
                    """,
                    hash,
                    a.getAccountIdentifier(),
                    now())
                != 1) throw new Unavailable();
            write(c, next, false);
            if (a.getUsernameHash().isPresent())
              hold(c, a.getAccountIdentifier(), a.getUsernameHash().orElseThrow(), operationTime);
            if (release.isPresent())
              releaseHold(c, a.getAccountIdentifier(), release.orElseThrow());
            return null;
          });
    } catch (Unavailable e) {
      throw new UsernameHashNotAvailableException();
    }
    a.setUsernameHash(hash);
    a.setReservedUsernameHash(null);
    a.setUsernameLinkDetails(next.getUsernameLinkHandle(), encrypted);
    a.setUsernameHolds(next.getUsernameHolds());
    a.setVersion(a.getVersion() + 1);
  }

  @Override
  public void clearUsernameHash(Account a) {
    if (a.getUsernameHash().isEmpty()) return;
    Account next = AccountUtil.cloneAccountAsNotStale(a);
    byte[] old = a.getUsernameHash().orElseThrow();
    long operationTime = now();
    next.setUsernameHash(null);
    next.setUsernameLinkDetails(null, null);
    Optional<byte[]> release = addHold(next, old, operationTime);
    transaction(
        c -> {
          lock(c, a);
          write(c, next, false);
          hold(c, a.getAccountIdentifier(), old, operationTime);
          if (release.isPresent()) releaseHold(c, a.getAccountIdentifier(), release.orElseThrow());
          return null;
        });
    a.setUsernameHash(null);
    a.setUsernameLinkDetails(null, null);
    a.setUsernameHolds(next.getUsernameHolds());
    a.setVersion(a.getVersion() + 1);
  }

  @Override
  public Optional<Account> getByE164(String number) {
    return lookup("number=?", number);
  }

  @Override
  public Optional<Account> getByPhoneNumberIdentifier(UUID pni) {
    return lookup("pni=?", pni);
  }

  @Override
  public Optional<Account> getByAccountIdentifier(UUID aci) {
    return lookup("aci=?", aci);
  }

  @Override
  public CompletableFuture<Optional<Account>> getByE164Async(String number) {
    return CompletableFuture.supplyAsync(() -> getByE164(number), executor);
  }

  @Override
  public CompletableFuture<Optional<Account>> getByPhoneNumberIdentifierAsync(UUID pni) {
    return CompletableFuture.supplyAsync(() -> getByPhoneNumberIdentifier(pni), executor);
  }

  @Override
  public CompletableFuture<Optional<Account>> getByAccountIdentifierAsync(UUID aci) {
    return CompletableFuture.supplyAsync(() -> getByAccountIdentifier(aci), executor);
  }

  @Override
  public CompletableFuture<Optional<Account>> getByUsernameHash(byte[] hash) {
    return CompletableFuture.supplyAsync(
        () ->
            transaction(
                c ->
                    query(
                        c,
                        "SELECT a.* FROM signal.accounts a JOIN signal.usernames u ON u.aci=a.aci"
                            + " WHERE u.hash=? AND u.confirmed",
                        hash)),
        executor);
  }

  @Override
  public CompletableFuture<Optional<Account>> getByUsernameLinkHandle(UUID handle) {
    return CompletableFuture.supplyAsync(() -> lookup("username_link=?", handle), executor);
  }

  @Override
  public boolean accountExists(UUID aci) {
    return getByAccountIdentifier(aci).isPresent();
  }

  private Optional<UUID> deleted(String field, UUID id, String result) {
    return transaction(
        c -> {
          try (var s =
                  statement(
                      c,
                      "SELECT "
                          + result
                          + " FROM signal.deleted_accounts WHERE "
                          + field
                          + "=? ORDER BY pni LIMIT 1",
                      id);
              var r = s.executeQuery()) {
            return r.next() ? Optional.of(r.getObject(1, UUID.class)) : Optional.empty();
          }
        });
  }

  @Override
  public Optional<UUID> findRecentlyDeletedAccountIdentifier(UUID pni) {
    return deleted("pni", pni, "aci");
  }

  @Override
  public Optional<UUID> findRecentlyDeletedPhoneNumberIdentifier(UUID aci) {
    return deleted("aci", aci, "pni");
  }

  @Override
  public Flux<Account> getAll(int segments, Scheduler scheduler) {
    if (segments < 1) throw new IllegalArgumentException("Segments must be positive");
    // Bounded keyset pages avoid retaining an entire population or a connection for slow
    // subscribers.
    return Flux.<List<Account>, UUID>generate(
            () -> null,
            (last, sink) -> {
              List<Account> page =
                  transaction(
                      c -> {
                        var list = new ArrayList<Account>();
                        String where = last == null ? "" : " WHERE aci > ?";
                        try (var s =
                                statement(
                                    c,
                                    "SELECT * FROM signal.accounts"
                                        + where
                                        + " ORDER BY aci LIMIT 256",
                                    last == null ? new Object[0] : new Object[] {last});
                            var r = s.executeQuery()) {
                          while (r.next()) list.add(decode(r));
                        }
                        return list;
                      });
              if (page.isEmpty()) {
                sink.complete();
                return last;
              }
              sink.next(page);
              return page.getLast().getAccountIdentifier();
            })
        .concatMapIterable(page -> page)
        .subscribeOn(scheduler);
  }

  @Override
  public Flux<UUID> getAllAccountIdentifiers(int segments, Scheduler scheduler) {
    return getAll(segments, scheduler).map(Account::getAccountIdentifier);
  }

  @Override
  public CompletableFuture<Void> regenerateConstraints(Account a) {
    // SQL identity indexes cannot drift from their account row. Username repair must never steal
    // another account's name.
    return CompletableFuture.runAsync(
        () ->
            transaction(
                c -> {
                  lock(c, a);
                  if (a.getUsernameHash().isPresent()) {
                    if (execute(
                            c,
                            """
                            INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,true,false,NULL)
                            ON CONFLICT(hash) DO UPDATE SET confirmed=true,reclaimable=false,expires_at=NULL WHERE signal.usernames.aci=EXCLUDED.aci
                            """,
                            a.getUsernameHash().orElseThrow(),
                            a.getAccountIdentifier())
                        != 1) throw new ContestedOptimisticLockException();
                  }
                  for (var h : a.getUsernameHolds())
                    if (h.expirationSecs() >= now()) {
                      if (execute(
                              c,
                              """
                              INSERT INTO signal.usernames(hash,aci,confirmed,reclaimable,expires_at) VALUES(?,?,false,false,?)
                              ON CONFLICT(hash) DO NOTHING
                              """,
                              h.usernameHash(),
                              a.getAccountIdentifier(),
                              h.expirationSecs())
                          == 0) {
                        Username u = username(c, h.usernameHash()).orElseThrow();
                        if (!u.owner().equals(a.getAccountIdentifier()))
                          throw new ContestedOptimisticLockException();
                      }
                    }
                  return null;
                }),
        executor);
  }

  public int deleteExpired(int limit) {
    if (limit < 1 || limit > 10000)
      throw new IllegalArgumentException("Cleanup batch must be 1..10000");
    return transaction(
        c -> {
          int removed = 0;
          for (String table : List.of("usernames", "deleted_accounts", "used_link_tokens"))
            removed +=
                execute(
                    c,
                    "DELETE FROM signal."
                        + table
                        + " WHERE ctid IN (SELECT ctid FROM signal."
                        + table
                        + " WHERE expires_at < ? LIMIT ? FOR UPDATE SKIP LOCKED)",
                    now(),
                    limit);
          return removed;
        });
  }
}
