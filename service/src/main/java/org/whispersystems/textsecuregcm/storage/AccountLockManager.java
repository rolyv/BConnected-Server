package org.whispersystems.textsecuregcm.storage;

import com.amazonaws.services.dynamodbv2.AcquireLockOptions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBLockClient;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBLockClientOptions;
import com.amazonaws.services.dynamodbv2.LockItem;
import com.amazonaws.services.dynamodbv2.ReleaseLockOptions;
import com.google.common.annotations.VisibleForTesting;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.util.ThrowingSupplier;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class AccountLockManager {

  private final AmazonDynamoDBLockClient lockClient;
  private final DataSource lockDataSource;
  private final ThreadLocal<SqlLockScope> sqlLockScope = new ThreadLocal<>();

  static final String KEY_ACCOUNT_PNI = "P";

  public AccountLockManager(final DynamoDbClient lockDynamoDb, final String lockTableName) {
    this(new AmazonDynamoDBLockClient(
        AmazonDynamoDBLockClientOptions.builder(lockDynamoDb, lockTableName)
            .withPartitionKeyName(KEY_ACCOUNT_PNI)
            .withLeaseDuration(15L)
            .withHeartbeatPeriod(2L)
            .withTimeUnit(TimeUnit.SECONDS)
            .withCreateHeartbeatBackgroundThread(true)
            .build()));
  }

  @VisibleForTesting
  AccountLockManager(final AmazonDynamoDBLockClient lockClient) {
    this.lockClient = lockClient;
    this.lockDataSource = null;
  }

  /// Uses a dedicated PostgreSQL connection pool for lifecycle locks. It MUST NOT be the account/key data pool:
  /// callbacks perform their own database operations while retaining the lock connection. The caller owns this
  /// pool's lifecycle and must allow its transactions to remain open for the full synchronous callback duration.
  public AccountLockManager(final DataSource dedicatedLockDataSource) {
    this.lockClient = null;
    this.lockDataSource = Objects.requireNonNull(dedicatedLockDataSource);
  }

  /// Acquires a distributed, pessimistic lock for the accounts identified by the given phone number identifiers. By
  /// design, the accounts need not actually exist in order to acquire a lock; this allows lock acquisition for
  /// operations that span account lifecycle changes (like deleting an account or changing a phone number). The given
  /// task runs once locks for all given identifiers have been acquired, and the locks are released as soon as the task
  /// completes by any means.
  ///
  /// @param phoneNumberIdentifiers  the phone number identifiers for which to acquire a distributed, pessimistic lock
  /// @param task                    the task to execute once locks have been acquired
  ///
  /// @return the value returned by the given {@code task}
  ///
  /// @throws E if an exception is thrown by the given {@code task}
  public <V, E extends Exception> V withLock(final Set<UUID> phoneNumberIdentifiers,
      final ThrowingSupplier<V, E> task) throws E {

    if (phoneNumberIdentifiers.isEmpty()) {
      throw new IllegalArgumentException("List of PNIs to lock must not be empty");
    }

    Objects.requireNonNull(task);
    if (lockDataSource != null) {
      return withPostgresLocks(Set.copyOf(phoneNumberIdentifiers), task);
    }

    final List<LockItem> lockItems = new ArrayList<>(phoneNumberIdentifiers.size());

    try {
      for (final UUID pni : phoneNumberIdentifiers.stream().sorted().toList()) {
        try {
          lockItems.add(lockClient.acquireLock(AcquireLockOptions.builder(pni.toString())
              .withAcquireReleasedLocksConsistently(true)
              .build()));
        } catch (final InterruptedException e) {
          throw new RuntimeException(e);
        }
      }
      return task.get();
    } finally {
      for (final LockItem lockItem : lockItems) {
        lockClient.releaseLock(ReleaseLockOptions.builder(lockItem)
            .withBestEffort(true)
            .build());
      }
    }
  }

  private record SqlLockScope(Connection connection, Set<Long> acquiredKeys) {}

  private <V, E extends Exception> V withPostgresLocks(final Set<UUID> identifiers,
      final ThrowingSupplier<V, E> task) throws E {
    // Sort the actual advisory keys, not the UUIDs: even a hash collision then cannot invert the lock order.
    // Collisions only serialize unrelated identities; row/account identity is never inferred from this hash.
    final List<Long> keys = identifiers.stream().map(AccountLockManager::advisoryKey).distinct().sorted().toList();
    final SqlLockScope enclosing = sqlLockScope.get();
    if (enclosing != null) {
      // Account creation can hold its PNI lock and then lock a recently-deleted ACI. Reuse the same connection so
      // nested calls work even with a one-connection lock pool. Acquiring a newly requested key without waiting
      // prevents nested scopes from forming an inverted-order deadlock. Never rerun a callback after side effects.
      acquirePostgresLocks(enclosing, keys, true);
      return task.get();
    }

    final Connection connection;
    try {
      connection = lockDataSource.getConnection();
    } catch (SQLException e) {
      throw new IllegalStateException("Cannot open PostgreSQL account lifecycle lock connection", e);
    }

    Throwable failure = null;
    try {
      try {
        connection.setAutoCommit(false);
      } catch (SQLException e) {
        throw new IllegalStateException("Cannot begin PostgreSQL account lifecycle lock scope", e);
      }
      final SqlLockScope scope = new SqlLockScope(connection, new HashSet<>());
      acquirePostgresLocks(scope, keys, false);
      sqlLockScope.set(scope);
      return task.get();
    } catch (Exception | Error e) {
      failure = e;
      throw e;
    } finally {
      sqlLockScope.remove();
      releasePostgresLocks(connection, failure);
    }
  }

  private static long advisoryKey(final UUID identifier) {
    return identifier.getMostSignificantBits()
        ^ Long.rotateLeft(identifier.getLeastSignificantBits(), 23) ^ 0x42434143434C4F43L;
  }

  private static void acquirePostgresLocks(final SqlLockScope scope, final List<Long> keys,
      final boolean nested) {
    for (final long key : keys) {
      if (scope.acquiredKeys().contains(key)) continue;
      try (var statement = scope.connection().prepareStatement(nested
          ? "SELECT pg_try_advisory_xact_lock(?)" : "SELECT pg_advisory_xact_lock(?)")) {
        statement.setLong(1, key);
        try (var result = statement.executeQuery()) {
          if (nested && (!result.next() || !result.getBoolean(1))) {
            throw new IllegalStateException("Nested PostgreSQL account lifecycle lock is already held");
          }
        }
        scope.acquiredKeys().add(key);
      } catch (SQLException e) {
        throw new IllegalStateException("Cannot acquire PostgreSQL account lifecycle lock", e);
      }
    }
  }

  private static void releasePostgresLocks(final Connection connection, final Throwable callbackFailure) {
    SQLException cleanupFailure = null;
    try {
      // There are no data writes in this transaction. Rollback releases every acquired advisory lock, including
      // nested and partially-acquired sets, before the connection is returned to its pool.
      connection.rollback();
    } catch (SQLException e) {
      cleanupFailure = e;
      try {
        // A connection whose rollback failed must not return to a pool while potentially retaining locks.
        connection.abort(Runnable::run);
      } catch (SQLException abortFailure) {
        cleanupFailure.addSuppressed(abortFailure);
      }
    }
    try {
      connection.close();
    } catch (SQLException e) {
      if (cleanupFailure == null) cleanupFailure = e;
      else cleanupFailure.addSuppressed(e);
    }
    if (cleanupFailure != null) {
      if (callbackFailure != null) callbackFailure.addSuppressed(cleanupFailure);
      else throw new IllegalStateException("Cannot release PostgreSQL account lifecycle locks", cleanupFailure);
    }
  }

  /// Acquires a distributed, pessimistic lock for a single account that already exists. The given task
  /// runs once a lock for the identifier has been acquired, and the lock is released as soon as
  /// the task completes by any means.
  ///
  /// If the account has a phone number, the lock will be based on its phone-number identifier, and
  /// will therefore guard against collisions with other operations that lock the same phone number
  /// identifier; if it does not, the lock will be based on its account identifier only. This is
  /// safe because accounts without phone numbers can never get phone numbers and accounts with
  /// them can never lose them, so we will never see two operations targeting the same account but
  /// locking with different identifier types.
  ///
  /// @param account                 the account for which to acquire a distributed, pessimistic lock
  /// @param task                    the task to execute once locks have been acquired
  ///
  /// @return the value returned by the given {@code task}
  ///
  /// @throws E if an exception is thrown by the given {@code task}
  public <V, E extends Exception> V withSingleAccountLock(final Account account,
      final ThrowingSupplier<V, E> task) throws E {
    return withLock(Set.of(account.getPhoneNumberIdentifier().orElse(account.getAccountIdentifier())), task);
  }
}
