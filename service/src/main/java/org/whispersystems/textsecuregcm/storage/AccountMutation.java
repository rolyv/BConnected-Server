// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;

/** One participant in an account transaction. Mixing storage backends is always an error. */
public sealed interface AccountMutation permits AccountMutation.Dynamo, AccountMutation.Sql {
  record Dynamo(TransactWriteItem item) implements AccountMutation {
    public Dynamo { Objects.requireNonNull(item); }
  }

  record Sql(SqlOperation operation) implements AccountMutation {
    public Sql { Objects.requireNonNull(operation); }
  }

  @FunctionalInterface
  interface SqlOperation {
    void apply(Connection connection) throws SQLException;
  }

  default TransactWriteItem dynamoItem() {
    if (this instanceof Dynamo dynamo) return dynamo.item();
    throw new IllegalArgumentException("A PostgreSQL mutation cannot participate in a DynamoDB transaction");
  }

  default void applySql(final Connection connection) throws SQLException {
    if (!(this instanceof Sql sql)) {
      throw new IllegalArgumentException("A DynamoDB mutation cannot participate in a PostgreSQL transaction");
    }
    if (connection.getAutoCommit()) {
      throw new IllegalStateException("Account mutations require an explicit PostgreSQL transaction");
    }
    sql.operation().apply(connection);
  }

  static List<TransactWriteItem> toDynamo(final Collection<? extends AccountMutation> mutations) {
    return mutations.stream().map(AccountMutation::dynamoItem).toList();
  }

  static void executeSql(final Connection connection, final Collection<? extends AccountMutation> mutations)
      throws SQLException {
    // Validate the entire collection before making any changes, even when an incorrectly configured participant
    // appears after valid SQL mutations. The caller still owns commit/rollback for the complete account operation.
    if (mutations.stream().anyMatch(mutation -> !(mutation instanceof Sql))) {
      throw new IllegalArgumentException("Cannot mix DynamoDB and PostgreSQL account mutations");
    }
    for (final AccountMutation mutation : mutations) mutation.applySql(connection);
  }
}
