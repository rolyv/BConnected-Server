// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.util.Util;

/** Permanent PNI mappings; an existing association is never reassigned. */
public final class PhoneNumberIdentifiersPostgres implements PhoneNumberIdentifierStore {
  private final DataSource dataSource;
  private final Executor executor;
  public PhoneNumberIdentifiersPostgres(DataSource dataSource, Executor executor) { this.dataSource=dataSource; this.executor=executor; }

  @Override public CompletableFuture<UUID> getPhoneNumberIdentifier(String number) {
    final List<String> forms=List.copyOf(Util.getAlternateForms(number));
    return transaction(forms, connection -> {
      Map<String,UUID> existing=read(connection,forms);
      if(existing.containsKey(number)) return existing.get(number);
      UUID selected=forms.stream().filter(existing::containsKey).findFirst().map(existing::get).orElseGet(UUID::randomUUID);
      putMissing(connection,forms,existing,selected);
      return selected;
    });
  }

  @Override public CompletableFuture<List<String>> getPhoneNumber(UUID pni) {
    return CompletableFuture.supplyAsync(() -> {
      try(var connection=dataSource.getConnection();var statement=connection.prepareStatement(
          "SELECT e164 FROM signal.phone_number_identifiers WHERE pni=? ORDER BY e164")) {
        statement.setObject(1,pni);
        var numbers=new ArrayList<String>();
        try(var rows=statement.executeQuery()) { while(rows.next()) numbers.add(rows.getString(1)); }
        return numbers;
      } catch(SQLException e) { throw new IllegalStateException("Cannot resolve phone identity",e); }
    },executor);
  }

  @Override public CompletableFuture<UUID> setPni(String original, List<String> allForms, UUID pni) {
    final List<String> forms=List.copyOf(allForms);
    if(forms.isEmpty() || !original.equals(forms.getFirst())) throw new IllegalArgumentException("Original number must be first");
    return transaction(forms,connection -> {
      Map<String,UUID> existing=read(connection,forms);
      if(existing.values().stream().anyMatch(value -> !value.equals(pni))) {
        if(existing.containsKey(original)) return existing.get(original);
        throw new IllegalStateException("An alternate phone form already has a different identity");
      }
      putMissing(connection,forms,existing,pni);
      return pni;
    });
  }

  @Override public CompletableFuture<Void> regeneratePhoneNumberIdentifierMappings(Account account) {
    return account.getNumber().map(number -> setPni(number,Util.getAlternateForms(number),
            account.getPhoneNumberIdentifier().orElseThrow(() -> new AssertionError("Phone number has no PNI")))
        .thenAccept(ignored -> {})).orElseGet(() -> CompletableFuture.completedFuture(null));
  }

  private static Map<String,UUID> read(Connection connection,List<String> forms) throws SQLException {
    var existing=new LinkedHashMap<String,UUID>();
    try(var statement=connection.prepareStatement("SELECT pni FROM signal.phone_number_identifiers WHERE e164=?")) {
      for(String form:forms) {
        statement.setString(1,form);
        try(var rows=statement.executeQuery()) { if(rows.next()) existing.put(form,rows.getObject(1,UUID.class)); }
      }
    }
    return existing;
  }

  private static void putMissing(Connection connection,List<String> forms,Map<String,UUID> existing,UUID pni) throws SQLException {
    try(var statement=connection.prepareStatement("INSERT INTO signal.phone_number_identifiers(e164,pni) VALUES (?,?)")) {
      for(String form:forms.stream().distinct().toList()) {
        if(existing.containsKey(form)) continue;
        statement.setString(1,form);statement.setObject(2,pni);statement.executeUpdate();
      }
    }
  }

  private static long lockId(String number) {
    try { return ByteBuffer.wrap(MessageDigest.getInstance("SHA-256").digest(number.getBytes(StandardCharsets.UTF_8)))
        .getLong() ^ 0x4243504E494C4F43L; }
    catch(NoSuchAlgorithmException e) { throw new AssertionError(e); }
  }

  private <T> CompletableFuture<T> transaction(List<String> forms,SqlWork<T> work) {
    return CompletableFuture.supplyAsync(() -> {
      try(var connection=dataSource.getConnection()) {
        connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        connection.setAutoCommit(false);
        try {
          // Lock every overlapping representation, in the same global order even if hash collisions occur.
          try(var statement=connection.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
            for(long lock:forms.stream().map(PhoneNumberIdentifiersPostgres::lockId).distinct().sorted().toList()) {
              statement.setLong(1,lock);statement.execute();
            }
          }
          T value=work.run(connection);connection.commit();return value;
        } catch(SQLException|RuntimeException e) {
          try { connection.rollback(); } catch(SQLException rollback) { e.addSuppressed(rollback); }
          throw e;
        }
      } catch(SQLException e) { throw new IllegalStateException("Phone identity transaction failed",e); }
    },executor);
  }
  @FunctionalInterface private interface SqlWork<T> { T run(Connection connection) throws SQLException; }
}
