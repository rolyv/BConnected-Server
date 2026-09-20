// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.converter.util.ObjectConverter;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.storage.Account;

/** Native App Attest persistence with atomic monotonic replacement and global public-key ownership. */
public final class AppleDeviceChecksPostgres implements AppleDeviceCheckStore {
  private final DataSource dataSource;
  private final AppleDeviceCheckCodec codec;

  public AppleDeviceChecksPostgres(final DataSource dataSource, final ObjectConverter objectConverter) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.codec = new AppleDeviceCheckCodec(objectConverter);
  }

  @Override
  public List<byte[]> keyIds(final Account account) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        SELECT key_id FROM signal.apple_device_checks WHERE account_id = ? ORDER BY key_id
        """)) {
      statement.setObject(1, account.getAccountIdentifier());
      final List<byte[]> keys = new ArrayList<>();
      try (var rows = statement.executeQuery()) {
        while (rows.next()) keys.add(rows.getBytes(1));
      }
      return List.copyOf(keys);
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL device-check key lookup failed", e);
    }
  }

  @Override
  public boolean storeAttestation(final Account account, final byte[] keyId, final DCAppleDevice appleDevice)
      throws DuplicatePublicKeyException {
    Objects.requireNonNull(keyId);
    final AppleDeviceCheckCodec.Encoded encoded = codec.encode(appleDevice);
    final byte[] publicKey = AppleDeviceCheckCodec.publicKey(appleDevice).getEncoded();
    try (var connection = dataSource.getConnection()) {
      connection.setTransactionIsolation(java.sql.Connection.TRANSACTION_READ_COMMITTED);
      connection.setAutoCommit(false);
      try {
        // Check the account/key counter first, matching the upstream precedence when both conditions would fail.
        try (var statement = connection.prepareStatement("""
            INSERT INTO signal.apple_device_checks
              (account_id, key_id, counter, credential_data, attestation_statement, authenticator_extensions)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (account_id, key_id) DO UPDATE SET
              counter = EXCLUDED.counter, credential_data = EXCLUDED.credential_data,
              attestation_statement = EXCLUDED.attestation_statement,
              authenticator_extensions = EXCLUDED.authenticator_extensions
            WHERE signal.apple_device_checks.counter <= EXCLUDED.counter
            """)) {
          statement.setObject(1, account.getAccountIdentifier());
          statement.setBytes(2, keyId);
          statement.setLong(3, encoded.counter());
          statement.setBytes(4, encoded.credentialData());
          statement.setBytes(5, encoded.statement());
          statement.setBytes(6, encoded.extensions());
          if (statement.executeUpdate() == 0) {
            connection.rollback();
            return false;
          }
        }
        // Keep historical public-key claims when replacing a key ID, as the upstream constraint table does.
        try (var statement = connection.prepareStatement("""
            INSERT INTO signal.apple_device_check_public_keys (public_key, account_id) VALUES (?, ?)
            ON CONFLICT (public_key) DO UPDATE SET account_id = EXCLUDED.account_id
            WHERE signal.apple_device_check_public_keys.account_id = EXCLUDED.account_id
            """)) {
          statement.setBytes(1, publicKey);
          statement.setObject(2, account.getAccountIdentifier());
          if (statement.executeUpdate() == 0) throw new DuplicatePublicKeyException();
        }
        connection.commit();
        return true;
      } catch (SQLException | RuntimeException | DuplicatePublicKeyException e) {
        try { connection.rollback(); }
        catch (SQLException rollbackFailure) { e.addSuppressed(rollbackFailure); }
        throw e;
      }
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL device-check attestation update failed", e);
    }
  }

  @Override
  public Optional<DCAppleDevice> lookup(final Account account, final byte[] keyId) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        SELECT credential_data, attestation_statement, authenticator_extensions, counter
        FROM signal.apple_device_checks WHERE account_id = ? AND key_id = ?
        """)) {
      statement.setObject(1, account.getAccountIdentifier());
      statement.setBytes(2, keyId);
      try (var rows = statement.executeQuery()) {
        return rows.next() ? Optional.of(codec.decode(rows.getBytes(1), rows.getBytes(2), rows.getBytes(3), rows.getLong(4)))
            : Optional.empty();
      }
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL device-check attestation lookup failed", e);
    }
  }

  @Override
  public boolean updateCounter(final Account account, final byte[] keyId, final long newCounter) {
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        UPDATE signal.apple_device_checks SET counter = ? WHERE account_id = ? AND key_id = ? AND counter <= ?
        """)) {
      statement.setLong(1, newCounter);
      statement.setObject(2, account.getAccountIdentifier());
      statement.setBytes(3, keyId);
      statement.setLong(4, newCounter);
      return statement.executeUpdate() == 1;
    } catch (SQLException e) {
      throw new IllegalStateException("PostgreSQL device-check counter update failed", e);
    }
  }
}
