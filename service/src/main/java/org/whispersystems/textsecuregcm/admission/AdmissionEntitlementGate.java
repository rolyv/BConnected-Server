// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.Binding;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.FreshEntitlement;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Source-only account-membership and optional live device-credential checks, not transport
 * enforcement. No HTTP request holds a SQL connection. Callers must recheck at use after any
 * asynchronous wait; this component does not schedule revocation, close sockets, or authorize
 * anonymous capabilities.
 */
public final class AdmissionEntitlementGate {
  private final DataSource dataSource;
  private final AdmissionServiceClient client;

  public AdmissionEntitlementGate(DataSource dataSource, AdmissionServiceClient client) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.client = Objects.requireNonNull(client);
  }

  public static final class DeniedException extends RuntimeException {
    private DeniedException() {
      super("Current alumni entitlement unavailable");
    }
  }

  /**
   * Non-serializable, privately constructed account-membership evidence. It does not expose a
   * reusable boolean or extend the private service's original request-start freshness budget.
   */
  public static final class Authorization {
    private final AdmissionEntitlementGate owner;
    private final Snapshot snapshot;
    private final FreshEntitlement receipt;

    private Authorization(
        AdmissionEntitlementGate owner, Snapshot snapshot, FreshEntitlement receipt) {
      this.owner = owner;
      this.snapshot = snapshot;
      this.receipt = receipt;
    }

    /** Recheck live local state and the original receipt; never refresh or activate. */
    public void requireCurrent(UUID expectedAci) {
      owner.requireCurrent(this, expectedAci);
    }

    @Override
    public String toString() {
      return "AdmissionAuthorization[redacted]";
    }
  }

  /** Device credentials were verified against the same live snapshot as membership. */
  public static final class DeviceAuthorization {
    private final Authorization membership;
    private final byte deviceId;

    private DeviceAuthorization(Authorization membership, byte deviceId) {
      this.membership = membership;
      this.deviceId = deviceId;
    }

    public void requireCurrent(UUID expectedAci, byte expectedDeviceId) {
      if (expectedDeviceId != deviceId) throw denied();
      membership.requireCurrent(expectedAci);
    }

    @Override
    public String toString() {
      return "AdmissionDeviceAuthorization[redacted]";
    }
  }

  // Canonical PostgreSQL JSON captures all account fields, including version and credential/device
  // state. Any intervening account mutation conservatively requires a new authorization. This does
  // not prove that credentials validated by a separate caller before authorize() were current.
  private record Snapshot(Binding binding, String account, String admission, String confirmation) {
    @Override
    public String toString() {
      return "AdmissionSnapshot[redacted]";
    }
  }

  public Authorization authorize(UUID aci) {
    requireAci(aci);
    Snapshot original = transaction(connection -> readLocked(connection, aci));
    return authorizeSnapshot(original);
  }

  /** Password is transient and is never retained by either authorization type. */
  public DeviceAuthorization authorizeDevice(UUID aci, byte deviceId, String password) {
    requireAci(aci);
    if (deviceId < 1 || password == null || password.isEmpty()) throw denied();
    Snapshot original = transaction(connection -> readLocked(connection, aci));
    try {
      var json = SystemMapper.jsonMapper();
      var account = json.treeToValue(json.readTree(original.account()).get("data"), Account.class);
      var device = account.getDevice(deviceId).orElseThrow(AdmissionEntitlementGate::denied);
      if (device.hasLockedCredentials() || !device.getAuthTokenHash().verify(password))
        throw denied();
    } catch (IOException | IllegalArgumentException | NullPointerException invalid) {
      throw denied();
    }
    return new DeviceAuthorization(authorizeSnapshot(original), deviceId);
  }

  private Authorization authorizeSnapshot(Snapshot original) {
    // The initial transaction and connection have ended before credentials/HTTP are requested.
    FreshEntitlement receipt = client.currentEntitlement(original.binding());
    requireReceipt(original, receipt);
    Authorization result = new Authorization(this, original, receipt);
    requireCurrent(result, original.binding().aci());
    return result;
  }

  /** The receiving gate must own the evidence, and callers must specify the intended account. */
  public void requireCurrent(Authorization authorization, UUID expectedAci) {
    Objects.requireNonNull(authorization);
    requireAci(expectedAci);
    if (authorization.owner != this || !authorization.snapshot.binding().aci().equals(expectedAci))
      throw denied();
    requireReceipt(authorization.snapshot, authorization.receipt);
    transaction(
        connection -> {
          requireReceipt(
              authorization.snapshot, authorization.receipt); // Pool acquisition consumes time.
          Snapshot current = readLocked(connection, expectedAci);
          if (!current.equals(authorization.snapshot)) throw denied();
          // Both account and admission updates are blocked until commit. Row waits consume the same
          // receipt deadline; a receipt checked before a lock wait is insufficient.
          requireReceipt(current, authorization.receipt);
          return null;
        });
    // A slow commit or connection close also consumes the original budget.
    requireReceipt(authorization.snapshot, authorization.receipt);
  }

  private static void requireReceipt(Snapshot snapshot, FreshEntitlement receipt) {
    if (receipt == null || !snapshot.binding().equals(receipt.binding())) throw denied();
    receipt.requireFreshCurrentEntitlement();
  }

  private static Snapshot readLocked(Connection connection, UUID aci) throws SQLException {
    final String account;
    // Separate statements preserve the account -> admission -> outbox lock order. FOR SHARE also
    // conflicts with non-key updates to device/credential JSON, unlike FOR KEY SHARE.
    try (var query =
        connection.prepareStatement(
            "SELECT to_jsonb(a)::text FROM signal.accounts a WHERE aci=? FOR SHARE")) {
      query.setObject(1, aci);
      try (var rows = query.executeQuery()) {
        if (!rows.next()) throw denied();
        account = rows.getString(1);
      }
    }
    final Binding binding;
    final String admission;
    final byte[] permit;
    try (var query =
        connection.prepareStatement(
            "SELECT a.*,to_jsonb(a)::text AS snapshot FROM signal.admissions a WHERE aci=? FOR"
                + " SHARE")) {
      query.setObject(1, aci);
      try (var rows = query.executeQuery()) {
        if (!rows.next()
            || !"ACTIVE".equals(rows.getString("status"))
            || rows.getObject("activated_at") == null
            || rows.getObject("suspended_at") != null) throw denied();
        permit = rows.getBytes("permit_id");
        binding =
            new Binding(
                rows.getObject("member_id", UUID.class),
                rows.getLong("approval_epoch"),
                rows.getObject("signal_operation_id", UUID.class),
                Base64.getUrlEncoder().withoutPadding().encodeToString(permit),
                aci);
        admission = rows.getString("snapshot");
      }
    }
    final String confirmation;
    try (var query =
        connection.prepareStatement(
            "SELECT confirmed_at::text FROM signal.admission_confirmation_outbox WHERE permit_id=?"
                + " FOR SHARE")) {
      query.setBytes(1, permit);
      try (var rows = query.executeQuery()) {
        if (!rows.next() || (confirmation = rows.getString(1)) == null) throw denied();
      }
    }
    return new Snapshot(binding, account, admission, confirmation);
  }

  @FunctionalInterface
  private interface Work<T> {
    T apply(Connection connection) throws SQLException;
  }

  private <T> T transaction(Work<T> work) {
    try (var connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
      try {
        try (var statement = connection.createStatement()) {
          statement.execute("SET LOCAL statement_timeout='5s'");
          statement.execute("SET LOCAL lock_timeout='3s'");
        }
        T result = work.apply(connection);
        connection.commit();
        return result;
      } catch (SQLException | RuntimeException failure) {
        try {
          connection.rollback();
        } catch (SQLException ignored) {
        }
        throw failure;
      }
    } catch (SQLException ignored) {
      throw denied();
    }
  }

  private static void requireAci(UUID aci) {
    if (aci == null || aci.equals(new UUID(0, 0))) throw denied();
  }

  private static DeniedException denied() {
    return new DeniedException();
  }
}
