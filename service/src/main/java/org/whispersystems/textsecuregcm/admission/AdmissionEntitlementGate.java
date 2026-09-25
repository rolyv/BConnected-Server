// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.Binding;
import org.whispersystems.textsecuregcm.admission.AdmissionServiceClient.FreshEntitlement;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Account-membership and live device-credential checks, including initial pilot authentication.
 * No HTTP request holds a SQL connection. Callers must recheck at use after any
 * asynchronous wait; this component does not schedule revocation, close sockets, or authorize
 * anonymous capabilities.
 */
public final class AdmissionEntitlementGate {
  private final DataSource dataSource;
  private final AdmissionServiceClient client;
  private final Set<UUID> allowedMembers;

  public AdmissionEntitlementGate(DataSource dataSource, AdmissionServiceClient client) {
    this(dataSource, client, null);
  }

  /** An explicit cohort constrains callers and recipients at every local proof recheck. */
  public AdmissionEntitlementGate(DataSource dataSource, AdmissionServiceClient client,
      Set<UUID> allowedMembers) {
    this.dataSource = Objects.requireNonNull(dataSource);
    this.client = Objects.requireNonNull(client);
    this.allowedMembers = allowedMembers == null ? null : Set.copyOf(allowedMembers);
  }

  public static final class DeniedException extends RuntimeException {
    private DeniedException() {
      super("Current alumni entitlement unavailable");
    }
  }

  /** No current decision is possible; this does not establish invalid device credentials. */
  public static final class UnavailableException extends RuntimeException {
    private UnavailableException() {
      super("Current alumni entitlement unavailable");
    }
  }

  static final class RecipientDeniedException extends RuntimeException {
    private RecipientDeniedException() { super("Current recipient unavailable"); }
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

    /** A detached recipient snapshot; callers must retain and recheck this authorization at use. */
    public Account accountForMessageSend(UUID expectedAci) {
      requireCurrent(expectedAci);
      return accountSnapshot(snapshot);
    }

    @Override
    public String toString() {
      return "AdmissionAuthorization[redacted]";
    }
  }

  /** Device credentials were verified against the same live snapshot as membership. */
  public record AccountProjection(UUID aci, UUID pni, String number, byte deviceId) {
    @Override public String toString() { return "AdmissionAccountProjection[redacted]"; }
  }

  /** Device credentials were verified against the same live snapshot as membership. */
  public static final class DeviceAuthorization {
    private final Authorization membership;
    private final byte deviceId;
    private final Instant primaryDeviceLastSeen;
    private final long deviceCreated;
    private final AccountProjection projection;

    private DeviceAuthorization(Authorization membership, byte deviceId, Instant primaryDeviceLastSeen,
        AccountProjection projection, long deviceCreated) {
      this.membership = membership;
      this.deviceId = deviceId;
      this.deviceCreated = deviceCreated;
      this.primaryDeviceLastSeen = primaryDeviceLastSeen;
      this.projection = projection;
    }

    public void requireCurrent(UUID expectedAci, byte expectedDeviceId) {
      if (expectedDeviceId != deviceId) throw denied();
      membership.requireCurrent(expectedAci);
    }

    /**
     * Native mutation boundary. The caller must commit/roll back this READ COMMITTED transaction;
     * account/admission locks remain held through its mutation. No separate connection or HTTP
     * request is opened, so a full deletion pool cannot starve waiting for another proof connection.
     */
    public void requireCurrent(Connection connection, UUID expectedAci, byte expectedDeviceId, long expectedCreated) {
      if (expectedDeviceId != deviceId) throw denied();
      if (expectedCreated != deviceCreated) throw unavailable();
      membership.owner.requireCurrent(connection, membership, expectedAci);
    }

    public void requireCurrent(UUID expectedAci, byte expectedDeviceId, long expectedCreated) {
      if (expectedCreated != deviceCreated) throw unavailable();
      requireCurrent(expectedAci, expectedDeviceId);
    }

    /** Only for scheduling closure; this is not a local-state or credential check. */
    public long remainingNanos() {
      return membership.receipt.remainingNanos();
    }

    /**
     * Renew the original credential-verified snapshot, never adopt a changed account/device or
     * retain its password. The old lease must survive the complete renewal, including SQL waits.
     */
    public DeviceAuthorization renew(UUID expectedAci, byte expectedDeviceId) {
      requireCurrent(expectedAci, expectedDeviceId);
      Authorization next = membership.owner.authorizeSnapshot(membership.snapshot);
      requireReceipt(membership.snapshot, membership.receipt);
      return new DeviceAuthorization(next, deviceId, primaryDeviceLastSeen, projection, deviceCreated);
    }

    /** Immutable authoritative identity from this same credential-verified snapshot, rechecked now. */
    public AccountProjection accountProjection() {
      requireCurrent(projection.aci(), projection.deviceId());
      return projection;
    }

    /**
     * Detached credential-issuance input from the original authenticated SQL snapshot. A cache read
     * could supply a different identity key or PNI even when this proof is current. This copy is
     * never persisted; issuers must recheck the same proof after signing and before returning it.
     */
    public Account accountForCredentialIssuance(UUID expectedAci, byte expectedDeviceId) {
      requireCurrent(expectedAci, expectedDeviceId);
      return accountSnapshot(membership.snapshot);
    }

    /** Immutable group-operation binding, checked under this original device receipt. */
    public Binding groupOperationBinding() {
      requireCurrent(projection.aci(), projection.deviceId());
      return membership.snapshot.binding();
    }

    /** Metadata from the credential-verified snapshot, not a separate cached account read. */
    public Instant primaryDeviceLastSeen() {
      return primaryDeviceLastSeen;
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

  /** The public directory contains labels only, never phone numbers or admission identifiers. */
  public record DirectoryMember(UUID aci, byte deviceId, String fullName, int graduationYear) {
    @Override public String toString() { return "DirectoryMember[redacted]"; }
  }
  public record DirectoryPage(List<DirectoryMember> members, Integer nextOffset) {
    public DirectoryPage { members = List.copyOf(members); }
    @Override public String toString() { return "DirectoryPage[redacted]"; }
  }

  /** Retains every original receipt until the response has been constructed. No receipt renewal. */
  public final class DirectoryAuthorization {
    private final DeviceAuthorization caller;
    private final AdmissionServiceClient.DirectoryPage privatePage;
    private final List<Authorization> targets;
    private final DirectoryPage page;
    private DirectoryAuthorization(DeviceAuthorization caller, AdmissionServiceClient.DirectoryPage privatePage,
        List<Authorization> targets, DirectoryPage page) {
      this.caller = caller; this.privatePage = privatePage; this.targets = List.copyOf(targets); this.page = page;
    }
    public DirectoryPage page() { requireCurrent(); return page; }
    public void requireCurrent() {
      privatePage.requireFresh();
      transaction(connection -> {
        caller.requireCurrent(connection, caller.projection.aci(), caller.deviceId, caller.deviceCreated);
        for (var target : targets) {
          try { AdmissionEntitlementGate.this.requireCurrent(connection, target, target.snapshot.binding().aci()); }
          catch (DeniedException noLongerVisible) { throw unavailable(); }
        }
        return null;
      });
      privatePage.requireFresh();
      requireReceipt(caller.membership.snapshot, caller.membership.receipt);
      for (var target : targets) requireReceipt(target.snapshot, target.receipt);
    }
    @Override public String toString() { return "DirectoryAuthorization[redacted]"; }
  }

  public DirectoryAuthorization directory(DeviceAuthorization caller, UUID expectedCaller, byte expectedDevice,
      String query, Integer offset, UUID targetAci) {
    if (caller == null || caller.membership.owner != this || expectedDevice != 1) throw denied();
    caller.requireCurrent(expectedCaller, expectedDevice);
    var privatePage = client.directory(caller.groupOperationBinding(), query, offset, targetAci);
    caller.requireCurrent(expectedCaller, expectedDevice);
    var targets = new java.util.ArrayList<Authorization>();
    var members = new java.util.ArrayList<DirectoryMember>();
    for (var row : privatePage.members) {
      privatePage.requireFresh();
      UUID aci = row.entitlement().binding().aci();
      final Snapshot snapshot;
      try { snapshot = transaction(connection -> readLocked(connection, aci)); }
      catch (DeniedException hiddenTarget) { continue; } // Not locally ACTIVE or outside this cohort.
      requireReceipt(snapshot, row.entitlement()); // Metadata must belong to the exact local binding.
      var proof = new Authorization(this, snapshot, row.entitlement());
      var account = accountSnapshot(snapshot);
      if (account.getDevices().size() != 1 || account.getDevice((byte) 1).isEmpty()) continue;
      targets.add(proof);
      members.add(new DirectoryMember(aci, (byte) 1, row.fullName(), row.graduationYear()));
    }
    var result = new DirectoryAuthorization(caller, privatePage, targets, new DirectoryPage(members, privatePage.nextOffset));
    result.requireCurrent();
    return result;
  }

  /** Both original proofs are checked under one native transaction, including its elapsed budget. */
  void requireCurrentSend(DeviceAuthorization sender, UUID senderAci, byte senderDevice,
      Authorization recipient, UUID recipientAci) {
    if (sender == null || sender.deviceId != senderDevice || sender.membership.owner != this
        || recipient == null || recipient.owner != this) throw denied();
    transaction(connection -> {
      // FOR SHARE locks are compatible across sends; no remote request holds these locks.
      requireCurrent(connection, sender.membership, senderAci);
      try { requireCurrent(connection, recipient, recipientAci); }
      catch (DeniedException denied) { throw new RecipientDeniedException(); }
      requireReceipt(sender.membership.snapshot, sender.membership.receipt);
      requireReceipt(recipient.snapshot, recipient.receipt);
      return null;
    });
    requireReceipt(sender.membership.snapshot, sender.membership.receipt);
    requireReceipt(recipient.snapshot, recipient.receipt);
  }

  /** Key reads/publications join the operation's transaction; no HTTP or separate pool acquisition. */
  void requireCurrentKeys(Connection connection, DeviceAuthorization caller, UUID callerAci, byte callerDevice,
      Authorization target, UUID targetAci) {
    if (caller == null || caller.deviceId != callerDevice || caller.membership.owner != this) throw denied();
    requireCurrent(connection, caller.membership, callerAci);
    if (target != null) {
      try { requireCurrent(connection, target, targetAci); }
      catch (DeniedException denied) { throw new RecipientDeniedException(); }
    }
    requireKeyReceipts(caller, target);
  }

  void requireKeyReceipts(DeviceAuthorization caller, Authorization target) {
    if (caller == null || caller.membership.owner != this || (target != null && target.owner != this)) throw denied();
    requireReceipt(caller.membership.snapshot, caller.membership.receipt);
    if (target != null) requireReceipt(target.snapshot, target.receipt);
  }

  private static Account accountSnapshot(Snapshot snapshot) {
    try {
      var json = SystemMapper.jsonMapper();
      var row = json.readTree(snapshot.account());
      var account = json.treeToValue(row.required("data"), Account.class);
      account.setAccountIdentifier(UUID.fromString(row.required("aci").textValue()));
      account.setNumber(row.required("number").textValue(), UUID.fromString(row.required("pni").textValue()));
      account.setVersion(row.required("version").intValue());
      if (account.getAccountIdentityKey() == null) throw unavailable();
      return account;
    } catch (IOException | IllegalArgumentException | NullPointerException malformed) {
      throw unavailable();
    }
  }

  /** Password is transient and is never retained by either authorization type. */
  public DeviceAuthorization authorizeDevice(UUID aci, byte deviceId, String password) {
    requireAci(aci);
    if (deviceId < 1 || password == null || password.isEmpty()) throw denied();
    Snapshot original = transaction(connection -> readLocked(connection, aci));
    final Instant primaryDeviceLastSeen;
    final AccountProjection projection;
    final long deviceCreated;
    try {
      var json = SystemMapper.jsonMapper();
      var row = json.readTree(original.account());
      var account = json.treeToValue(row.get("data"), Account.class);
      var device = account.getDevice(deviceId).orElseThrow(AdmissionEntitlementGate::denied);
      if (device.hasLockedCredentials() || !device.getAuthTokenHash().verify(password))
        throw denied();
      deviceCreated = device.getCreated();
      if (deviceCreated < 0) throw unavailable();
      long lastSeen = account.getDevice(org.whispersystems.textsecuregcm.storage.Device.PRIMARY_ID)
          .orElseThrow(AdmissionEntitlementGate::denied).getLastSeen();
      if (lastSeen < 0) throw unavailable();
      primaryDeviceLastSeen = Instant.ofEpochMilli(lastSeen);
      UUID storedAci = UUID.fromString(row.required("aci").textValue());
      UUID pni = UUID.fromString(row.required("pni").textValue());
      String number = row.required("number").textValue();
      if (!aci.equals(storedAci) || pni.equals(new UUID(0, 0)) || number == null
          || !number.matches("\\+[1-9][0-9]{1,14}")) throw unavailable();
      projection = new AccountProjection(storedAci, pni, number, deviceId);
    } catch (IOException | IllegalArgumentException | NullPointerException invalid) {
      throw unavailable();
    }
    return new DeviceAuthorization(authorizeSnapshot(original), deviceId, primaryDeviceLastSeen, projection, deviceCreated);
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
          // The row may have changed benignly; stale evidence is not proof of a bad password.
          if (!current.equals(authorization.snapshot)) throw unavailable();
          // Both account and admission updates are blocked until commit. Row waits consume the same
          // receipt deadline; a receipt checked before a lock wait is insufficient.
          requireReceipt(current, authorization.receipt);
          return null;
        });
    // A slow commit or connection close also consumes the original budget.
    requireReceipt(authorization.snapshot, authorization.receipt);
  }

  private void requireCurrent(Connection connection, Authorization authorization, UUID expectedAci) {
    requireAci(expectedAci);
    if (authorization.owner != this || !authorization.snapshot.binding().aci().equals(expectedAci))
      throw denied();
    try {
      if (connection.getAutoCommit()
          || connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED)
        throw unavailable();
      requireReceipt(authorization.snapshot, authorization.receipt);
      Snapshot current = readLocked(connection, expectedAci);
      if (!current.equals(authorization.snapshot)) throw unavailable();
      requireReceipt(current, authorization.receipt);
    } catch (SQLException failure) {
      throw unavailable();
    }
  }

  private static void requireReceipt(Snapshot snapshot, FreshEntitlement receipt) {
    if (receipt == null || !snapshot.binding().equals(receipt.binding())) throw unavailable();
    receipt.requireFreshCurrentEntitlement();
  }

  AdmissionServiceClient.Binding keyPublicationBinding(Connection connection, DeviceAuthorization caller, UUID aci, byte device) {
    requireCurrentKeys(connection, caller, aci, device, null, aci);
    return caller.membership.snapshot.binding();
  }

  /** Seal exactly one permitted self-update without renewing its original private-service receipt. */
  Authorization accountMutationResult(Connection connection, DeviceAuthorization caller, Account written) {
    final Authorization original = caller.membership;
    if (original.owner != this || caller.deviceId != org.whispersystems.textsecuregcm.storage.Device.PRIMARY_ID
        || !original.snapshot.binding().aci().equals(written.getAccountIdentifier())) throw denied();
    try {
      if (connection.getAutoCommit()
          || connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) throw unavailable();
      requireReceipt(original.snapshot, original.receipt);
      final Snapshot current = readLocked(connection, written.getAccountIdentifier());
      final var expected = (com.fasterxml.jackson.databind.node.ObjectNode)
          SystemMapper.jsonMapper().readTree(original.snapshot.account());
      expected.set("data", SystemMapper.jsonMapper().readTree(SystemMapper.jsonMapper().writeValueAsString(written)));
      expected.put("version", written.getVersion() + 1);
      if (!expected.equals(SystemMapper.jsonMapper().readTree(current.account()))
          || !original.snapshot.binding().equals(current.binding())
          || !original.snapshot.admission().equals(current.admission())
          || !original.snapshot.confirmation().equals(current.confirmation())) throw unavailable();
      requireReceipt(current, original.receipt);
      return new Authorization(this, current, original.receipt);
    } catch (java.io.IOException | SQLException failure) {
      throw unavailable();
    }
  }

  private Snapshot readLocked(Connection connection, UUID aci) throws SQLException {
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
        if (allowedMembers != null && !allowedMembers.contains(rows.getObject("member_id", UUID.class))) {
          throw denied();
        }
        permit = rows.getBytes("permit_id");
        try {
          binding =
              new Binding(
                  rows.getObject("member_id", UUID.class),
                  rows.getLong("approval_epoch"),
                  rows.getObject("signal_operation_id", UUID.class),
                  Base64.getUrlEncoder().withoutPadding().encodeToString(permit),
                  aci);
        } catch (IllegalArgumentException | NullPointerException malformedStoredBinding) {
          throw unavailable();
        }
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
      throw unavailable();
    }
  }

  private static void requireAci(UUID aci) {
    if (aci == null || aci.equals(new UUID(0, 0))) throw denied();
  }

  private static DeniedException denied() {
    return new DeniedException();
  }

  private static UnavailableException unavailable() {
    return new UnavailableException();
  }
}
