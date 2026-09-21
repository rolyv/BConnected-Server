/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;

public class DynamoDbTables {

  public static class Table {
    private final String tableName;

    @JsonCreator
    public Table(
        @JsonProperty("tableName") final String tableName) {
      this.tableName = tableName;
    }

    @NotEmpty
    public String getTableName() {
      return tableName;
    }
  }

  public static class TableWithExpiration extends Table {
    private final Duration expiration;

    @JsonCreator
    public TableWithExpiration(
        @JsonProperty("tableName") final String tableName,
        @JsonProperty("expiration") final Duration expiration) {
      super(tableName);
      this.expiration = expiration;
    }

    @NotNull
    public Duration getExpiration() {
      return expiration;
    }
  }

  private final AccountsTableConfiguration accounts;

  private final Table changeNumberWaitingPeriods;
  private final Table backups;
  private final Table deletedAccounts;
  private final Table deletedAccountsLock;
  private final TableWithExpiration donationPermits;
  private final IssuedReceiptsTableConfiguration issuedReceipts;
  private final TableWithExpiration onetimeDonations;
  private final Table phoneNumberIdentifiers;
  private final Table redeemedReceipts;
  private final TableWithExpiration registrationRecovery;
  private final Table subscriptions;
  private final Table verificationSessions;

  public DynamoDbTables(
      @JsonProperty("accounts") final AccountsTableConfiguration accounts,
      @JsonProperty("changeNumberWaitingPeriods") final Table changeNumberWaitingPeriods,
      @JsonProperty("backups") final Table backups,
      @JsonProperty("deletedAccounts") final Table deletedAccounts,
      @JsonProperty("deletedAccountsLock") final Table deletedAccountsLock,
      @JsonProperty("donationPermits") final TableWithExpiration donationPermits,
      @JsonProperty("issuedReceipts") final IssuedReceiptsTableConfiguration issuedReceipts,
      @JsonProperty("onetimeDonations") final TableWithExpiration onetimeDonations,
      @JsonProperty("phoneNumberIdentifiers") final Table phoneNumberIdentifiers,
      @JsonProperty("redeemedReceipts") final Table redeemedReceipts,
      @JsonProperty("registrationRecovery") final TableWithExpiration registrationRecovery,
      @JsonProperty("subscriptions") final Table subscriptions,
      @JsonProperty("verificationSessions") final Table verificationSessions) {

    this.accounts = accounts;
    this.changeNumberWaitingPeriods = changeNumberWaitingPeriods;
    this.backups = backups;
    this.deletedAccounts = deletedAccounts;
    this.deletedAccountsLock = deletedAccountsLock;
    this.donationPermits = donationPermits;
    this.issuedReceipts = issuedReceipts;
    this.onetimeDonations = onetimeDonations;
    this.phoneNumberIdentifiers = phoneNumberIdentifiers;
    this.redeemedReceipts = redeemedReceipts;
    this.registrationRecovery = registrationRecovery;
    this.subscriptions = subscriptions;
    this.verificationSessions = verificationSessions;
  }

  @NotNull
  @Valid
  public AccountsTableConfiguration getAccounts() {
    return accounts;
  }

  @NotNull
  @Valid
  public Table getChangeNumberWaitingPeriods() {
    return changeNumberWaitingPeriods;
  }

  @NotNull
  @Valid
  public Table getBackups() {
    return backups;
  }

  @NotNull
  @Valid
  public Table getDeletedAccounts() {
    return deletedAccounts;
  }

  @NotNull
  @Valid
  public Table getDeletedAccountsLock() {
    return deletedAccountsLock;
  }

  @NotNull
  @Valid
  public TableWithExpiration getDonationPermits() {
    return donationPermits;
  }

  @NotNull
  @Valid
  public IssuedReceiptsTableConfiguration getIssuedReceipts() {
    return issuedReceipts;
  }

  @NotNull
  @Valid
  public TableWithExpiration getOnetimeDonations() {
    return onetimeDonations;
  }

  @NotNull
  @Valid
  public Table getPhoneNumberIdentifiers() {
    return phoneNumberIdentifiers;
  }

  @NotNull
  @Valid
  public Table getRedeemedReceipts() {
    return redeemedReceipts;
  }

  @NotNull
  @Valid
  public TableWithExpiration getRegistrationRecovery() {
    return registrationRecovery;
  }

  @NotNull
  @Valid
  public Table getSubscriptions() {
    return subscriptions;
  }

  @NotNull
  @Valid
  public Table getVerificationSessions() {
    return verificationSessions;
  }
}
