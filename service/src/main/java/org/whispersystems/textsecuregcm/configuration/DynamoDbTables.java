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

  private final Table backups;
  private final Table deletedAccounts;
  private final Table deletedAccountsLock;
  private final TableWithExpiration donationPermits;
  private final IssuedReceiptsTableConfiguration issuedReceipts;
  private final TableWithExpiration onetimeDonations;
  private final Table redeemedReceipts;
  private final Table subscriptions;

  public DynamoDbTables(
      @JsonProperty("accounts") final AccountsTableConfiguration accounts,
      @JsonProperty("backups") final Table backups,
      @JsonProperty("deletedAccounts") final Table deletedAccounts,
      @JsonProperty("deletedAccountsLock") final Table deletedAccountsLock,
      @JsonProperty("donationPermits") final TableWithExpiration donationPermits,
      @JsonProperty("issuedReceipts") final IssuedReceiptsTableConfiguration issuedReceipts,
      @JsonProperty("onetimeDonations") final TableWithExpiration onetimeDonations,
      @JsonProperty("redeemedReceipts") final Table redeemedReceipts,
      @JsonProperty("subscriptions") final Table subscriptions) {

    this.accounts = accounts;
    this.backups = backups;
    this.deletedAccounts = deletedAccounts;
    this.deletedAccountsLock = deletedAccountsLock;
    this.donationPermits = donationPermits;
    this.issuedReceipts = issuedReceipts;
    this.onetimeDonations = onetimeDonations;
    this.redeemedReceipts = redeemedReceipts;
    this.subscriptions = subscriptions;
  }

  @NotNull
  @Valid
  public AccountsTableConfiguration getAccounts() {
    return accounts;
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
  public Table getRedeemedReceipts() {
    return redeemedReceipts;
  }

  @NotNull
  @Valid
  public Table getSubscriptions() {
    return subscriptions;
  }

}
