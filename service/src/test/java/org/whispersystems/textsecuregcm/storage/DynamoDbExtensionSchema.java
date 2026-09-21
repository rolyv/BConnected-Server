/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.util.Collections;
import java.util.List;
import org.whispersystems.textsecuregcm.backup.BackupsDb;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.LocalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.Projection;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ProvisionedThroughput;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

public final class DynamoDbExtensionSchema {

  // Generic transaction participants for retained Dynamo account atomicity tests.
  public static final String TRANSACTION_PARTITION = "partition";
  public static final String TRANSACTION_SORT = "sort";

  public enum Tables implements DynamoDbExtension.TableSchema {

    ACCOUNTS("accounts_test",
        Accounts.KEY_ACCOUNT_UUID,
        null,
        List.of(
            AttributeDefinition.builder()
                .attributeName(Accounts.KEY_ACCOUNT_UUID)
                .attributeType(ScalarAttributeType.B)
                .build(),
            AttributeDefinition.builder()
                .attributeName(Accounts.ATTR_USERNAME_LINK_UUID)
                .attributeType(ScalarAttributeType.B)
                .build()),
        List.of(
            GlobalSecondaryIndex.builder()
                .indexName(Accounts.USERNAME_LINK_TO_UUID_INDEX)
                .keySchema(
                    KeySchemaElement.builder()
                        .attributeName(Accounts.ATTR_USERNAME_LINK_UUID)
                        .keyType(KeyType.HASH)
                        .build()
                )
                .projection(Projection.builder().projectionType(ProjectionType.KEYS_ONLY).build())
                .provisionedThroughput(ProvisionedThroughput.builder().readCapacityUnits(10L).writeCapacityUnits(10L).build())
                .build()
        ),
        List.of()),

    BACKUPS("backups_test",
        BackupsDb.KEY_BACKUP_ID_HASH,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(BackupsDb.KEY_BACKUP_ID_HASH)
            .attributeType(ScalarAttributeType.B).build()),
        Collections.emptyList(), Collections.emptyList()),

    CHANGE_NUMBER_WAITING_PERIODS("change_number_waiting_periods_test",
        ChangeNumberWaitingPeriods.KEY_ACCOUNT_UUID,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(ChangeNumberWaitingPeriods.KEY_ACCOUNT_UUID)
            .attributeType(ScalarAttributeType.B)
            .build()),
        List.of(), List.of()),

    TRANSACTION_PARTICIPANTS("transaction_participants_test",
        TRANSACTION_PARTITION,
        TRANSACTION_SORT,
        List.of(
            AttributeDefinition.builder()
                .attributeName(TRANSACTION_PARTITION)
                .attributeType(ScalarAttributeType.S)
                .build(),
            AttributeDefinition.builder()
                .attributeName(TRANSACTION_SORT)
                .attributeType(ScalarAttributeType.S)
                .build()),
        List.of(),
        List.of()),

    DELETED_ACCOUNTS("deleted_accounts_test",
        Accounts.DELETED_ACCOUNTS_KEY_ACCOUNT_PNI,
        null,
        List.of(
            AttributeDefinition.builder()
                .attributeName(Accounts.DELETED_ACCOUNTS_KEY_ACCOUNT_PNI)
                .attributeType(ScalarAttributeType.S).build(),
            AttributeDefinition.builder()
                .attributeName(Accounts.DELETED_ACCOUNTS_ATTR_ACCOUNT_UUID)
                .attributeType(ScalarAttributeType.B)
                .build()),
        List.of(
            GlobalSecondaryIndex.builder()
                .indexName(Accounts.DELETED_ACCOUNTS_UUID_TO_PNI_INDEX_NAME)
                .keySchema(
                    KeySchemaElement.builder().attributeName(Accounts.DELETED_ACCOUNTS_ATTR_ACCOUNT_UUID).keyType(KeyType.HASH).build()
                )
                .projection(Projection.builder().projectionType(ProjectionType.KEYS_ONLY).build())
                .provisionedThroughput(ProvisionedThroughput.builder().readCapacityUnits(10L).writeCapacityUnits(10L).build())
                .build()),
        List.of()
    ),

    DELETED_ACCOUNTS_LOCK("deleted_accounts_lock_test",
        AccountLockManager.KEY_ACCOUNT_PNI,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(AccountLockManager.KEY_ACCOUNT_PNI)
            .attributeType(ScalarAttributeType.S).build()),
        List.of(), List.of()),

    DONATION_PERMITS("donation_permits_test",
        DonationPermits.KEY_SPEND_ID,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(DonationPermits.KEY_SPEND_ID)
            .attributeType(ScalarAttributeType.B)
            .build()), List.of(), List.of()),

    NUMBERS("numbers_test",
        Accounts.ATTR_ACCOUNT_E164,
        null,
        List.of(AttributeDefinition.builder()
              .attributeName(Accounts.ATTR_ACCOUNT_E164)
              .attributeType(ScalarAttributeType.S)
            .build()),
        List.of(), List.of()),

    PNI("pni_test",
        PhoneNumberIdentifiers.KEY_E164,
        null,
        List.of(
            AttributeDefinition.builder()
                .attributeName(PhoneNumberIdentifiers.KEY_E164)
                .attributeType(ScalarAttributeType.S)
                .build(),
            AttributeDefinition.builder()
                .attributeName(PhoneNumberIdentifiers.ATTR_PHONE_NUMBER_IDENTIFIER)
                .attributeType(ScalarAttributeType.B)
                .build()),
        List.of(GlobalSecondaryIndex.builder()
            .indexName(PhoneNumberIdentifiers.INDEX_NAME)
            .projection(Projection.builder()
                .projectionType(ProjectionType.KEYS_ONLY)
                .build())
            .keySchema(KeySchemaElement.builder().keyType(KeyType.HASH)
                .attributeName(PhoneNumberIdentifiers.ATTR_PHONE_NUMBER_IDENTIFIER)
                .build())
            .provisionedThroughput(ProvisionedThroughput.builder().readCapacityUnits(10L).writeCapacityUnits(10L).build())
            .build()),
        List.of()),

    PNI_ASSIGNMENTS("pni_assignment_test",
        Accounts.ATTR_PNI_UUID,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(Accounts.ATTR_PNI_UUID)
            .attributeType(ScalarAttributeType.B)
            .build()),
        List.of(), List.of()),

    ISSUED_RECEIPTS("issued_receipts_test",
        IssuedReceiptsManager.KEY_PROCESSOR_ITEM_ID,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(IssuedReceiptsManager.KEY_PROCESSOR_ITEM_ID)
            .attributeType(ScalarAttributeType.S)
            .build()),
        List.of(), List.of()),

    ONETIME_DONATIONS("onetime_donations_test",
        OneTimeDonationsManager.KEY_PAYMENT_ID,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(OneTimeDonationsManager.KEY_PAYMENT_ID)
            .attributeType(ScalarAttributeType.S)
            .build()),
        List.of(), List.of()),

    REDEEMED_RECEIPTS("redeemed_receipts_test",
        RedeemedReceiptsManager.KEY_SERIAL,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(RedeemedReceiptsManager.KEY_SERIAL)
            .attributeType(ScalarAttributeType.B)
            .build()),
        List.of(), List.of()),

    PHONE_NUMBER_RECOVERY_PASSWORDS("registration_recovery_passwords_test",
        PhoneNumberRecoveryPasswords.KEY_PNI,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(PhoneNumberRecoveryPasswords.KEY_PNI)
            .attributeType(ScalarAttributeType.S)
            .build()),
        List.of(), List.of()),

    SUBSCRIPTIONS("subscriptions_test",
        Subscriptions.KEY_USER,
        null,
        List.of(
            AttributeDefinition.builder()
                .attributeName(Subscriptions.KEY_USER)
                .attributeType(ScalarAttributeType.B)
                .build(),
            AttributeDefinition.builder()
                .attributeName(Subscriptions.KEY_PROCESSOR_ID_CUSTOMER_ID)
                .attributeType(ScalarAttributeType.B)
                .build()),
        List.of(GlobalSecondaryIndex.builder()
            .indexName(Subscriptions.INDEX_NAME)
            .keySchema(KeySchemaElement.builder()
                .attributeName(Subscriptions.KEY_PROCESSOR_ID_CUSTOMER_ID)
                .keyType(KeyType.HASH)
                .build())
            .projection(Projection.builder()
                .projectionType(ProjectionType.KEYS_ONLY)
                .build())
            .provisionedThroughput(ProvisionedThroughput.builder()
                .readCapacityUnits(20L)
                .writeCapacityUnits(20L)
                .build())
            .build()),
        List.of()),

    USED_LINK_DEVICE_TOKENS("used_link_device_tokens_test",
        Accounts.KEY_LINK_DEVICE_TOKEN_HASH,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(Accounts.KEY_LINK_DEVICE_TOKEN_HASH)
            .attributeType(ScalarAttributeType.B)
            .build()),
        List.of(),
        List.of()),

    USERNAMES("usernames_test",
        Accounts.ATTR_USERNAME_HASH,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(Accounts.ATTR_USERNAME_HASH)
            .attributeType(ScalarAttributeType.B)
            .build()),
        List.of(), List.of()),

    VERIFICATION_SESSIONS("verification_sessions_test",
        VerificationSessions.KEY_KEY,
        null,
        List.of(AttributeDefinition.builder()
            .attributeName(VerificationSessions.KEY_KEY)
            .attributeType(ScalarAttributeType.S)
            .build()),
        List.of(), List.of());

    private final String tableName;
    private final String hashKeyName;
    private final String rangeKeyName;
    private final List<AttributeDefinition> attributeDefinitions;
    private final List<GlobalSecondaryIndex> globalSecondaryIndexes;
    private final List<LocalSecondaryIndex> localSecondaryIndexes;

    Tables(
        final String tableName,
        final String hashKeyName,
        final String rangeKeyName,
        final List<AttributeDefinition> attributeDefinitions,
        final List<GlobalSecondaryIndex> globalSecondaryIndexes,
        final List<LocalSecondaryIndex> localSecondaryIndexes
    ) {
      this.tableName = tableName;
      this.hashKeyName = hashKeyName;
      this.rangeKeyName = rangeKeyName;
      this.attributeDefinitions = attributeDefinitions;
      this.globalSecondaryIndexes = globalSecondaryIndexes;
      this.localSecondaryIndexes = localSecondaryIndexes;
    }

    public String tableName() {
      return tableName;
    }

    public String hashKeyName() {
      return hashKeyName;
    }

    public String rangeKeyName() {
      return rangeKeyName;
    }

    public List<AttributeDefinition> attributeDefinitions() {
      return attributeDefinitions;
    }

    public List<GlobalSecondaryIndex> globalSecondaryIndexes() {
      return globalSecondaryIndexes;
    }

    public List<LocalSecondaryIndex> localSecondaryIndexes() {
      return localSecondaryIndexes;
    }

  }

}
