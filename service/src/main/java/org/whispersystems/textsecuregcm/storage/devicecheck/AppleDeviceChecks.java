/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage.devicecheck;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.converter.util.ObjectConverter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/**
 * Store DeviceCheck attestations along with accounts, so they can be retrieved later to validate assertions.
 * <p>
 * Callers associate a keyId and attestation with an account, and then use the corresponding key to make potentially
 * many attested requests (assertions). Each assertion increments the counter associated with the key.
 * <p>
 * Callers can associate more than one keyId/attestation with an account (for example, they may get a new device).
 * However, each keyId must only be registered for a single account.
 *
 * @implNote We use a second table keyed on the public key to enforce uniqueness.
 */
public class AppleDeviceChecks implements AppleDeviceCheckStore {

  // B: uuid, primary key
  public static final String KEY_ACCOUNT_UUID = "U";
  // B: key id, sort key. The key id is the SHA256 of the X9.62 uncompressed point format of the public key
  public static final String KEY_PUBLIC_KEY_ID = "KID";
  // N: counter, the number of asserts signed by the public key (updates on every assert)
  private static final String ATTR_COUNTER = "C";
  // B: attestedCredentialData
  private static final String ATTR_CRED_DATA = "CD";
  // B: attestationStatement, CBOR
  private static final String ATTR_STATEMENT = "S";
  // B: authenticatorExtensions, CBOR
  private static final String ATTR_AUTHENTICATOR_EXTENSIONS = "AE";

  // B: public key bytes, primary key for the public key table
  public static final String KEY_PUBLIC_KEY = "PK";

  private static final String CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailed";

  private final DynamoDbClient dynamoDbClient;
  private final String deviceCheckTableName;
  private final String publicKeyConstraintTableName;
  private final AppleDeviceCheckCodec codec;

  public AppleDeviceChecks(
      final DynamoDbClient dynamoDbClient,
      final ObjectConverter objectConverter,
      final String deviceCheckTableName,
      final String publicKeyConstraintTableName) {
    this.dynamoDbClient = dynamoDbClient;
    this.codec = new AppleDeviceCheckCodec(objectConverter);
    this.deviceCheckTableName = deviceCheckTableName;
    this.publicKeyConstraintTableName = publicKeyConstraintTableName;
  }

  /**
   * Retrieve DeviceCheck keyIds
   *
   * @param account The account to fetch keyIds for
   * @return A list of keyIds currently associated with the account
   */
  public List<byte[]> keyIds(final Account account) {
    return dynamoDbClient.queryPaginator(QueryRequest.builder()
            .tableName(deviceCheckTableName)
            .keyConditionExpression("#aci = :aci")
            .expressionAttributeNames(Map.of("#aci", KEY_ACCOUNT_UUID, "#kid", KEY_PUBLIC_KEY_ID))
            .expressionAttributeValues(Map.of(":aci", AttributeValues.fromUUID(account.getAccountIdentifier())))
            .projectionExpression("#kid")
            .build())
        .items()
        .stream()
        .flatMap(item -> getByteArray(item, KEY_PUBLIC_KEY_ID).stream())
        .toList();
  }

  /**
   * Register an attestation for a keyId with an account. The attestation can later be retrieved via {@link #lookup}. If
   * the provided keyId is already registered with the account and is more up to date, no update will occur and this
   * method will return false.
   *
   * @param account     The account to store the registration
   * @param keyId       The keyId to associate with the account
   * @param appleDevice Attestation information to store
   * @return true if the attestation was stored, false if the keyId already had an attestation
   * @throws DuplicatePublicKeyException If a different account has already registered this public key
   */
  public boolean storeAttestation(final Account account, final byte[] keyId, final DCAppleDevice appleDevice)
      throws DuplicatePublicKeyException {
    try {
      dynamoDbClient.transactWriteItems(TransactWriteItemsRequest.builder().transactItems(

          // Register the public key and associated data with the account
          TransactWriteItem.builder().put(Put.builder()
              .tableName(deviceCheckTableName)
              .item(toItem(account, keyId, appleDevice))
              // The caller should have done a non-transactional read to verify we didn't already have this keyId, but a
              // race is possible. It's fine to wipe out an existing key (should be identical), as long as we don't
              // lower the signed count associated with the key.
              .conditionExpression("attribute_not_exists(#counter) OR #counter <= :counter")
              .expressionAttributeNames(Map.of("#counter", ATTR_COUNTER))
              .expressionAttributeValues(Map.of(":counter", AttributeValues.n(appleDevice.getCounter())))
              .build()).build(),

          // Enforce uniqueness on the supplied public key
          TransactWriteItem.builder().put(Put.builder()
              .tableName(publicKeyConstraintTableName)
              .item(Map.of(
                  KEY_PUBLIC_KEY, AttributeValues.fromByteArray(AppleDeviceCheckCodec.publicKey(appleDevice).getEncoded()),
                  KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getAccountIdentifier())
              ))
              // Enforces public key uniqueness, as described in https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Store-the-public-key-and-receipt
              .conditionExpression("attribute_not_exists(#pk) or #aci = :aci")
              .expressionAttributeNames(Map.of("#aci", KEY_ACCOUNT_UUID, "#pk", KEY_PUBLIC_KEY))
              .expressionAttributeValues(Map.of(":aci", AttributeValues.fromUUID(account.getAccountIdentifier())))
              .build()).build()).build());
      return true;

    } catch (TransactionCanceledException e) {
      final CancellationReason updateCancelReason = e.cancellationReasons().get(0);
      if (conditionalCheckFailed(updateCancelReason)) {
        // The provided attestation is older than the one we already have stored
        return false;
      }
      final CancellationReason publicKeyCancelReason = e.cancellationReasons().get(1);
      if (conditionalCheckFailed(publicKeyCancelReason)) {
        throw new DuplicatePublicKeyException();
      }
      throw e;
    }
  }

  /**
   * Retrieve the device attestation information previous registered with the account
   *
   * @param account The account that registered the keyId
   * @param keyId   The keyId that was registered
   * @return Device attestation information that can be used to validate an assertion
   */
  public Optional<DCAppleDevice> lookup(final Account account, final byte[] keyId) {
    final GetItemResponse item = dynamoDbClient.getItem(GetItemRequest.builder()
        .tableName(deviceCheckTableName)
        .key(Map.of(
            KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getAccountIdentifier()),
            KEY_PUBLIC_KEY_ID, AttributeValues.fromByteArray(keyId))).build());
    return item.hasItem() ? Optional.of(fromItem(item.item())) : Optional.empty();
  }

  /**
   * Attempt to increase the signed counter to the newCounter value. This method enforces that the counter increases
   * monotonically, if the new value is less than the existing counter, no update occurs and the method returns false.
   *
   * @param account    The account the keyId is registered to
   * @param keyId      The keyId to update
   * @param newCounter The new counter value
   * @return true if the counter was updated, false if the stored counter was larger than newCounter
   */
  public boolean updateCounter(final Account account, final byte[] keyId, final long newCounter) {
    try {
      dynamoDbClient.updateItem(UpdateItemRequest.builder()
          .tableName(deviceCheckTableName)
          .key(Map.of(
              KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getAccountIdentifier()),
              KEY_PUBLIC_KEY_ID, AttributeValues.fromByteArray(keyId)))
          .expressionAttributeNames(Map.of("#counter", ATTR_COUNTER))
          .expressionAttributeValues(Map.of(":counter", AttributeValues.n(newCounter)))
          .updateExpression("SET #counter = :counter")
          // someone could possibly race with us to update the counter. No big deal, but we shouldn't decrease the
          // current counter
          .conditionExpression("#counter <= :counter").build());
      return true;
    } catch (ConditionalCheckFailedException e) {
      // We failed to increment the counter because it has already moved forward
      return false;
    }
  }

  private Map<String, AttributeValue> toItem(final Account account, final byte[] keyId, DCAppleDevice appleDevice) {
    final AppleDeviceCheckCodec.Encoded encoded = codec.encode(appleDevice);
    return Map.of(
        KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getAccountIdentifier()),
        KEY_PUBLIC_KEY_ID, AttributeValues.fromByteArray(keyId),
        ATTR_CRED_DATA, AttributeValues.fromByteArray(encoded.credentialData()),
        ATTR_STATEMENT, AttributeValues.fromByteArray(encoded.statement()),
        ATTR_AUTHENTICATOR_EXTENSIONS, AttributeValues.fromByteArray(encoded.extensions()),
        ATTR_COUNTER, AttributeValues.n(encoded.counter()));
  }

  private DCAppleDevice fromItem(final Map<String, AttributeValue> item) {
    return codec.decode(
        getByteArray(item, ATTR_CRED_DATA)
            .orElseThrow(() -> new IllegalStateException("Stored device check key missing attestation credential data")),
        getByteArray(item, ATTR_STATEMENT)
            .orElseThrow(() -> new IllegalStateException("Stored device check key missing attestation statement")),
        getByteArray(item, ATTR_AUTHENTICATOR_EXTENSIONS)
            .orElseThrow(() -> new IllegalStateException("Stored device check key missing attestation extensions")),
        AttributeValues.getLong(item, ATTR_COUNTER, 0));
  }


  private static boolean conditionalCheckFailed(final CancellationReason reason) {
    return CONDITIONAL_CHECK_FAILED.equals(reason.code());
  }

  private static Optional<byte[]> getByteArray(Map<String, AttributeValue> item, String key) {
    return AttributeValues.get(item, key).map(av -> av.b().asByteArray());
  }

}
