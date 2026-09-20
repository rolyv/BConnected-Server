// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage.devicecheck;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.storage.Account;

@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AppleDeviceChecksPostgresTest {
  private PGSimpleDataSource dataSource;
  private AppleDeviceChecksPostgres store;
  private ExecutorService executor;
  private Account account;
  private DCAppleDevice appleSample;

  @BeforeEach
  void setUp() throws Exception {
    final String url = System.getenv("BCONNECTED_TEST_JDBC_URL");
    if (!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) {
      throw new IllegalArgumentException("Tests require a local isolated _test database");
    }
    dataSource = new PGSimpleDataSource();
    dataSource.setURL(url);
    dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/009-apple-device-checks.sql")));
      statement.execute("TRUNCATE signal.apple_device_checks, signal.apple_device_check_public_keys");
    }
    store = new AppleDeviceChecksPostgres(dataSource, DeviceCheckManager.createObjectConverter());
    executor = Executors.newFixedThreadPool(12);
    account = account();
    // Reuse upstream's genuinely verified historical Apple fixture; do not invent attestation validity in this test.
    appleSample = DeviceCheckTestUtil.appleSampleDevice();
  }

  @AfterEach
  void tearDown() throws Exception {
    if (executor != null) {
      executor.shutdown();
      assertThat(executor.awaitTermination(20, TimeUnit.SECONDS)).isTrue();
    }
  }

  private static Account account() {
    final Account account = new Account();
    account.setAccountIdentifier(UUID.randomUUID());
    return account;
  }

  private static DCAppleDevice counter(final DCAppleDevice device, final long value) {
    return new DCAppleDeviceImpl(device.getAttestedCredentialData(), device.getAttestationStatement(), value,
        device.getAuthenticatorExtensions());
  }

  private static void assertSameAttestation(final DCAppleDevice actual, final DCAppleDevice expected) throws Exception {
    assertThat(actual.getClass()).isEqualTo(expected.getClass());
    assertThat(actual.getAttestationStatement().getClass()).isEqualTo(expected.getAttestationStatement().getClass());
    assertThat(actual.getAttestationStatement().getFormat()).isEqualTo(expected.getAttestationStatement().getFormat());
    assertThat(actual.getAttestedCredentialData().getCredentialId())
        .isEqualTo(expected.getAttestedCredentialData().getCredentialId());
    assertThat(actual.getAttestedCredentialData().getCOSEKey()).isEqualTo(expected.getAttestedCredentialData().getCOSEKey());
    assertThat(actual.getAttestedCredentialData().getAaguid()).isEqualTo(expected.getAttestedCredentialData().getAaguid());
    assertThat(actual.getAuthenticatorExtensions().getExtensions())
        .containsExactlyEntriesOf(expected.getAuthenticatorExtensions().getExtensions());
    assertThat(actual.getCounter()).isEqualTo(expected.getCounter());
    final var actualStatement = (AppleAppAttestAttestationStatement) actual.getAttestationStatement();
    final var expectedStatement = (AppleAppAttestAttestationStatement) expected.getAttestationStatement();
    assertThat(actualStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getEncoded())
        .isEqualTo(expectedStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getEncoded());
    assertThat(AppleDeviceCheckCodec.publicKey(actual).getEncoded())
        .isEqualTo(AppleDeviceCheckCodec.publicKey(expected).getEncoded());
  }

  @Test
  void preservesCredentialCertificateAndCborBytesWithTheSharedCodec() throws Exception {
    final byte[] keyId = appleSample.getAttestedCredentialData().getCredentialId();
    assertThat(store.storeAttestation(account, keyId, appleSample)).isTrue();
    assertSameAttestation(store.lookup(account, keyId).orElseThrow(), appleSample);
    final var encoded = new AppleDeviceCheckCodec(DeviceCheckManager.createObjectConverter()).encode(appleSample);
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        SELECT credential_data, attestation_statement, authenticator_extensions FROM signal.apple_device_checks
        WHERE account_id = ? AND key_id = ?
        """)) {
      statement.setObject(1, account.getAccountIdentifier());
      statement.setBytes(2, keyId);
      try (var rows = statement.executeQuery()) {
        assertThat(rows.next()).isTrue();
        assertThat(rows.getBytes(1)).isEqualTo(encoded.credentialData());
        assertThat(rows.getBytes(2)).isEqualTo(encoded.statement());
        assertThat(rows.getBytes(3)).isEqualTo(encoded.extensions());
      }
    }
  }

  @Test
  void keyIdsAreAccountScopedAndDoNotRequireOneIdPerPublicKeyAtTheStorageLayer() throws Exception {
    // Upstream validates the key-ID binding before storage; its repository permits these aliases within one account.
    final List<byte[]> ids = IntStream.range(0, 10).mapToObj(i -> new byte[] {0, (byte) i, (byte) 0xff}).toList();
    for (final byte[] id : ids) assertThat(store.storeAttestation(account, id, appleSample)).isTrue();
    assertThat(store.keyIds(account)).containsExactlyInAnyOrderElementsOf(ids);
    final Account other = account();
    assertThat(store.keyIds(other)).isEmpty();
    assertThat(store.lookup(other, ids.getFirst())).isEmpty();
    assertThat(store.lookup(account, new byte[] {9, 9})).isEmpty();
  }

  @Test
  void counterUpdatesAllowEqualityRejectDecreasesAndDoNotCreateMissingKeys() throws Exception {
    final byte[] keyId = appleSample.getAttestedCredentialData().getCredentialId();
    assertThat(store.updateCounter(account, keyId, 1)).isFalse();
    assertThat(store.storeAttestation(account, keyId, appleSample)).isTrue();
    assertThat(store.updateCounter(account, keyId, 0)).isTrue();
    assertThat(store.updateCounter(account, keyId, 2)).isTrue();
    assertThat(store.updateCounter(account, keyId, 2)).isTrue();
    assertThat(store.updateCounter(account, keyId, 1)).isFalse();
    assertThat(store.updateCounter(account(), keyId, 99)).isFalse();
    assertThat(store.lookup(account, keyId).orElseThrow().getCounter()).isEqualTo(2);
  }

  @Test
  void attestationReplacementAllowsEqualCountersAndRetainsHistoricalPublicKeyOwnership() throws Exception {
    final byte[] keyId = appleSample.getAttestedCredentialData().getCredentialId();
    assertThat(store.storeAttestation(account, keyId, counter(appleSample, 7))).isTrue();
    final DCAppleDevice otherFixture = DeviceCheckTestUtil.sampleDevice();
    assertThat(store.storeAttestation(account, keyId, counter(otherFixture, 6))).isFalse();
    assertSameAttestation(store.lookup(account, keyId).orElseThrow(), counter(appleSample, 7));
    assertThat(store.storeAttestation(account, keyId, counter(otherFixture, 7))).isTrue();
    assertSameAttestation(store.lookup(account, keyId).orElseThrow(), counter(otherFixture, 7));
    assertThat(store.storeAttestation(account, keyId, counter(otherFixture, 8))).isTrue();
    assertThat(store.lookup(account, keyId).orElseThrow().getCounter()).isEqualTo(8);
    assertThrows(DuplicatePublicKeyException.class, () -> store.storeAttestation(account(), keyId, appleSample));
  }

  @Test
  void duplicatePublicKeysRollBackNewRowsAndUpdatesToExistingRows() throws Exception {
    final byte[] firstId = appleSample.getAttestedCredentialData().getCredentialId();
    store.storeAttestation(account, firstId, appleSample);
    final Account other = account();
    assertThrows(DuplicatePublicKeyException.class, () -> store.storeAttestation(other, firstId, appleSample));
    assertThat(store.lookup(other, firstId)).isEmpty();
    assertThat(store.keyIds(other)).isEmpty();

    final DCAppleDevice otherFixture = DeviceCheckTestUtil.sampleDevice();
    final byte[] secondId = otherFixture.getAttestedCredentialData().getCredentialId();
    store.storeAttestation(other, secondId, otherFixture);
    assertThrows(DuplicatePublicKeyException.class,
        () -> store.storeAttestation(other, secondId, counter(appleSample, 5)));
    assertSameAttestation(store.lookup(other, secondId).orElseThrow(), otherFixture);
    assertSameAttestation(store.lookup(account, firstId).orElseThrow(), appleSample);
  }

  @Test
  void staleAttestationTakesPrecedenceOverAnUnrelatedPublicKeyConflict() throws Exception {
    final byte[] id = appleSample.getAttestedCredentialData().getCredentialId();
    store.storeAttestation(account, id, counter(appleSample, 10));
    final DCAppleDevice otherFixture = DeviceCheckTestUtil.sampleDevice();
    store.storeAttestation(account(), otherFixture.getAttestedCredentialData().getCredentialId(), otherFixture);
    // Both upstream conditions would fail: the lower counter wins and returns false, without a duplicate exception.
    assertThat(store.storeAttestation(account, id, counter(otherFixture, 9))).isFalse();
    assertSameAttestation(store.lookup(account, id).orElseThrow(), counter(appleSample, 10));
  }

  @Test
  void competingAccountsCannotClaimTheSamePublicKeyAcrossStoreInstances() {
    final byte[] id = appleSample.getAttestedCredentialData().getCredentialId();
    final var otherStore = new AppleDeviceChecksPostgres(dataSource, DeviceCheckManager.createObjectConverter());
    final List<Account> contenders = IntStream.range(0, 24).mapToObj(i -> account()).toList();
    final var attempts = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 0; i < contenders.size(); i++) {
      final Account contender = contenders.get(i);
      final AppleDeviceChecksPostgres selected = i % 2 == 0 ? store : otherStore;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        try { return selected.storeAttestation(contender, id, appleSample); }
        catch (DuplicatePublicKeyException e) { return false; }
      }, executor));
    }
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    assertThat(contenders.stream().filter(a -> store.lookup(a, id).isPresent()).count()).isEqualTo(1);
  }

  @Test
  void racingAttestationsAndAssertionsNeverDecreaseTheCounter() throws Exception {
    final byte[] id = appleSample.getAttestedCredentialData().getCredentialId();
    store.storeAttestation(account, id, appleSample);
    final var otherStore = new AppleDeviceChecksPostgres(dataSource, DeviceCheckManager.createObjectConverter());
    final var attempts = new ArrayList<CompletableFuture<Boolean>>();
    for (int i = 1; i <= 80; i++) {
      final int count = i;
      attempts.add(CompletableFuture.supplyAsync(() -> {
        if (count % 2 == 0) return otherStore.updateCounter(account, id, count);
        try { return store.storeAttestation(account, id, counter(appleSample, count)); }
        catch (DuplicatePublicKeyException e) { throw new AssertionError(e); }
      }, executor));
    }
    attempts.forEach(CompletableFuture::join);
    assertThat(store.lookup(account, id).orElseThrow().getCounter()).isEqualTo(80);
    assertThat(store.updateCounter(account, id, 79)).isFalse();
    assertThat(store.updateCounter(account, id, 80)).isTrue();
  }

  @Test
  void malformedStoredAttestationFailsClosedWithoutLosingItsOwnership() throws Exception {
    final byte[] id = appleSample.getAttestedCredentialData().getCredentialId();
    store.storeAttestation(account, id, appleSample);
    try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
        UPDATE signal.apple_device_checks SET attestation_statement = ? WHERE account_id = ? AND key_id = ?
        """)) {
      statement.setBytes(1, new byte[] {(byte) 0xff});
      statement.setObject(2, account.getAccountIdentifier());
      statement.setBytes(3, id);
      assertThat(statement.executeUpdate()).isEqualTo(1);
    }
    assertThrows(RuntimeException.class, () -> store.lookup(account, id));
    assertThat(store.keyIds(account)).containsExactly(id);
    assertThrows(DuplicatePublicKeyException.class, () -> store.storeAttestation(account(), id, appleSample));
  }
}
