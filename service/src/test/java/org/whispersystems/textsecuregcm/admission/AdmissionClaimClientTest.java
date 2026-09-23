// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.junit.jupiter.api.*;

class AdmissionClaimClientTest {
  AdmissionProtocolFixture http;
  RegistrationOperations.AuthenticatedOperation operation;
  RegistrationOperations.VerifiedPhone phone;
  String challenge;

  @BeforeEach
  void setup() throws Exception {
    http = new AdmissionProtocolFixture();
    challenge = AdmissionTestData.id();
    operation = mock(RegistrationOperations.AuthenticatedOperation.class);
    when(operation.operationId()).thenReturn(UUID.randomUUID());
    when(operation.memberId()).thenReturn(UUID.randomUUID());
    when(operation.challengeHash())
        .thenReturn(
            HexFormat.of()
                .formatHex(
                    MessageDigest.getInstance("SHA-256")
                        .digest(challenge.getBytes(StandardCharsets.US_ASCII))));
    when(operation.registrationAttemptHash()).thenReturn(AdmissionTestData.hash(1));
    when(operation.deviceKeyCommitment()).thenReturn(AdmissionTestData.hash(2));
    when(operation.serverRequestCommitment()).thenReturn(AdmissionTestData.hash(3));
    when(operation.requestedNumber()).thenReturn("+13055550123");
    when(operation.expiresAtMillis()).thenReturn(http.clock.millis() + 300000);
    phone = mock(RegistrationOperations.VerifiedPhone.class);
    doReturn(operation.operationId()).when(phone).operationId();
    doReturn(operation.requestedNumber()).when(phone).canonicalNumber();
    when(phone.observedAtMillis()).thenReturn(http.clock.millis());
    when(phone.sessionExpiresAtMillis()).thenReturn(http.clock.millis() + 600000);
    when(phone.serverVerificationSessionHash()).thenReturn(AdmissionTestData.hash(4));
  }

  @AfterEach
  void close() {
    http.close();
  }

  AdmissionServiceClient.FreshClaim claim() {
    return http.client.claim(operation, challenge);
  }

  AdmissionPermitVerifier.VerifiedPermit attest(AdmissionServiceClient.FreshClaim claim) {
    return http.client.attest(operation, claim, phone, AdmissionTestData.hash(5), http.verifier);
  }

  @Test
  void exactClaimRetryHasStrictRequestAndNoRawPhoneOrPassword() {
    var first = claim();
    var second = claim();
    assertThat(http.claims.getFirst()).isEqualTo(http.claims.getLast());
    assertThat(http.claims.getFirst().size()).isEqualTo(6);
    assertThat(http.claims.getFirst().toString()).doesNotContain(operation.requestedNumber());
    assertThat(first.operationId()).isEqualTo(second.operationId());
    assertThat(first.approvalEpoch()).isEqualTo(7);
    assertThat(first.toString()).isEqualTo("FreshClaim[redacted]");
  }

  @Test
  void signupProofMustHaveBothCanonicalFieldsAndKeepsLegacyClaimsUnchanged() {
    assertThat(claim().signupProofId()).isNull();
    var proof = UUID.randomUUID();
    var sessionHash = AdmissionTestData.hash(6);
    http.mutateClaim = b -> { b.put("signupProofId", proof.toString()); b.put("communitySessionHash", sessionHash); };
    var verified = claim();
    assertThat(verified.signupProofId()).isEqualTo(proof);
    assertThat(verified.communitySessionHash()).isEqualTo(sessionHash);
    for (String field : List.of("signupProofId", "communitySessionHash")) {
      http.mutateClaim = b -> b.put(field, field.equals("signupProofId") ? proof.toString() : sessionHash);
      assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::claim);
    }
    for (String invalid : List.of("00000000-0000-0000-0000-000000000000", "1-1-1-1-1", proof.toString().toUpperCase())) {
      http.mutateClaim = b -> { b.put("signupProofId", invalid); b.put("communitySessionHash", sessionHash); };
      assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::claim);
    }
    http.mutateClaim = b -> { b.put("signupProofId", proof.toString()); b.put("communitySessionHash", "z".repeat(64)); };
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::claim);
  }

  @Test
  void changedClaimTupleUnknownFieldsWrongStatusAndAuthorizationAreRejected() {
    Map<String, Object> changed =
        Map.of(
            "memberId",
            UUID.randomUUID().toString(),
            "signalOperationId",
            UUID.randomUUID().toString(),
            "approvalEpoch",
            -1,
            "expiresAt",
            operation.expiresAtMillis() + 1,
            "status",
            "confirmed",
            "registrationAuthorized",
            true,
            "extra",
            1);
    changed.forEach(
        (field, value) -> {
          http.mutateClaim = b -> b.put(field, value);
          assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::claim, field);
        });
    http.mutateClaim = b -> b.remove("registrationAuthorized");
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, this::claim);
  }

  @Test
  void challengeMismatchNeverContactsAdmission() {
    assertThrows(
        AdmissionServiceClient.AdmissionServiceException.class,
        () -> http.client.claim(operation, AdmissionTestData.id()));
    assertThat(http.claims).isEmpty();
  }

  @Test
  void receiptDeadlineStartsBeforeNetworkAndNeverRenewsOnArrivalOrWallRollback() {
    http.afterClaim = () -> http.advance(3000);
    var receipt = claim();
    receipt.requireFresh();
    http.clock.incrementMillis(-10000);
    http.nanos.addAndGet(1_000_000_000L);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, receipt::requireFresh);
  }

  @Test
  void signedAttestationIsVerifiedAndExactRetryReturnsSamePermit() {
    var first = attest(claim());
    var second = attest(claim());
    assertThat(first.permitId()).isEqualTo(second.permitId());
    assertThat(first.binding().canonicalVerifiedNumber()).isEqualTo(operation.requestedNumber());
    assertThat(http.attestations.getFirst().size()).isEqualTo(9);
    assertThat(http.attestations.getFirst().toString()).doesNotContain(operation.requestedNumber());
  }

  @Test
  void responsePermitIdExpiryUnknownFieldsAndSignatureCannotOverrideSignedClaims() {
    for (var field : List.of("permitId", "expiresAt", "assertion", "extra")) {
      http.mutateAttest =
          b ->
              b.put(
                  field,
                  field.equals("expiresAt") ? http.clock.millis() + 20000 : AdmissionTestData.id());
      assertThrows(RuntimeException.class, () -> attest(claim()), field);
    }
  }

  @Test
  void changedOrStaleAuthoritativePhoneCannotBeAttested() {
    var receipt = claim();
    when(phone.canonicalNumber()).thenReturn("+13055550124");
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> attest(receipt));
    doReturn(operation.requestedNumber()).when(phone).canonicalNumber();
    when(phone.observedAtMillis()).thenReturn(http.clock.millis() - 30001);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> attest(receipt));
    when(phone.observedAtMillis()).thenReturn(http.clock.millis());
    http.advance(4000);
    assertThrows(AdmissionServiceClient.AdmissionServiceException.class, () -> attest(receipt));
    assertThat(http.attestations).isEmpty();
  }
}
