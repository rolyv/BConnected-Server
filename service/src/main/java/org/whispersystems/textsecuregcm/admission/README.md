# Admission source prerequisite

This package is not wired into registration or account authentication. It does not enable an enrollment route, activate an account, or enforce ongoing alumni entitlement. Migration `bconnected/migrations/012-admission.sql` is source-only; the local tests apply it to an isolated database.

`AdmissionPermitVerifier` accepts only pinned Ed25519 keys and the exact `bconnected-admission-v1` JWS header/claims. It rejects duplicate or unknown JSON fields, noncanonical base64url/UUID/hash encodings, wrong issuer/audience/type, unsupported keys/algorithms and changed operation bindings. Only successful verification can construct `VerifiedPermit`. `ExpectedBinding` must come from an immutable, persisted Signal operation and its authoritative verified-phone session, never an HTTP DTO. The transient verified E.164 is not an assertion claim and is checked against the inserted account.

Signed lifetime is at most 30 seconds. `iat` may be at most five seconds ahead of the verifier, so the verifier can observe up to 35 seconds remaining under permitted clock skew. Exact expiry is rejected. The issuer never refreshes expiry or permit ID on a retry.

`RegistrationRequestCommitment` computes a Signal-only HMAC over the domain `bconnected.registration-request.v1` plus NUL, then two unsigned 32-bit big-endian length-framed inputs: a complete canonical validated registration request and its salted authentication-verifier binding. The helper does not yet define the canonical request encoder, create/persist server operations, or bind an actual controller request. The key must be a new owned secret; raw passwords must not be copied into admission state.

`AdmissionLedger.pendingMutation` participates in the existing `AccountMutation.Sql` account transaction. It requires an existing account row with the verified phone, inserts the unique permit/member/ACI/operation/session association as `PENDING`, and inserts confirmation-outbox work atomically. It checks expiry after account locking, after the potentially blocked unique insertion, and after the outbox write. The future coordinator should order this after account/key writes. Errors roll back the account, keys, redemption and outbox. There is no standalone redemption or activation API. Spent associations intentionally survive account deletion; re-registration and reassociation require a separate explicit lifecycle design.

Before this can be used, integration must supply the canonical full-request encoder and validated public-key transcript, persist the server-owned operation before SMS, verify authoritative phone/session binding, handle exact retries, and implement authenticated confirmation. Every account capability and transport must deny absent/PENDING/SUSPENDED admission and enforce current approval epoch; established connections must honor revocation. The ledger alone does not block existing account authentication. None of these runtime gates is implemented by this package.

## Evidence

On 2026-09-20, the focused run passed **44 tests with zero failures/errors/skips**: 11 verifier/HMAC tests (including a public Node-issued interoperability fixture), 11 native PostgreSQL ledger tests, and 22 existing `AccountsPostgresTest` regressions. Ledger coverage includes real signed-key/account transaction rollback, outbox failure, concurrent redemption, changed bindings, retained spent permits, exact expiry and a blocked unique insertion that resumes after expiry when the competitor rolls back. The root workspace evidence is `.local/signal-admission-tests.log`.

Run from the Signal-Server repository using JDK 26 and the isolated loopback fixture:

```sh
BCONNECTED_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/bconnected_test \
BCONNECTED_TEST_POSTGRES_PASSWORD=bconnected-local-test \
./mvnw -B -ntp -pl service -am \
  -Dtest=AdmissionPermitVerifierTest,AdmissionLedgerPostgresTest,AccountsPostgresTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

The tests refuse non-loopback/non-`_test` JDBC URLs. They truncate their Signal test tables; use a dedicated fixture. No libsignal cryptography or production runtime configuration is changed.
