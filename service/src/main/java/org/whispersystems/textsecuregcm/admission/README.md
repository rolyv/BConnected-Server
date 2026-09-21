# Admission integration components

This package is not wired into registration or account authentication. It does not enable an enrollment route, activate an account, or enforce ongoing alumni entitlement. Native PostgreSQL migrations `bconnected/migrations/012-admission.sql` and `013-registration-operations.sql` define its ledger, confirmation outbox and immutable registration operations. Migration application and deployed privilege checks are tracked by the root workspace's infrastructure evidence; their presence does not establish runtime integration.

`AdmissionPermitVerifier` accepts only pinned Ed25519 keys and the exact `bconnected-admission-v1` JWS header/claims. It rejects duplicate or unknown JSON fields, noncanonical base64url/UUID/hash encodings, wrong issuer/audience/type, unsupported keys/algorithms and changed operation bindings. Only successful verification can construct `VerifiedPermit`. `ExpectedBinding` must come from an immutable, persisted Signal operation and its authoritative verified-phone session, never an HTTP DTO. The transient verified E.164 is not an assertion claim and is checked against the inserted account.

Signed lifetime is at most 30 seconds. `iat` may be at most five seconds ahead of the verifier, so the verifier can observe up to 35 seconds remaining under permitted clock skew. Exact expiry is rejected. The issuer never refreshes expiry or permit ID on a retry.

`RegistrationKeyCommitment` validates and hashes the exact public registration-key transcript, including existing libsignal signature checks. The matching Swift helper and this Java helper use the same 3,662-byte public fixture. Connecting the Swift helper to the exact material ultimately serialized by the iPhone registration flow remains pending.

`CanonicalRegistrationRequest` snapshots and validates the complete supported phone-registration request, including account/device attributes, capabilities, identity and signed prekeys, transfer choice, push credentials and client metadata. Mutable input arrays are copied; closing the snapshot clears its canonical byte buffer. Unsupported recovery, numberless and client-selected verification-session paths fail closed. `RegistrationRequestCommitment` computes a Signal-only HMAC over the domain `bconnected.registration-request.v1` plus NUL, then two unsigned 32-bit big-endian length-framed inputs: this canonical request and its salted authentication-verifier binding. Its key must be a new owned Signal-only secret. Raw passwords and canonical request bytes are not persisted in admission state.

`RegistrationOperations` persists a server-generated operation ID with immutable member/attempt, challenge, key/request commitments, requested phone and the existing salted Signal authentication verifier. Exact retries must authenticate the original verifier and match all bindings; they do not renew the operation's five-minute lifetime. Initial requests for an existing account are rejected as unsupported recovery. The future approved-claim coordinator must create the verification session itself before using the package-private association method. Association and verified-phone reads check the authoritative SQL session's phone, state and expiry. Preparing an operation alone neither proves membership nor sends SMS.

`AdmissionLedger.pendingMutation` participates in the existing `AccountMutation.Sql` account transaction. It requires an existing account row with the verified phone, inserts the unique permit/member/ACI/operation/session association as `PENDING`, and inserts confirmation-outbox work atomically. It checks expiry after account locking, after the potentially blocked unique insertion, and after the outbox write. The future coordinator should order this after account/key writes. Errors roll back the account, keys, redemption and outbox. There is no standalone redemption or activation API. Spent associations intentionally survive account deletion; re-registration and reassociation require a separate explicit lifecycle design.

## Private confirmation and entitlement client

`AdmissionServiceClient` implements only the private confirmation and current-entitlement HTTP calls. Configuration pins the exact origin `https://bconnected-admission-mk5xfhz7jq-ue.a.run.app`. Google application-default credentials must support audience-bound ID tokens; the client requests full-format metadata tokens and included email for impersonated tokens. It checks the expected audience, Signal service-account email and token expiry before use. There is no access-token fallback. Token acquisition uses a bounded executor and shares the request deadline; redirects, cookies, automatic application retries, compressed responses and responses over 8 KiB are rejected.

Every request includes a fresh random nonce and the exact member/approval-epoch/operation/permit/ACI tuple. Strict response parsing rejects malformed UTF-8, duplicate, unknown or missing fields, changed bindings, nonce replay and invalid timestamps. These responses are HTTPS/IAM service receipts, not signed assertions; only the permit is a signed JWS.

Opaque receipts expire no later than four seconds from the monotonic request start, before credential acquisition. Network or credential latency consumes that budget. Absolute issuer expiry and a shorter issuer TTL can only reduce it. Callers must invoke `requireFresh()` again at the actual use boundary, **after** local queue or lock waits, and require the correct local ledger state. Pending-account confirmation must use `requireFreshConfirmation()`: an otherwise fresh current-entitlement receipt cannot substitute for confirmation. Neither receipt mutates or activates an account. Sensitive binding and receipt objects have redacted `toString()` methods; transport failures do not expose response bodies, tokens or provider exception causes.

## Remaining runtime work

The coordinator still needs to connect the tested components to the actual registration request, claim approved intent before provider calls, attach its own fresh verification session, attest authoritative phone verification and consume the signed permit in the account/key transaction. Claim, attestation and revocation HTTP methods are not implemented by this client. Confirmation retries and local activation must be coordinated with the persisted outbox, immutable receipt tuple and freshness checks.

Every account capability and transport must deny absent/PENDING/SUSPENDED admission and require current approval epoch; established connections must honor revocation. An entitlement receipt alone cannot establish local ACTIVE state. These runtime gates are not implemented by this package, and the ledger alone does not block existing account authentication. No libsignal cryptography is changed.

## Evidence

The following 2026-09-20 checkpoints passed with zero failures/errors/skips. Totals overlap and must not be added as distinct coverage:

- **44 tests**: verifier/HMAC, Node-issued public interoperability fixture, native PostgreSQL ledger and account regressions. Ledger cases include account/key rollback, outbox failure, concurrent redemption, retained spent permits and an insertion that resumes after expiry when a competing transaction rolls back. Root evidence: `.local/signal-admission-tests.log`.
- **52 tests**: Java key transcript helper and existing registration-request tests. The matching Swift helper separately passed **nine native tests**; neither result establishes the mobile registration handshake.
- **66 tests**: canonical request/authentication and native operation tests plus key, permit, ledger, salted-token and runtime-configuration regressions. Cases include changed request fields, exact password retries, concurrent creation, immutable session association, authoritative phone expiry and recovery rejection. Root evidence: `.local/signal-registration-operation-tests.log`.
- **87 tests** in the final combined client/monitor run: 19 client/credential tests, 11 existing permit tests and 57 monitor/configuration regressions. Client coverage includes strict binding/JSON parsing, nonce replay, full-format credential options, identity pinning, response bounds, timeout cancellation, freshness after delayed credentials/HTTP/lock waits, and confirmation-purpose separation. Root evidence: `.local/signal-admission-http-client-tests.log`.

Run from the Signal-Server repository using JDK 26 and the isolated loopback fixture:

```sh
BCONNECTED_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/bconnected_test \
BCONNECTED_TEST_POSTGRES_PASSWORD=bconnected-local-test \
./mvnw -B -ntp -pl service -am \
  -Dtest=AdmissionPermitVerifierTest,AdmissionLedgerPostgresTest,RegistrationKeyCommitmentTest,CanonicalRegistrationRequestTest,RegistrationOperationsPostgresTest,AccountsPostgresTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

The PostgreSQL tests refuse non-loopback/non-`_test` JDBC URLs. They truncate their Signal test tables; use a dedicated fixture. The HTTP/credential suite requires no PostgreSQL fixture or live credentials:

```sh
./mvnw -B -ntp -pl service -am \
  -Dtest=AdmissionServiceClientTest,AdmissionServiceCredentialsTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```
