# PostgreSQL persistence for BConnected

This fork implements native PostgreSQL storage for the pilot's account, key, message, profile, registration-support, reporting, challenge, Apple DeviceCheck and client-release paths. Selecting the optional `postgres` configuration uses those implementations in the server and worker dependency factories. Omitting it preserves the legacy backend.

**The Signal messaging server is not deployed.** PostgreSQL selection does not yet remove every DynamoDB/S3 client or the other upstream startup dependencies. Local storage tests and schema provisioning do not demonstrate working phone registration or encrypted messaging between devices.

## Accounts and their transaction boundary

`AccountStore` separates account persistence from DynamoDB. `AccountsPostgres` implements phone-account creation, versioned updates, re-registration, number changes, deletion, username reservation/confirmation/holds, username links, recently-deleted identities and device-link replay markers. Number and PNI uniqueness are enforced independently. Reads restore canonical identity/version fields from SQL columns, and account scans use bounded keyset pages.

`AccountMutation` has explicit SQL and DynamoDB variants. The selected account store executes related mutations on its own connection before committing; mixed backends are rejected. `SignedPreKeysPostgres` preserves libsignal EC/KEM public-key and signature encodings. `PhoneNumberRecoveryPasswordsPostgres` stores salted recovery hashes. Together they keep these write sets atomic:

- Account creation and initial ACI/PNI signed EC and KEM last-resort keys, including a recovery-password mutation when provided.
- Device linking/removal, signed-key changes and the device-link token's single-use marker.
- Account replacement, phone-number changes and deletion with their supplied key/recovery mutations.

A rejected key mutation or replayed device-link token rolls back the account/version change. Native account operations update caller objects only after successful commits. Username expiration keeps the upstream strict epoch-second boundary, and ordinary updates cannot bypass the explicit phone-identity change path.

The broader re-registration flow also clears one-time keys, messages and profiles before and after account replacement. Those cleanup steps retain their upstream ordering; they are not part of the account SQL transaction. **Paid/receipt-based numberless creation is explicitly unsupported by the PostgreSQL pilot.** Its receipt-redemption transaction must be implemented before enabling that feature.

`AccountLockManager` uses PostgreSQL advisory locks for the selected backend, including PNI locks before an account exists. It orders multiple lock keys, preserves synchronous nested lock scopes and releases locks after callback success or failure. These lifecycle locks use a **dedicated connection pool**: the callback can perform data operations while retaining its lock connection. Sharing the data pool would allow pool starvation/deadlock. Nested lock acquisition does not rerun callbacks after side effects.

## Other implemented storage

`MessagesPostgres` stores serialized encrypted envelopes, preserving account/device-generation isolation, atomic batches, duplicate-key behavior, ordered keyset pagination and acknowledgement through `DELETE ... RETURNING`. Reads exclude expired envelopes; a bounded worker physically removes them later. The storage layer never decrypts message contents or changes Signal cryptography. Routing identifiers and queue timestamps remain database-visible metadata.

`RemoteConfigsPostgres` preserves percentages, UUID enrollment and nullable configuration fields. `remote-config.json` remains an input specification; it is not automatically imported.

`SingleUseECPreKeysPostgres` and `SingleUseKEMPreKeysPostgres` preserve the original public-key encodings and KEM signatures. Their transactions coordinate bulk replacement, consumption and account/device deletion across store instances. Invalid writes roll back complete batches; malformed stored keys fail without consuming them. KEM exhaustion falls back to the repeated-use signed KEM store through `KeysManager`. The native one-time KEM path creates no S3 client and skips orphan-page pruning.

`ProfilesPostgres` commits both encrypted profile formats together, preserving commitments and optimistic data-hash checks. `ProfileAvatarsPostgres` stores ownership/expiry metadata; avatar bytes still require the separate object-storage integration.

`VerificationSessionsPostgres`, `PhoneNumberIdentifiersPostgres` and `ChangeNumberWaitingPeriodsPostgres` cover verification state, stable phone-to-PNI mappings and registration/number-change bookkeeping. Equivalent phone forms are locked in a deterministic order without overwriting established mappings. The external registration service and SMS provider are separate work.

`ReportMessagePostgres` and `PushChallengePostgres` preserve the upstream consumption and expiry rules. `AppleDeviceChecksPostgres` shares the existing certificate/CBOR codec and preserves global public-key ownership, equal-or-increasing assertion counters and atomic rollback when a public key belongs to another account. This is an attestation storage port, not configuration of Apple credentials or a deployed attestation test.

`ClientReleasesPostgres` reads operator-maintained client-release metadata used for metrics labels. Malformed rows are skipped; database failures propagate so the manager retains its last successful snapshot. The runtime requires SELECT only on `client_releases`.

## Runtime selection

In PostgreSQL mode, the server and worker factories skip FoundationDB initialization. Message-manager experiments cannot select an absent FoundationDB store, and FoundationDB-only maintenance operations fail explicitly. Redis remains required for the message cache, availability notifications and coordination; durable PostgreSQL queues do not replace those responsibilities.

The `type: file` monitored-object implementation can load dynamic configuration without S3. Configure its `path`, optional `maxSize` and optional `refreshInterval`, and provide the file in the deployed process. The default maximum is 16 MiB and the refresh interval is five minutes. This removes S3 reads for selected monitored objects; it does not remove all AWS-backed bootstrap components.

## Schema and cloud connection

Apply all ten migrations with a migration identity before starting the selected backend:

1. [001-postgres.sql](migrations/001-postgres.sql): encrypted envelopes and remote configuration.
2. [002-ec-prekeys.sql](migrations/002-ec-prekeys.sql): one-time EC keys.
3. [003-accounts.sql](migrations/003-accounts.sql): `accounts`, `usernames`, `deleted_accounts`, `used_link_tokens`, `signed_prekeys` and `phone_recovery_passwords`.
4. [004-registration.sql](migrations/004-registration.sql): verification sessions, stable phone identities and waiting periods.
5. [005-kem-prekeys.sql](migrations/005-kem-prekeys.sql): one-time KEM keys.
6. [006-profiles.sql](migrations/006-profiles.sql): both profile formats and avatar metadata.
7. [007-report-message.sql](migrations/007-report-message.sql): message-report records.
8. [008-push-challenges.sql](migrations/008-push-challenges.sql): push-challenge records.
9. [009-apple-device-checks.sql](migrations/009-apple-device-checks.sql): attestation records and global public-key ownership.
10. [010-client-releases.sql](migrations/010-client-releases.sql): operator-maintained client-release metadata.

These define **21 application tables**, excluding the migration ledger. Migration 003 adds six account-related tables. The root BConnected repository's `services/community/scripts/migrate-signal.mjs` applies reviewed migrations with checksums and explicit grants. The server does not change schemas at startup.

The 2026-09-20 [cloud evidence](https://github.com/rolyv/BConnected/blob/codex/bconnected-pilot/infra/signal-deployment.json) records all ten migrations applied, all 21 application tables empty, and 81 table grants: SELECT/INSERT/UPDATE/DELETE on 20 tables and SELECT only on `client_releases`. Private Cloud Run execution `bconnected-signal-db-check-8vr9v` passed IAM login and the 21-table probe at `2026-09-20T22:08:13.227303Z`; its synthetic writes were rolled back. Schema isolation and denial of runtime schema creation passed. The probe did not run the Java server or deploy messaging.

The pilot database target is Cloud SQL PostgreSQL 17 at `roly-dev:us-east1:bconnected-postgres`, database `bconnected`. The messaging IAM database username is `bconnected-signal@roly-dev.iam`, separate from the community API identity. Grant schema usage and the table privileges above; the runtime does not need schema-creation or community-schema privileges. Cloud SQL IAM grants are restricted to this instance, and runtime authentication uses no stored database password.

Run Cloud SQL Auth Proxy v2 beside the server with the messaging service account's credentials and a trusted loopback listener:

```sh
cloud-sql-proxy --auto-iam-authn --address=127.0.0.1 --port=5432 \
  roly-dev:us-east1:bconnected-postgres
```

Add this top-level YAML block after applying the schema and grants:

```yaml
postgres:
  jdbcUrl: "jdbc:postgresql://127.0.0.1:5432/bconnected?sslmode=disable"
  username: "bconnected-signal@roly-dev.iam"
  maximumPoolSize: 5
```

The proxy's IAM identity must match the database user. It secures the Cloud SQL connection and supplies short-lived authentication credentials; `sslmode=disable` applies only to the local application-to-proxy connection. Do not use that URL pattern for a direct remote database connection. See [Google's automatic IAM login procedure](https://docs.cloud.google.com/sql/docs/postgres/iam-logins).

For a local password-authenticated fixture, set `passwordEnvironmentVariable` to the name of a variable containing the password. Never put the value in YAML. Omit that field for automatic IAM authentication; a configured but missing/blank password variable fails startup.

`maximumPoolSize` defaults to five and accepts 1–30. **Both** the data pool and separate lifecycle-lock pool use that maximum, so budget up to twice the configured value per server/worker process. The lifecycle closes both pools. Bounded expiry maintenance runs every 60 seconds; delayed cleanup remains possible during backlog, downtime or failures.

## Local validation

From this checkout's root, use JDK 26 and an isolated PostgreSQL 17 fixture. Reuse the container if it is already running, and wait until `pg_isready` reports readiness:

```sh
docker run --rm --detach --name bconnected-postgres-test \
  --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_PASSWORD=bconnected-local-test \
  --env POSTGRES_DB=bconnected_test postgres:17
docker exec bconnected-postgres-test pg_isready -U postgres -d bconnected_test

BCONNECTED_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/bconnected_test \
BCONNECTED_TEST_POSTGRES_PASSWORD=bconnected-local-test \
./mvnw -B -ntp -pl service -am \
  -Dtest=AccountsPostgresTest,SignedPreKeysAndRecoveryPostgresTest,AccountLockManagerPostgresTest,ReportMessagePostgresTest,PushChallengePostgresTest,AppleDeviceChecksPostgresTest,ClientReleasesPostgresTest,ClientReleaseManagerTest,MessagesManagerPostgresModeTest,FileObjectMonitorTest,DynamicConfigurationManagerTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

Set `JAVA_HOME` to JDK 26 if needed. The credential above is a disposable local fixture. PostgreSQL tests require loopback and a database name ending in `_test`; they apply migrations and truncate their tables. Without `BCONNECTED_TEST_JDBC_URL`, the database tests are skipped.

The final local focused checkpoint on 2026-09-20 passed **88 tests with zero failures, errors or skips**, recorded in the root BConnected checkout's ignored `.local/signal-final-postgres-tests.log`. The command above selects that suite: 22 account, eight signed-key/recovery, eight PostgreSQL lock, six reporting, seven push-challenge, nine Apple DeviceCheck, eight client-release store, one client-release manager, eight PostgreSQL-mode message-manager, eight file-monitor and three dynamic-configuration tests.

Earlier checkpoints passed 43 account/lock tests (22 account, eight signed-key/recovery, eight PostgreSQL lock and five legacy lock tests) and 377 affected API/manager regressions, including 162 `AccountsManagerTest` tests. These results overlap the later run and must not be added into a distinct-test total. Coverage includes competing identities, optimistic updates, key/token rollback, re-registration, number changes, deletion, username expiration, scan boundaries, distributed/nested locks, challenge consumption, DeviceCheck key ownership/counters and runtime backend guards.

The earlier storage suites are `PostgresPersistenceTest`, `SingleUseECPreKeysPostgresTest`, `SingleUseKEMPreKeysPostgresTest`, `ProfilesPostgresTest` and `RegistrationPostgresTest`; run them by replacing the `-Dtest` list above. They cover envelope queues, one-time key concurrency, encrypted profiles and registration bookkeeping. Stop the fixture only after all selected suites finish:

```sh
docker stop bconnected-postgres-test
```

## Remaining release work

The selected core account path no longer requires DynamoDB transactions, and reporting, push challenges, DeviceCheck and client-release reads are ported. Startup still constructs AWS-backed supporting services for optional billing/backups/experiments/schedulers and S3-oriented avatar paths. Disabling a product feature does not automatically remove its bootstrap dependencies. Configure a complete server/worker composition and prove its enabled paths start without AWS calls.

Upstream already supplies GCS attachment uploads through `GcsAttachmentGenerator`; the owned bucket, signing identity, upload/download endpoints and CDN still need provisioning and client validation. Avatar bytes, upload policies and deletion require separate GCP storage work despite native SQL metadata. Provision Redis, supply the local monitored files and deploy the separate encrypted group-storage service. FoundationDB is excluded in the selected PostgreSQL mode; it is no longer an unconditional initialization blocker there.

No Signal data backfill or dual-write migration exists. An existing deployment would need coordinated writers/readers, data transfer and verification before switching; switching back after PostgreSQL receives writes requires reconciliation.

Before opening the pilot, deploy an owned service composition, configure SMS and APNs, bind approved alumni to Signal identities, and connect the forked iPhone/libsignal networking to owned endpoints. Telnyx Verify is selected, but account access and its registration adapter are pending; no SMS integration is deployed. Validate two real clients exchanging encrypted DMs/group messages, offline redelivery, acknowledgements, suspension and re-registration. The 10,000-member configuration target does not establish 8,000-member capacity.
