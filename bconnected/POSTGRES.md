# PostgreSQL persistence for BConnected

This fork is moving its database storage to PostgreSQL on GCP Cloud SQL. The messaging server is not deployed. The optional `postgres` configuration currently selects native SQL implementations for durable encrypted-envelope storage, remote configuration, single-use EC/KEM public prekeys, profiles and registration-support storage; other server paths retain their upstream dependencies.

## Implemented paths

`PersistentMessageStore` separates message consumers from the DynamoDB implementation. `MessagesPostgres` uses `signal.messages`, keyed by account, device generation, server timestamp and message UUID. It preserves upstream device-generation encoding and stores serialized encrypted envelopes in a `bytea` column. The storage layer never decrypts them or changes Signal cryptography. Routing identifiers and queue timestamps remain database-visible metadata.

Message batches commit atomically, including batches spanning multiple JDBC executions. Duplicate keys update the existing envelope. Ordered, bounded keyset pages preserve the upstream publisher contract; the requested page size does not limit the total result count. Acknowledgement uses `DELETE ... RETURNING`, so competing acknowledgements cannot return the same stored envelope twice. Reads exclude expired envelopes, and a managed worker deletes at most 5,000 expired rows every 60 seconds. Deletion is eventual; it can lag under sustained backlog or worker downtime.

`RemoteConfigStore` allows `RemoteConfigsManager` to use `RemoteConfigsPostgres`. `signal.remote_configs` stores percentages, UUID enrollment arrays and nullable default/value/hash fields using bound SQL parameters. The supplied `remote-config.json` remains an input specification, not an automatically imported database file.

`SingleUseECPreKeyStorage` separates `KeysManager` from the upstream EC prekey store. `SingleUseECPreKeysPostgres` uses `signal.single_use_ec_prekeys` and preserves libsignal's public-key serialization; private keys never enter this store. Taking a key deletes and returns it within one transaction. A per-account PostgreSQL advisory lock coordinates consumption, whole-device replacement and account/device deletion across store instances. Failed replacement restores the previous keys, and invalid stored encoding rolls back consumption. Repeated-use signed prekeys still require the account transaction migration.

The main service and worker dependency factory select the implemented PostgreSQL stores when `postgres` is present. Omitting it preserves the existing DynamoDB selection. This is an incremental migration switch, not a declaration that the server can start without DynamoDB configuration.

## Additional implemented paths

`SingleUseKEMPreKeysPostgres` retains serialized libsignal public keys and signatures in native SQL rows. Account locks make replacement, consumption and deletion atomic. Duplicate key IDs collapse to one entry, preventing repeated distribution. Invalid new key IDs are rejected; malformed stored key bytes fail without consuming the row. Last-resort fallback remains in `KeysManager`. Native storage constructs no KEM S3 client; the page-pruning command explicitly skips this backend.

`ProfilesPostgres` stores v1/v2 ciphertext and commits dual writes on one connection. It preserves the initial commitment, checks expected data hashes and rolls back both formats on failure. `ProfileAvatarsPostgres` stores ownership/expiry metadata; avatar object bytes still use the upstream object-storage integration. The metadata expiry worker is bounded.

`VerificationSessionsPostgres` preserves insert-only creation, update/upsert and the upstream expiration boundary. `PhoneNumberIdentifiersPostgres` locks equivalent phone forms in a deterministic order and never overwrites established mappings. `ChangeNumberWaitingPeriodsPostgres` preserves registration and change-number expiry rules. Phone mappings are intentionally retained independently of account deletion.

These three suites passed 25 PostgreSQL tests in total. Affected manager and cleanup-worker regressions passed 66 tests. There is no SMS provider configured and no full messaging deployment.

## Cloud SQL connection example

The community pilot uses Cloud SQL PostgreSQL 17 in `roly-dev:us-east1:bconnected-postgres`, database `bconnected`. Its PostgreSQL cutover was verified on 2026-09-20 with 17 deployed API checks; this does not constitute a messaging-server deployment. Its runtime identity has access only to the `community` schema. The separate `bconnected-signal@roly-dev.iam.gserviceaccount.com` identity and its IAM database user have now been provisioned with instance-scoped login and DML on the ten implemented Signal tables. SQL privilege checks show no access to the community schema and no schema-creation privilege. The server process has not yet connected using this identity.

Run Cloud SQL Auth Proxy v2 beside the server using the messaging service account's credentials. The proxy and JDBC application must share a trusted host/network namespace; keep its listener on loopback:

```sh
cloud-sql-proxy --auto-iam-authn --address=127.0.0.1 --port=5432 \
  roly-dev:us-east1:bconnected-postgres
```

The proxy's IAM identity must match the database username. With an authorized impersonation setup, an operator can use service-account ADC instead of a downloaded service-account key. See [Google's automatic IAM login procedure](https://docs.cloud.google.com/sql/docs/postgres/iam-logins).

Add this top-level block to the server's YAML, after provisioning that identity and applying the schema:

```yaml
postgres:
  jdbcUrl: "jdbc:postgresql://127.0.0.1:5432/bconnected?sslmode=disable"
  username: "bconnected-signal@roly-dev.iam"
  maximumPoolSize: 5
```

`sslmode=disable` applies only to the local application-to-proxy connection; the proxy secures its Cloud SQL connection. Do not use this URL pattern for a direct remote database connection. Automatic IAM authentication supplies the database credential, so omit `passwordEnvironmentVariable` in this deployment mode. The Cloud SQL instance requires connectors and IAM authorization; its public IP is not permission to connect directly.

For a local PostgreSQL fixture using password authentication, the supported optional setting is the **name** of an environment variable:

```yaml
postgres:
  jdbcUrl: "jdbc:postgresql://127.0.0.1:55432/bconnected_test"
  username: "postgres"
  passwordEnvironmentVariable: "BCONNECTED_POSTGRES_PASSWORD"
  maximumPoolSize: 5
```

Never put a password or access token into YAML. A configured password variable that is missing or blank fails startup. Pool size defaults to five and is restricted to 1–30. The pool uses a 15-second connection timeout and query/lock timeouts; the application lifecycle closes it on shutdown. Size the combined pools of every service and worker against database capacity before deployment.

## Schema and local validation

Apply migrations `001-postgres.sql`, `002-ec-prekeys.sql`, `004-registration.sql`, `005-kem-prekeys.sql` and `006-profiles.sql` with a migration identity before selecting PostgreSQL. All are required for the selected storage paths; 003 is reserved for the account transaction port. The root repository's `migrate-signal.mjs` applies them with checksums and narrow database grants. The server does not apply schema changes at startup. The community API's separate migration script creates only its own schema.

From the root of this Signal server checkout, with Docker and JDK 26 available:

```sh
docker run --rm --detach --name bconnected-postgres-test \
  --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_PASSWORD=bconnected-local-test \
  --env POSTGRES_DB=bconnected_test postgres:17
docker exec bconnected-postgres-test pg_isready -U postgres -d bconnected_test

BCONNECTED_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/bconnected_test \
BCONNECTED_TEST_POSTGRES_PASSWORD=bconnected-local-test \
./mvnw -B -ntp -pl service -am \
  -Dtest=PostgresPersistenceTest,SingleUseECPreKeysPostgresTest,SingleUseKEMPreKeysPostgresTest,ProfilesPostgresTest,RegistrationPostgresTest \
  -Dsurefire.failIfNoSpecifiedTests=false test

docker stop bconnected-postgres-test
```

Reuse the container if the community tests already started it, and wait for `pg_isready` before running Maven. Set `JAVA_HOME` to the installed JDK 26 if the shell uses another Java version. The test password is a local fixture. The test URL must use a loopback host and an isolated database ending in `_test`; these tests apply the schema and truncate their tables. Without `BCONNECTED_TEST_JDBC_URL`, the integration tests are skipped.

On 2026-09-20 the full main/test sources compiled and both PostgreSQL suites passed, with zero failures, errors or skips:

- `PostgresPersistenceTest`: six tests covering 205 envelopes across small pages, duplicate storage and encrypted content preservation, account/device-generation isolation, 20 competing acknowledgements, rollback after a late batch failure, expiry and remote-config null/enrollment behavior.
- `SingleUseECPreKeysPostgresTest`: seven tests covering libsignal encoding/key-ID boundaries, account/device isolation, concurrent consumers across store instances, failed bulk-replacement rollback, competing replacements, account deletion racing with replacement, and rollback when stored encoding is invalid.

The existing `KeysManagerTest` also passed all 16 tests after the interface change. This is focused local persistence and caller regression validation, not a complete server integration or load test.

## Remaining migration work

Repeated-use signed prekeys still generate DynamoDB `TransactWriteItem` objects that participate in account/device transactions. Accounts and these key mutations must migrate as one atomic unit; a split transaction across DynamoDB and PostgreSQL is not an acceptable substitute.

Other DynamoDB stores and AWS dependencies remain, including repeated-use signed keys and accounts. The native one-time KEM store no longer uses S3, but avatar and attachment bytes still need their GCP object-storage integration. FoundationDB, Redis, registration/push integrations, attachments and the separate group-storage service also remain deployment dependencies or migration decisions. `postgres` does not configure, disable or replace those components.

No existing Signal messaging data has been migrated by these SQL files, and no dual-write/backfill mechanism is implemented. Enabling PostgreSQL against an existing deployment with queued messages or stored prekeys would require a write freeze, export/import verification and coordinated readers/writers. After writes begin in PostgreSQL, switching the configuration back cannot restore those writes to DynamoDB automatically.

Before a messaging pilot, validate two approved accounts exchanging encrypted DMs and group messages on owned infrastructure, reject unapproved and suspended accounts at the server, and configure APNs. Large-group testing remains a separate release gate; the 10,000-member configuration target is not evidence of 8,000-member capacity.
