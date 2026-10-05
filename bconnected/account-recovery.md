# Operator-assisted account recovery

Recovery retains the existing member, ACI, PNI, phone claim, permit and admission lineage. It replaces the primary device credential, both identity keys, signed prekeys and registration IDs. Old encrypted queues, single-use prekeys and profiles are removed. It cannot restore the missing device's private keys or message history; contacts must establish a new cryptographic session.

Public REST routes are `POST /v1/bconnected/recovery/begin` and `POST /v1/bconnected/recovery/{recoveryId}/{send-code,check-code,status,complete}`. They require the canonical phone number and newly frozen password in Basic authentication. Every body contains the same `recoveryAttemptId`, `registrationRequest`, `originalSignalAgent` and `originalUserAgent`; only `check-code` includes `code`. `begin` never sends a message. The ordinary signup application and journal are not recovery authority and remain untouched.

Native Telnyx verification records its original completion instant. Existing sessions without that new timestamp are ineligible. A fresh proof lasts five minutes. The private admission service registers the exact original binding, new request/key commitments and original account version, then requires its separate operator-only SQL grant. The runtime cannot mint grants. The original binding must still be approved at the same epoch and hold the same permanent phone claim.

`complete` records explicit durable intent before consuming the private grant. An exact confirmed receipt can reconcile a lost response after its original deadline; an expired unconfirmed proof cannot initiate replacement. Status may resume that explicitly started work but cannot start a merely prepared/authorized replacement. A changed original account version, either unchanged registration ID, another device or a mismatched immutable tuple fails closed.

Replacement locks account, admission and recovery in that order. One transaction updates the account and four repeated keys, removes old SQL queue/profile/prekey material, and commits `RECOVERING` plus cleanup work. Existing membership gates deny all normal old/new-device and recipient traffic during that fence. Device creation time advances into a distinct 128 ms message-queue generation. Initial-prekey tombstones remain retained; a new device generation gets its own initial publication slot and cannot replay a previous generation's operation.

Cleanup is serialized by a PostgreSQL session advisory lock. It waits for socket disconnection, Redis queue clearing and profile/account cache invalidation before any activation. Failure retains the durable fence. A fresh, exact private recovery entitlement is then checked again while account/admission/recovery rows are locked before `ACTIVE`. This matches first enrollment: the app still holds local pending-services readiness until normal authenticated profile, attributes and initial prekey publication complete.

Deploy native migrations `018-verification-time.sql` and `019-account-recovery.sql` after the existing migrations. Migration 018 does not backfill old verification times. Migration 019 preserves initial-publication history and only replaces the original exact seven-column uniqueness constraint. Runtime needs the usual native store permissions on `signal.account_recoveries`; admission grants remain separately restricted. A legacy runtime must not be restored after recovery is used because it does not enforce the new device-publication generation contract.

Once the operator has approved the prepared private request, run the following inside the owned runtime's network namespace (admin remains loopback port 8081):

```sh
python3 bconnected/recover-account.py RECOVERY_UUID EXACT_REQUEST_HASH
```

This calls the same tested service logic as public `complete`, using the persisted salted verifier and frozen registration payload. It does not extract or print the new password, OTP, phone, account identity, grant or keys. Output contains only status/state or a typed error. An interrupted call has an uncertain outcome: inspect or retry that exact operation and commitment, without creating another grant. The native status route installs the matching result and then publishes the new local materials.
