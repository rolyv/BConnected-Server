# Pilot MFA and independent worker closure

`AccountOperationsPolicy.PILOT_PRIMARY_ONLY` rejects all nine MFA gRPC methods with
the existing unavailable mapping before account/cache reads, rate limiters or
provider effects. This is explicit policy and does not depend on the account
having a phone number. `STANDARD` retains the upstream behavior.

`RuntimeMode.GCP_PILOT` allows only `message-persister-service` through the worker
dependency builder. Scheduled APNs, account/device deletion, discoverability and
activity cleanup commands reject before dependency validation or construction.
`LEGACY` remains unchanged. Message persistence remains available for previously
enqueued messages; it does not require renewing an expired sender receipt.

Tests use an authenticated in-process gRPC stub for all nine MFA denials,
verify no account/rate-limit/provider collaborators were called, retain the
standard account-service regression suite, and exercise worker policy before
dependency construction. This source does not implement admitted username/ZK
mutations, account lifecycle operations, or enable enrollment or scheduling.
