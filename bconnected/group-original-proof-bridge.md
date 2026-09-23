# Original group proof bridge (unregistered)

This source checkpoint adds a bounded process-local registry retaining the actual, privately
constructed `AdmissionEntitlementGate.DeviceAuthorization`. It never renews the proof, creates a
membership, copies a password/account JSON, or trusts actor fields from a client. Only device 1 can
mint a ticket. The ticket binds the exact method, typed operation, derived group ID, canonical
request UUID and exact public request body SHA-256. Handles contain 256 random bits and remain
private service metadata. Explicit close, single resolve consumption and original expiry end their
use; fresh identical client retries require a fresh ticket with the same durable request ID/body.

`GroupResolveEndpoint` is an **unregistered application component**, not a working HTTP route.
Google `TokenVerifier` checks signatures and fixed issuer/audience. The component additionally
requires RS256, the exact configured Groups numeric subject, bounded issuance/expiry and the
strict version-one body. IAM/operator invocation alone is insufficient. Successful resolution
rechecks the same native account/device/admission snapshot and returns only the immutable full
membership binding, primary device, operation, echoed 256-bit nonce and remaining original
monotonic lifetime (at most four seconds). All diagnostics redact identity and handles.

The registry is bounded to a configured maximum of 4,096 retained proofs. Native proof rechecks
occur outside the registry monitor. No Groups SQL connection or lock may span this callback.
The Groups receiver must start its timer before queue/RPC work, use start plus returned remaining
duration, and never refresh a proof under authority/signing work. This is a bounded-staleness
cross-service lease, not an instantaneous distributed transaction.

Acceptance in this checkpoint: ten RSA-verifying endpoint/registry cases cover pinned identity,
issuer/audience/signature/time errors, missing token, replay, wrong binding, saturation, close and
secondary denial; four native PostgreSQL cases cover actual original device proof resolution and
account/membership/receipt changes before callback completion. Keys/accounts are synthetic. These
tests do not establish the live Google token exchange, owned TLS reachability, multi-instance
owner routing, authenticated public route, or end-to-end fanout.

Before registration: compose actual Signal REST account authentication and primary proof dispatch;
enforce per-account rate/in-flight caps, total request limits and statuses; pin the Groups runtime
subject and owned audience; deploy/verify a fixed private TLS callback and bounded OIDC key-fetch
execution; demonstrate failed operator-only invocation, original-proof checks before dispatch and
after result, delayed RPC/queue/SQL/signing churn, and same-byte lost-response recovery. Do not
register the callback or public gateway solely because these classes are present. Production group
signer/trust pins, invitations/consent bootstrap, key distribution, Stories and measured
8,000-recipient fanout remain separate required work.
