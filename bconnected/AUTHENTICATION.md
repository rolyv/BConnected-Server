# Pilot authentication boundary

`GCP_PILOT` always constructs a pinned, IAM-authenticated private admission client and a native
PostgreSQL `AdmissionEntitlementGate`. Startup has no missing-client or legacy-auth fallback.
`AccountAuthenticator.withAdmission` accepts only the primary device, matching the one-iPhone
pilot. It verifies its password in the live SQL snapshot, requires local ACTIVE admission with
confirmation and a fresh current-entitlement receipt, and checks the same evidence again before
returning a principal. Cache-backed credentials are not consulted. Missing, pending, suspended,
locked, replaced, expired or unavailable state cannot return an authenticated principal.

Definitive local identity, approval and password rejection is unauthenticated. Storage failures,
changed full-row evidence and all private admission errors are retriable unavailability, not proof
of a bad device password. In particular, the private client's denied category includes IAM errors
and rate limits, so its remote status must not be translated into terminal device-auth rejection.
HTTP and WebSocket upgrade failures use 503; gRPC uses UNAVAILABLE. None returns a principal or
refreshes the original receipt.

The HTTP principal retains opaque device evidence. The gRPC interceptor preserves that same
object when converting principals. Their explicit `requireCurrentEntitlement()` method rechecks
live state and the original receipt without HTTP renewal; a principal without evidence cannot
satisfy it. Evidence is excluded from JSON serialization and never retains the raw password.
Legacy constructors remain available for the legacy composition and tests.

## Activity writes are deferred

Pilot authentication deliberately does not call the legacy `updateLastSeen` path. That write changes
the complete account snapshot, which would invalidate the evidence. Acquiring another receipt to
hide the mutation would silently replace its freshness budget. A future activity update must prove
an explicitly permitted transition while retaining the original receipt and validating live device
identity; it must not copy an old device's activity onto a replacement device.

Consequently last-seen metadata and activity metrics do not advance through this auth path. Idle
classification, device-age decisions and any future cleanup based on that data cannot be treated
as current pilot activity. The unused legacy idle worker is not enabled for the pilot. Do not enable
idle cleanup until a guarded activity transition is implemented and tested.

## Still required before opening enrollment

This is initial HTTP/WebSocket/gRPC authentication, not complete capability or revocation
enforcement. Existing connections, delayed message delivery, credential issuance, device-link
routes, and anonymous Stories/group/media operations still require their own use-time gates and
bounded revocation handling. Retaining a proof does not automatically enforce it at those sites.
Registration controllers stay absent and the confirmation worker stays unscheduled. No public
enrollment or continuously running messaging service is enabled by this source change.

## Verification

The 2026-09-21 focused reactor run passed 115 tests (110 service and five WebSocket-resource
tests), with no failures, errors or skips. This includes 28 native PostgreSQL authentication cases,
36 entitlement-gate cases, legacy authentication/configuration regressions, and actual HTTP filter,
WebSocket upgrade and gRPC error-mapping checks. Native fixtures assert zero phone-provider
interactions. The log is `.local/admission-authentication-tests.log` in the enclosing workspace.
These tests do not establish existing-connection revocation, anonymous capability enforcement or
real iPhone messaging.
