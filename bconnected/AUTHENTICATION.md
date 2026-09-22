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

This is not complete capability or revocation enforcement. Cross-store delivery/acknowledgment
boundaries beyond the guarded native queue deletion, credential issuance, and anonymous
Stories/group/media operations still require their own use-time gates and bounded revocation
handling. Retaining a proof does not automatically enforce it at those sites.
Registration controllers stay absent and the confirmation worker stays unscheduled. No public
enrollment or continuously running messaging service is enabled by this source change.

## Retained chat WebSockets

The GCP composition now installs `AdmissionWebSocketSessionManager` and a global request filter.
The filter admits an exact opaque device proof and replaces the provider's original reusable-auth
property. A Jersey `SubjectSecurityContext` checks that same proof immediately before invoking the
resource method, after managed asynchronous dispatch and parameter validation. A delayed request
cannot substitute a later renewed connection proof. This includes Optional-auth handlers and
methods without an auth parameter; a missing proof cannot downgrade a request to anonymous.

The session manager renews at half the remaining receipt lifetime. Renewal rechecks the original
credential-verified SQL snapshot, obtains a new private receipt outside SQL, rechecks that snapshot,
and requires the old lease to remain valid through publication. It never retains the password or
reads the upgrade Authorization header. Any account-row mutation requires reconnecting rather
than adopting a new credential snapshot. Successful renewal has its own original request-start
deadline, so healthy connections can outlive the first four-second lease.

An independent scheduler closes expired connections while SQL/HTTP renewal workers are blocked.
There is at most one renewal per connection, at most 64 concurrent renewal workers, and no worker
queue or caller-runs fallback. Exhaustion, issuer errors, stale evidence and expiry close with 1013;
definitive local membership rejection closes with 1008. A 250ms forced-disconnect fallback does not
depend on peer cooperation. Request checks remain conservative if a scheduler is delayed. In-flight
requests on an unavailable closing connection remain 503; a local definitive rejection remains 401.
The context's identity is never cleared as a failure response, and closed sessions cannot reopen
from late renewal results. Close listeners execute outside the context lock to avoid lifecycle lock
inversion.

Initially anonymous or proofless pilot chat upgrades are rejected. Pilot provisioning upgrades are
also rejected and the REST provisioning controller is omitted for the one-iPhone policy. This is a
**temporary closed-runtime boundary**: anonymous Stories and group sending remain required before
release, including the 8,000-member announcements use case. Deferred account-management methods
use the explicit policy below. Server-initiated delivery and acknowledgments do not pass
the request filter; their separate dispatch guards are described below.

The high-frequency private entitlement reads have not been capacity-tested for 8,000 connected
alumni. Half-life renewal can mean roughly 4,000 private reads per second at a four-second lease,
plus initial authentication and local request checks. The 64-worker limit is a bounded pilot safety
limit, not an 8,000-user throughput claim; entitlement distribution/capacity remains a release gate.

## WebSocket delivery and native queue acknowledgments

The pilot connect listener supplies a mandatory delivery authorization adapter. Startup, encrypted
message dispatch, queue-empty notification, story-discard acknowledgments and successful client
acknowledgments capture the current credential-verified connection proof before executor dispatch.
Queued work rechecks that exact proof; it cannot adopt a later renewal to hide elapsed time. A later
client ACK is a separate use and may capture the connection's legitimately renewed proof, so an
ordinary message round trip is not limited to the first lease's four seconds. Queue-empty remains
ordered after preceding acknowledgments. Stopped or closed connections cannot restart queued work.

Delivery SQL checks use a separate executor with at most 64 virtual workers and no queue/caller-runs
fallback. A pilot connection allows at most eight concurrent message sends. These are bounded pilot
limits, not a capacity claim. The deadline scheduler never performs SQL or waits on this executor.
GCP composition has no unguarded listener fallback; legacy constructors retain legacy behavior.

Native PostgreSQL deletion carries the exact ACK proof through its executor and pool acquisition.
It locks account, admission and confirmation state on the deletion's existing READ COMMITTED
connection, checks the original receipt, deletes only the exact account/device-generation/message,
then checks again before commit. Expiry during account or message-row waits rolls the transaction
back. Using the existing connection avoids pool starvation from a second authorization checkout.
The proof additionally binds the device creation timestamp, so a stale cached device generation
cannot authorize a different queue. Backends without guarded deletion reject the operation.

Redis-miss continuation rechecks on the delivery executor before dispatching native deletion, not
on a Redis event-loop thread. Receipt submission and its own executor/account-cache waits also
retain and recheck the ACK proof. Pilot disconnects no longer schedule delayed push from a stale
cached identity; an independently authorized notification reconciler remains necessary.

This is a dispatch and native-transaction boundary, **not atomic authorization across every store
or network queue**. Redis deletion, including its asynchronous retries/remote execution, is not
atomic with PostgreSQL account state or the receipt deadline. A cache deletion may already have
occurred when a later check rejects the operation. Downstream receipt message enqueue, socket
transport buffering and anonymous Stories/group capabilities need further
use-time enforcement. No new public route, outbox scheduling, real provider request or deployment
is enabled by this source checkpoint.

## Authenticated gRPC message streams

`GCP_PILOT` supplies a mandatory `AdmissionGrpcSessionManager` to `MessagesGrpcService`.
Opening a stream requires a primary-device proof and checks its unchanged native account/device
generation before using the cached account to initialize the message queue. Missing or stale cache
state is unavailable, not proof that the password is invalid. Initialization runs on a bounded
delivery executor. Cancellation while that initialization waits cannot leave a renewing lease.

The stream renews its immutable credential proof with fresh private entitlement using the same
old-lease publication fence as WebSockets. Independent deadlines terminate it with UNAVAILABLE
while renewal or delivery workers are blocked. There are separate 64-worker delivery and renewal
executors without queues or caller-runs fallback; SQL never executes on the deadline thread.
Late renewal completion cannot revive a cancelled stream.

Encrypted responses and queue-empty notifications pass a native proof check after downstream demand
and the final delivery-worker wait. One response may be buffered; a healthy renewal can authorize a
later client demand rather than forcing reconnection because the client paused. The check captures
one proof and retains it through its own SQL wait. An actual simple-grpc readiness test verifies no
observer emission after expiry, and an in-process authenticated service test covers delivery and ACK.

ACK and story-discard effects capture their proof before worker dispatch and use the same guarded
queue and PostgreSQL deletion APIs as WebSockets. Later ACKs may use a legitimately renewed lease;
already queued effects cannot borrow it. Expiry closes input ACK/message subscriptions even at zero
demand: cancellation is explicit because Reactor's secondary-error path alone does not cancel its
main publisher. Pilot stream closure does not schedule push from a cached identity.

This covers authenticated message retrieval, its ACKs and story-discard operations. It does not
gate unary sends, every recipient, anonymous sending, previously issued capabilities, or bytes
already accepted by transport buffers. The Redis and downstream receipt limits described above
remain. No provider traffic or deployment is implied by these source tests.

## Deferred pilot account management

GCP composition explicitly passes `AccountOperationsPolicy.PILOT_PRIMARY_ONLY` to both REST and
gRPC account/device controllers. Device-link token issuance, linking, linked-device removal and
naming, link/transfer waiters, restore-account notification, transfer-archive operations, number
changes and recovery-password changes reject before any handler dependency calls. HTTP uses503
and gRPC UNAVAILABLE through the existing disabled-feature mapping; no successful no-op is returned.
Wire validation and authentication can reject earlier. The anonymous restore endpoints receive the
same policy even though they have no `@Auth` parameter. Provisioning remains omitted separately.

Ordinary primary-device reads, names, push registration and capability updates retain their existing
behavior. An `/attributes` request carrying a nonempty recovery password rejects the whole mutation;
pilot clients must omit it on ordinary attribute updates. The isolated enrollment snapshot/native
primary account creator is not modified, including its existing optional recovery-password field.
Its public route remains unregistered, and legacy account registration/recovery stays omitted.
The policy controls available operations; it does not replace use-time entitlement guards on the
retained mutable methods or enable deferred flows via an internal manager API.

## Verification

The 2026-09-21 focused reactor run passed 115 tests (110 service and five WebSocket-resource
tests), with no failures, errors or skips. This includes 28 native PostgreSQL authentication cases,
36 entitlement-gate cases, legacy authentication/configuration regressions, and actual HTTP filter,
WebSocket upgrade and gRPC error-mapping checks. Native fixtures assert zero phone-provider
interactions. The log is `.local/admission-authentication-tests.log` in the enclosing workspace.
That initial-authentication checkpoint did not establish existing-connection revocation.
The subsequent WebSocket suite exercises native SQL snapshots, synthetic issuer responses, actual
Jersey synchronous and managed-asynchronous dispatch, blocked renewal, independent deadlines,
healthy repeated renewal, local mutation, executor rejection and closure. It does not establish
anonymous capability enforcement, server-initiated delivery revocation or real iPhone messaging.
The final combined run passed 171 tests (146 service and 25 WebSocket-resource), including 29
native WebSocket entitlement cases and two close-listener concurrency cases, with no failures,
errors or skips. Evidence: `.local/admission-websocket-tests.log` in the enclosing workspace.
The subsequent delivery checkpoint passed 143 tests on isolated PostgreSQL 18.6, including 22 new
native delivery/acknowledgment cases and retained WebSocket, entitlement, enrollment and queue
regressions. It tests queued-send rejection, healthy renewed ACKs, story-drop guards, stop/close
races, receipt waits, exact generation binding, and rollback after real SQL message-row waits.
All issuer, phone-provider and socket responses are synthetic. Evidence:
`.local/admission-delivery-tests.log` in the enclosing workspace.
The gRPC checkpoint passed 141 tests on isolated PostgreSQL 18.6, including 21 new native gRPC
cases, 22 delivery cases, 36 entitlement cases and 62 retained dispatcher/service cases. Coverage
includes actual bridge readiness, authenticated in-process delivery/ACK, stopped initialization,
late renewal cancellation, executor rejection, original-proof expiry and guarded story discard.
No failures, errors or skips; evidence: `.local/admission-grpc-tests.log` (2026-09-22).
The deferred account-policy suite passed 451 tests with no failures, errors or skips, including 17
new actual REST/gRPC policy cases and 27 native primary enrollment cases. Synthetic valid link and
number-change requests prove rejection before dependency interactions; primary APNs/device reads
remain available. Retained account/device regressions cover the standard constructor behavior.
Evidence: `.local/pilot-account-operations-tests.log` (2026-09-22).
