# Mobile enrollment implementation checkpoint

The `MobileEnrollmentController` implements the frozen version-one mobile enrollment contract at
`/v1/bconnected/enrollment` in an isolated Jersey composition. It is deliberately **not registered**
in `WhisperServerService`. No public signup route, confirmation worker, provider traffic, or new
deployment is enabled by this checkpoint.

Each request authenticates with the original phone number and generated password and carries the
same immutable enrollment envelope. Only `begin` can create an operation. Every operation-scoped
action first authenticates an existing operation and matches its path identifier before private
claims, verification-provider requests or account mutations. Exact committed retries can read
their original status after the enrollment deadline, but cannot recreate a deleted account.
Original Signal/user-agent metadata remains frozen; a future ingress must provide an explicit
trusted source-address resolver for `begin` rather than trusting arbitrary forwarding headers.

The controller limits body reads to ten seconds or less with bounded concurrency, enforces the
64-KiB cap before deserialization, and delegates strict UTF-8/JSON/key validation to the shared
parser. The future ingress still needs a bounded servlet/network read timeout so an uncooperative
stream cannot occupy a reader indefinitely. Responses use stable sanitized JSON errors and
`Cache-Control: no-store`. Missing or invalid Basic credentials return 401; missing or unsupported
media types return 400. Issuer, provider, storage and ambiguous failures remain retriable 503.

Verification status is capped by the original operation, native verification session and stored
claim deadlines. Status polling performs no provider send or automatic retry. An ambiguous send
does not trigger a resend on polling or process restart. A later explicit user-requested resend
remains subject to the existing durable cooldown and quotas.

Completion creates PENDING admission and its outbox atomically with the account and keys. Pending
and suspended responses contain no account projection and never authorize registration. ACTIVE
responses require a fresh device entitlement proof. Their ACI, PNI, number and primary-device ID
come from the same authoritative PostgreSQL account snapshot used to verify the password and
entitlement; no later account-cache lookup can substitute a different identity.

Shared response examples are in `service/src/test/resources/admission/mobile-enrollment-v1-responses.json`.
The enclosing workspace's `docs/mobile-enrollment-api.md` remains the integration contract.

## Validation and remaining boundaries

The initial focused run passed 142 tests on PostgreSQL 18.6, including native operation,
coordinator, account-creation, entitlement and retained-WebSocket regressions. The final HTTP
input refinement passed 37 tests: 27 native enrollment/Jersey cases, three body-reader cases and
seven shared-parser cases, with no failures, errors or skips. Evidence is recorded in the enclosing
workspace's `.local/mobile-enrollment-service-tests.log` and `.local/mobile-enrollment-final-tests.log`.
All phone and private-issuer responses in these tests are synthetic.

Opening the routes still requires owned ingress composition, trusted source-address handling,
bounded transport reads, scheduled confirmation/revocation handling and the remaining message
delivery/acknowledgment, gRPC-stream and anonymous capability gates. Stories and 8,000-member
announcements remain release requirements. This checkpoint does not demonstrate real iPhone
registration, end-to-end messaging, or capacity at that scale.
