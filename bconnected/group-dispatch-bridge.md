# Unregistered authenticated group dispatch slice

`GroupDispatchController` exposes only the four initial REST shapes to an actual Jersey
`@Auth AuthenticatedDevice` principal. No launcher registers this controller. The dispatcher
requires the principal's retained, credential-verified `DeviceAuthorization` and primary device 1.
It binds exact client request bytes and canonical operation fields into a fresh registry ticket on
each attempt, rechecks that same ticket before private dispatch and after strict response parsing,
and closes it on every exit. It never reads an actor, enrollment, epoch or deadline from a client.
Native presentation and group protobuf validation remain in the storage `GroupGateway`.

The source limits are 64 KiB request body, 20 MiB successful JSON response (allowing the existing
8 MiB native state and 4 MiB manifest payload ceilings), ten requests per
account with one replenished every six seconds, two concurrent requests per account, four concurrent
requests across accounts, 4,096 account slots, and four transport workers plus eight queued tasks.
An idle slot can be reclaimed after two minutes at slot capacity. The original proof remains at
most four seconds; executor, token and network waits spend that budget. The HTTP request has a
one-second connect timeout and at most two seconds for a complete response. Late, interrupted or
cancelled token providers are checked again before any network dispatch. Cancellation of a stalled
provider is best effort; the worker/queue limit remains enforced. The transport also rechecks the
same retained original proof before and after OIDC acquisition and immediately before send; it
does not rely on the monotonic deadline alone.

The fixed Groups HTTPS origin is constructor supplied and must have no path, query, port or
userinfo. `GroupGatewayHttpTransport` obtains a Google ID token for exactly that origin from the
dedicated Signal runtime identity. It sends the original public method/path/body, `Authorization:
Bearer <IAM token>`, and a private `X-BConnected-Original-Proof` handle header. The handle is never
returned to clients or logged. Redirects, compressed responses, unexpected content types/statuses,
and streaming responses above 20 MiB fail closed. The private HTTP adapter on Groups must pass the
handle plus exact method/path/body to existing `GroupGateway.execute`; it must not accept any
client-supplied actor binding. On success it must return one `application/json` body with status
200. Storage `GroupGateway.Committed` and `Outcome` carry `GroupAuthority.CommittedOutcome`
(`groupId`, `revision`, `nativeSha256`); `Current` carries `requestNonce` and a
`GroupManifestCodec.Envelope` (`nativeGroup`, `compactJws`). The private adapter serializes
mutation/outcome success JSON as exactly `groupId`, `revision`, `nativeSha256`; state success JSON
as exactly `requestNonce`, `nativeGroup`, `manifest`, where `manifest` is the envelope's compact JWS.
Binary fields use unpadded base64url and UUIDs use canonical lowercase text. Signal validates
the canonical binary/UUID fields, group/nonce binding, uint32 revision, duplicate/unknown fields,
and response size before forwarding. Only 403, 404, 409 and 503 denial statuses are mapped to
sanitized public responses; other private statuses become 503. The public controller sets
`Cache-Control: no-store` on every result.
An empty historical `Outcome` maps to 404; it never grants membership.
The Signal ceiling test uses syntactically canonical maximum-size fields; a combined native-valid,
signed maximum fixture and measured four-request memory peak remain integration acceptance work.

The following are **root-owned composition and network prerequisites**, not established by this
source: register the Signal controller and Groups private gateway adapter only after integrated
review; pin the fixed Signal/Groups origins and dedicated runtime principals; verify bidirectional
private TLS/IAM, callback routing to the ticket-owning Signal process and Google OIDC key refresh
bounds; provision the independent group manifest signer and client trust pins; and exercise actual
callback, SQL and signing waits under account/epoch churn. A multi-instance Signal deployment needs
an explicit ticket-owner route. No public group route, callback, signer or delivery path is enabled
by compiling these files.

The unregistered Signal callback `GroupResolveEndpoint` is also `AutoCloseable`. It uses two
verification workers and eight queued tasks; a caller waits at most one second including queue
time. A malformed bounded envelope is rejected before any token key-provider fetch. Timeout,
interruption or cancellation never resolves its handle. A late, uninterruptible provider occupies
only bounded worker capacity. Closing the endpoint drains admitted registry resolutions and
suppresses their responses. Provider HTTP/key-fetch termination remains best effort; live Google
key-refresh execution bounds have not been verified.
