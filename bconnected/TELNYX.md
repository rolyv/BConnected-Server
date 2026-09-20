# Telnyx Verify registration adapter

`registrationService.type: telnyx` selects a native PostgreSQL registration coordinator and Telnyx Verify SMS transport. This is source integration; selecting it does not deploy Signal Server, remove other bootstrap dependencies, configure APNs, or bypass existing CAPTCHA, push-challenge and fraud checks. Alumni admission enforcement remains additional integration work.

The original gRPC registration service remains the default. Both implement `RegistrationService`; existing controllers and phone-verification token checks retain their behavior.

## Configuration

Apply `migrations/011-telnyx-registration.sql` before starting the Telnyx implementation. The Signal PostgreSQL role needs SELECT, INSERT, UPDATE and DELETE on `signal.registration_sessions` and `signal.registration_quotas`. The factory reuses the configured Signal PostgreSQL pool; it does not construct a separate database or public service.

The following is a **proposed pilot policy**, not automatically enabled configuration. Review the limits before deployment. The quota window is fixed, so requests around its boundary can consume two successive windows. Provider-level destination restrictions and a monetary spending cap are additional controls, not substitutes for these application limits.

```yaml
registrationService:
  type: telnyx
  verify:
    apiKeyEnvironmentVariable: TELNYX_API_KEY
    verifyProfileId: <owned-Telnyx-Verify-profile-UUID>
    verificationTimeout: PT5M
  policy:
    sessionLifetime: PT10M
    quotaWindow: PT24H
    maxSessionsPerNumber: 10
    maxSessionsPerSource: 30
    maxSmsPerNumber: 5
    maxSmsPerSession: 3
    maxChecksPerNumber: 20
    maxChecksPerSession: 5
    smsCooldown: PT1M
    checkCooldown: PT1S
  collationKeySalt: secret://registrationCollationKey
```

Supply `TELNYX_API_KEY` using a Secret Manager environment reference. The existing Signal secrets bundle entry `registrationCollationKey` contains Base64 of at least 32 random bytes. An operator probe can instead decode `BCONNECTED_REGISTRATION_COLLATION_KEY` and pass the resulting bytes to the coordinator constructor. Never place either value in source, command arguments, logs or documentation. Keep the collation key stable across replicas and restarts; changing it resets the effective HMAC-keyed quota namespace and requires a deliberate transition plan.

All coordinator policy fields are required and validated. SMS verification lifetime must fit within session lifetime. The factory rejects absent PostgreSQL persistence before constructing the provider. A missing API key prevents startup. Session data and provider verification IDs stay server-side; responses use independently generated 32-byte session IDs. The database stores no OTP code or provider credential. Source addresses and phone numbers used for quotas are represented by domain-separated HMACs; the short-lived session itself retains the phone number for binding.

## Verification behavior

Creating a session sends nothing. The existing `VerificationController` must first allow code requests following its admission checks. Only SMS is supported; voice and sender overrides are explicitly rejected. Telnyx's accepted send response proves only that it accepted the send request. The session remains unverified until Telnyx explicitly accepts a submitted code for its server-stored verification UUID and matching phone number.

Each send/check reserves its counters and operation lease in a committed SQL transaction before any provider request. Provider calls execute outside database transactions and are not automatically retried. Failed or ambiguous requests consume budget. A resend invalidates the prior provider verification ID before contacting Telnyx. A crash or timeout may require the user to request another code after the cooldown; it cannot silently verify the session.

Completion requires the same operation UUID, an active lease, an unexpired session and, for checks, an unexpired code. An old or late accepted response cannot verify newer state. Verification does not extend session lifetime. Reads perform no provider request and ignore expired sessions. `PhoneVerificationTokenManager` still requires both an exact phone-number match and `verified=true` before accepting the session for registration.

Quota limits for phone numbers survive new sessions and process restarts. Check budgets are not reset by resending. A scheduled cleanup removes bounded batches of expired sessions and expired quota windows every minute. Expiry is enforced on reads/operations independently of cleanup.

## Local validation

`TelnyxRegistrationServiceTest` requires an isolated local `_test` PostgreSQL database and uses a mocked provider, so it sends no SMS. It covers concurrent reservations, quotas across sessions, rejected/ambiguous outcomes, malformed-code handling, exact expiry, stale completion fencing and the existing token manager's authorization requirements. `TelnyxRegistrationServiceConfigurationTest` checks discoverability and fail-closed configuration. `TelnyxVerifyClientTest` exercises mocked HTTP responses.

The PostgreSQL tests truncate the two registration tables. Do not run them against a database containing a live pilot verification between its send and code-check steps. Any real SMS test requires the owner's selected number and explicit authorization; keep its session identifier and submitted OTP private.

## BConnected checkpoint — 2026-09-20

The final source passed 99 tests (16 coordinator, 13 provider, three factory, 55 controller, 12 token manager). One user-authorized SMS was delivered and its code accepted using the actual adapter/coordinator and a disposable local database. A subsequent expiry-timing refinement was covered by the final 99-test run; no second live SMS was sent. The provider profile now enforces the approved $10 daily cap and six-digit codes for Signal iOS; configuration was re-read successfully. Eleven migrations and 23 application tables are provisioned in GCP. The Signal messaging process and iPhone signup are not deployed. See the root repository for sanitized deployment evidence.
