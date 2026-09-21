# Registration public-key commitment

`admission.RegistrationKeyCommitment.compute(RegistrationRequest)` implements the public transcript in the community admission contract. It returns lowercase SHA-256 hex after requiring ACI and PNI identities, registration IDs, signed EC prekeys and last-resort Kyber prekeys. It snapshots signatures, reparses serialized keys with libsignal, checks canonical round trips, and applies the existing `PreKeySignatureValidator` to the same snapshots that are hashed. Invalid input throws a fixed-message exception without retaining request material or a parser cause.

The prefix is UTF-8 `bconnected.registration-keys.v1` followed by a zero byte. Each of the following 16 fields has an unsigned 32-bit big-endian byte-length prefix:

1. ACI identity key serialization, then PNI identity key serialization.
2. ACI registration ID, then PNI registration ID, each encoded as four big-endian bytes.
3. ACI EC prekey ID (eight big-endian bytes), serialized public key, signature.
4. PNI EC prekey ID, serialized public key, signature.
5. ACI last-resort KEM prekey ID, serialized public key, signature.
6. PNI last-resort KEM prekey ID, serialized public key, signature.

The actual existing validation limits apply: registration IDs are `1..16383`; key IDs are `0..2147483647` from `KeyIdUtil`. Some inherited prekey schema prose describes older bounds, so it must not be used to narrow the existing validator during this migration. Signatures have the existing 64-byte representation. Encoded JSON/base64 strings are never hashed.

The synthetic public-only fixture is `service/src/test/resources/admission/registration-key-commitment-v1.json`. It contains two public identity keys, four public prekeys and signatures, numeric IDs, the complete transcript, and its SHA-256 result:

`3b5817c63cb5ba35e0a6d1bd8b4323381de46a585b3f0ca52eb945cd831f8fd5`

The transcript is 3,662 bytes. Keys/signatures were generated with libsignal; framing and the expected digest were independently generated with Python `struct.pack` and `hashlib`. No private keys, account IDs, phone numbers, passwords, OTPs or production credentials are included. The fixture deliberately includes boundary key IDs and can be consumed by a later Swift parity test; Swift parity has not been verified by this server-only change.

The focused run passed 52 tests: 10 helper tests and 42 existing `RegistrationRequestTest` cases. Coverage includes the exact public fixture, repeated native serialization, changed valid keys/signatures/IDs, ACI/PNI ordering, missing phone-pilot fields, invalid signatures, malformed signature lengths and upstream numeric bounds. Evidence: root workspace `.local/registration-key-commitment-tests.log`, completed 2026-09-21T00:38:15Z.

This helper grants no admission authority and has no controller integration. It deliberately excludes session IDs, phone numbers, credentials and non-key account attributes. The complete-request HMAC, authoritative phone verification, persisted operation binding, pending-account confirmation and ongoing membership checks remain separate requirements. Registration routes remain closed.
