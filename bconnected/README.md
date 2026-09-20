# BConnected messaging server

Personal fork for the Belen alumni pilot. This server is not deployed yet. The independent membership/directory APIs are deployed in the GCP project `roly-dev`; they do not relay encrypted messages.

Integration must enforce approved alumni status when creating/binding a Signal account and on subsequent authenticated operations. Existing sessions must lose access when membership is suspended. Do not rely on the iPhone approval screen for enforcement. The membership service currently has no Signal account-binding endpoint and must not be treated as a completed admission control for this server.

The current upstream sample configuration includes DynamoDB, FoundationDB, Redis, registration/push services and other dependencies; a GCP deployment requires an explicit plan for these dependencies. Do not copy upstream production endpoints or third-party credentials. The accompanying `remote-config.json` records the desired group-size settings, which must be applied using the server's actual remote-configuration mechanism. It is not automatically loaded.

Next validation: two independently registered approved accounts exchange end-to-end encrypted DMs and a group message on owned infrastructure; an unapproved account fails even through direct API calls. Only after that should the pilot expand to large-group load tests.
