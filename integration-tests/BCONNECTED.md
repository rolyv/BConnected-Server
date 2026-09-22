# Legacy integration harness

This upstream module is excluded from the default BConnected reactor and is not
an accepted GCP test harness. Its configuration and `IntegrationTools` still target
legacy DynamoDB stores and excluded donation/recovery operations. It also retains
references to stores removed from the supported server, including
`VerificationSessions` and `ChangeNumberWaitingPeriods`.

Do not run this harness against the pilot or interpret default service compilation
as validation of this module. Required registration and waiting-period behavior
is retained in the service tests using disposable PostgreSQL databases. Migrating
or removing the remaining AWS harness belongs to the final AWS tooling cleanup.
