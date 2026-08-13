# ScopeRange Daily Runner

This package is a public-safe automation control plane. It contains no ScopeMatch application source, estimation logic, evidence, production target, credential, or pricing authority. The reusable inert shell remains registered and provider-disabled. The production schedule is now registered from the exact reviewed candidate at `.github/workflows/scoperange-daily.yml`, but its bridge configuration, external commit binding, and activation authorization remain false, and the workflow must remain disabled at the provider.

The registered production workflow is byte-for-byte identical to `inactive-production-daily-workflow.yml`. Its checked-in bridge stops before environment or secret access and therefore performs no private checkout, public request, database connection, or evidence write. The private execution package remains exact-commit-bound and evidence-only, while proposal review, promotion, rollback, live pricing, workflow execution, and activation remain unavailable.

The source lock identifies one immutable private commit and a deterministic five-file bundle without copying those files. A separately authorized future implementation would use a repository-scoped read-only deploy key, strict GitHub SSH host verification, an exact-commit fetch, source verification, and ephemeral cleanup. This package performs none of those network or credential operations.

Standard GitHub-hosted runners in a public repository are currently free, but that statement is conditional on public visibility and standard runners. Larger runners, artifacts, caches, packages, retries, and alternate triggers are excluded. Public scheduled workflows may be disabled after 60 days without repository activity, so recovery is fail-closed and never catches up automatically.

Credential provisioning, workflow enablement or invocation, production connection, evidence work, promotion, and public activation each require separate authorization.

## Activation-contract repair

The inactive candidate now models an external post-merge binding for the exact approved public commit. The binding is deliberately unconfigured: no commit is embedded into the commit that must approve itself, and no default-branch fallback is allowed. Dependency caching is explicitly disabled.

Recurrence is also contract-only. A future invocation would need a current bounded durable-lease receipt, an on-time schedule state, a fresh non-resumed invocation, a clear cancellation state, and a clear overlap state. No lease adapter, missed-run monitor, resume authority, or cancellation service is connected.

Future production identity requires short-lived claims for audience, repository and owner identity, protected ref, immutable workflow identity, scheduled event, exact commit, first attempt, and protected environment. Future target selection requires one provider-side target binding expressed through opaque digests, with raw target identifiers excluded from public configuration and logs. Both contracts are unconfigured, forbid broad or implicit fallback, and provide no connection or writer authority.

Operational output remains a fixed-schema zero-effect receipt. Unrecognized reason text and configuration values are never reflected into that receipt. Private checkout output, credential material, targets, customer data, evidence, and pricing data remain forbidden from public logs.

## Synthetic adapter gate

The credentialless source adapter can verify an exact bundle in a caller-supplied local Git object fixture. It returns only a fixed-schema verification receipt and never materializes source bytes, reads credentials, invokes a network operation, executes verified code, or exposes repository paths and commit identifiers. It is not imported by the bootstrap entry point or inactive workflow candidate.

The recurrence adapter uses a shared in-memory fixture store to exercise lease, overlap, missed-run, expiry, replay, cancellation, and resume behavior. The store is explicitly non-durable and synthetic-only. Its lease receipts are opaque digests, its rejection receipts do not reflect caller identifiers, and every adapter instance has zero network and production authority.

Neither adapter is configured, registered, or connected. They do not create a workflow, schedule, timer, credential, identity, target, writer, provider connection, production connection, ingestion path, promotion path, or pricing path.

## Synthetic authorization contracts

The identity verifier accepts only an Ed25519-signed synthetic receipt with the complete bounded workload claim set. It checks the issuer, audience, subject, immutable repository and owner identifiers, protected ref, exact workflow and workflow commit, scheduled event, first run attempt, environment, approved commit, source-lock digest, lease receipt, signature, five-minute lifetime, and one-use token identifier. Successful verification returns only an opaque claims digest and expiry. The verifier does not request an OIDC token, read a credential, contact GitHub, select an identity, or configure trust.

The target verifier accepts only an Ed25519-signed synthetic capability bound to that opaque identity verification, one provider-side account digest, one target digest, one evidence-envelope digest, the approved commit, source lock, lease, run, and idempotency binding. Its sole operation is `submit_evidence_envelope`; pricing, promotion, and live-price authority are fixed to none. Token and idempotency replay state is shared only inside an in-memory synthetic fixture.

Caller-supplied identity and target state strings are excluded from the bootstrap environment contract. The identity and target verifiers are not imported by the entry point or either workflow description. The production-connection interface is structurally disabled and returns a fixed zero-effect rejection for every connection-shaped input. No public key, private key, audience, environment, provider mapping, target, broker, endpoint, writer, or connection is configured.

A future production design would require a separately reviewed trust boundary to validate real workload identity, map it privately to exactly one evidence-only writer, and issue a one-use capability. This package does not implement or authorize that boundary.

## Metadata-only connection proof candidate

The package now includes a locally testable exact-commit fetch boundary, a closed non-secret authorization gate, a disabled child-process bridge, and `inactive-metadata-connection-proof-workflow.yml`. That candidate remains outside `.github/workflows/**`; it is not registered and has never been run. The already registered inert shell remains unchanged, provider-disabled, and has zero runs.

The candidate has no configured approved-commit binding, database target, provider identity, or production connection. Its checked-in entry exits before reading configuration, constructing a client, fetching private source, or attempting a network connection. The candidate explicitly disables package-manager caching, uses pinned action commits, permits only a manual trigger, and keeps acquisition, ingestion, promotion, recurrence, and pricing authority false.

The public `bootstrap/supabase-root-2021-ca.crt` artifact is the reviewed Supabase root CA used by the future bridge. Its PEM SHA-256 is `700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7`. The bridge verifies that digest, the certificate fingerprint, CA/self-issued identity, and current validity before private source fetch or child execution. It never downloads trust material at runtime, accepts no caller-supplied CA, and requires no CA secret. The inactive workflow still invokes only the disabled entry, so source presence creates no connection or execution authority.

Any future governance binding, private-source credential use, provider-level egress restriction, workflow registration, temporary database login window, proof run, cleanup, recurrence, or acquisition step requires its own review and explicit authorization. None is authorized by this source package.

## Minimum production runner candidate

The public package includes a registered, provider-disabled production workflow and bridge for the credentialless fetch, durable lease, and evidence-only writer implementation bound by `production-source-lock.example.json`. The registered file is identical to the retained inactive candidate; its external commit binding, bridge configuration, and activation authorization remain false, so its runner job cannot become eligible. No source target, database connection, evidence ingestion, proposal, promotion, or pricing authority is configured or activated.
