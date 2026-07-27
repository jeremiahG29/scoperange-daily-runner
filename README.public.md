# ScopeRange Daily Runner

This package is an inert, public-safe automation control-plane scaffold. It contains no ScopeMatch application source, estimation logic, evidence, production target, credential, or pricing authority. One reusable-workflow shell is registered with no inputs, outputs, secrets, or token permissions; its only job is unconditionally skipped, fails defensively if that guard is removed, and must remain disabled at the provider. The scheduled workflow remains a non-registered model, and the bootstrap path is not invoked by the registered shell.

The source lock identifies one immutable private commit and a deterministic five-file bundle without copying those files. A separately authorized future implementation would use a repository-scoped read-only deploy key, strict GitHub SSH host verification, an exact-commit fetch, source verification, and ephemeral cleanup. This package performs none of those network or credential operations.

Standard GitHub-hosted runners in a public repository are currently free, but that statement is conditional on public visibility and standard runners. Larger runners, artifacts, caches, packages, retries, and alternate triggers are excluded. Public scheduled workflows may be disabled after 60 days without repository activity, so recovery is fail-closed and never catches up automatically.

Credential provisioning, workflow enablement or invocation, production connection, evidence work, promotion, and public activation each require separate authorization.
