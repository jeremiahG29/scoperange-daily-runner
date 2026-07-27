# ScopeRange Daily Runner

This package is an inert, public-safe automation control-plane scaffold. It contains no ScopeMatch application source, estimation logic, evidence, production target, credential, or pricing authority. The workflow file is a non-registered model; the only bootstrap path is a non-secret gate whose activation remains hard-coded off.

The source lock identifies one immutable private commit and a deterministic five-file bundle without copying those files. A separately authorized future implementation would use a repository-scoped read-only deploy key, strict GitHub SSH host verification, an exact-commit fetch, source verification, and ephemeral cleanup. This package performs none of those network or credential operations.

Standard GitHub-hosted runners in a public repository are currently free, but that statement is conditional on public visibility and standard runners. Larger runners, artifacts, caches, packages, retries, and alternate triggers are excluded. Public scheduled workflows may be disabled after 60 days without repository activity, so recovery is fail-closed and never catches up automatically.

Repository creation, governance settings, credential provisioning, workflow registration, production connection, evidence work, promotion, and public activation each require separate authorization.
