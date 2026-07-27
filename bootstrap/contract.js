export const ACTIVATION_AUTHORIZED = false;

export const EXPECTED_REPOSITORY = "jeremiahG29/scoperange-daily-runner";
export const EXPECTED_WORKFLOW_REF = `${EXPECTED_REPOSITORY}/.github/workflows/scoperange-daily.yml@refs/heads/main`;
export const EXPECTED_SCHEDULE = "17 09 * * *";
export const EXPECTED_REF = "refs/heads/main";

export const APPROVED_COMMIT_BINDING_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-approved-public-commit-binding-v1",
  source: "external_post_merge_governance",
  exactCommitRequired: true,
  embeddedSelfHashAllowed: false,
  defaultBranchFallbackAllowed: false,
  configured: false
});

export const RECURRENCE_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-public-runner-recurrence-v1",
  durableLeaseRequired: true,
  maximumLeaseSeconds: 600,
  missedRunCatchUpAllowed: false,
  implicitResumeAllowed: false,
  cancellationMustFailClosed: true,
  overlapMustFailClosed: true,
  adapterConfigured: false
});

export const PRODUCTION_IDENTITY_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-production-identity-claims-v1",
  requiredClaims: Object.freeze([
    "audience",
    "repository_id",
    "repository_owner_id",
    "ref",
    "workflow_ref",
    "event_name",
    "sha",
    "run_attempt",
    "environment"
  ]),
  shortLivedIdentityRequired: true,
  broadFallbackAllowed: false,
  configured: false
});

export const TARGET_BINDING_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-exact-target-binding-v1",
  requiredClaims: Object.freeze(["provider_account_digest", "target_digest", "identity_claims_digest"]),
  exactTargetCount: 1,
  providerSideBindingRequired: true,
  rawConnectionStringAllowed: false,
  implicitTargetAllowed: false,
  callerOverrideAllowed: false,
  configured: false,
  writerConnected: false
});

export const SAFE_REASON_CODES = Object.freeze([
  "runner_disabled",
  "configuration_unreadable",
  "repository_rejected",
  "workflow_path_rejected",
  "event_rejected",
  "schedule_rejected",
  "default_branch_rejected",
  "rerun_forbidden",
  "approved_commit_binding_unverified",
  "runner_commit_unapproved",
  "source_lock_mismatch",
  "lease_not_held",
  "lease_receipt_rejected",
  "lease_window_rejected",
  "missed_run_no_catch_up",
  "resume_not_authorized",
  "invocation_cancelled",
  "active_overlap",
  "identity_contract_unconfigured",
  "identity_unverified",
  "target_contract_unconfigured",
  "target_unbound",
  "timing_rejected",
  "schedule_not_due",
  "activation_not_authorized",
  "unknown_rejection"
]);

export const CONFIGURATION_KEYS = Object.freeze([
  "PUBLIC_RUNNER_MODE",
  "PUBLIC_RUNNER_REPOSITORY",
  "PUBLIC_RUNNER_EXPECTED_REPOSITORY",
  "PUBLIC_RUNNER_WORKFLOW_REF",
  "PUBLIC_RUNNER_EVENT_NAME",
  "PUBLIC_RUNNER_EVENT_SCHEDULE",
  "PUBLIC_RUNNER_REF",
  "PUBLIC_RUNNER_RUN_ATTEMPT",
  "PUBLIC_RUNNER_COMMIT",
  "PUBLIC_RUNNER_APPROVED_COMMIT",
  "PUBLIC_RUNNER_APPROVED_COMMIT_BINDING_STATE",
  "PUBLIC_RUNNER_SOURCE_LOCK_DIGEST",
  "PUBLIC_RUNNER_LEASE_STATE",
  "PUBLIC_RUNNER_LEASE_RECEIPT",
  "PUBLIC_RUNNER_LEASE_EXPIRES_AT",
  "PUBLIC_RUNNER_MISSED_RUN_STATE",
  "PUBLIC_RUNNER_RESUME_STATE",
  "PUBLIC_RUNNER_CANCELLATION_STATE",
  "PUBLIC_RUNNER_OVERLAP_STATE",
  "PUBLIC_RUNNER_LIFECYCLE_STATE",
  "PUBLIC_RUNNER_IDENTITY_STATE",
  "PUBLIC_RUNNER_TARGET_BINDING_STATE"
]);

export const ZERO_EFFECTS = Object.freeze({
  secretReads: 0,
  sourceCheckoutAttempts: 0,
  networkAttempts: 0,
  providerConnections: 0,
  databaseConnections: 0,
  acquisitionEffects: 0,
  ingestionEffects: 0,
  reviewEffects: 0,
  promotionEffects: 0,
  rollbackEffects: 0,
  pricingEffects: 0
});
