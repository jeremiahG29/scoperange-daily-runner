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
  schemaVersion: "scoperange-production-identity-claims-v2",
  requiredClaims: Object.freeze([
    "iss",
    "aud",
    "sub",
    "jti",
    "iat",
    "nbf",
    "exp",
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "repository_visibility",
    "ref",
    "ref_type",
    "workflow_ref",
    "workflow_sha",
    "event_name",
    "event_schedule",
    "sha",
    "run_id",
    "run_attempt",
    "runner_environment",
    "environment",
    "approved_commit",
    "source_lock_digest",
    "lease_receipt"
  ]),
  shortLivedIdentityRequired: true,
  maximumReceiptSeconds: 300,
  signatureAlgorithm: "Ed25519",
  immutableRepositoryIdsRequired: true,
  workflowShaRequired: true,
  replayProtectionRequired: true,
  broadFallbackAllowed: false,
  syntheticVerifierConfigured: false,
  configured: false
});

export const TARGET_BINDING_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-exact-target-binding-v2",
  requiredClaims: Object.freeze([
    "iss",
    "aud",
    "jti",
    "iat",
    "nbf",
    "exp",
    "identity_claims_digest",
    "provider_account_digest",
    "target_digest",
    "operation",
    "envelope_digest",
    "approved_commit",
    "source_lock_digest",
    "lease_receipt",
    "run_id",
    "run_attempt",
    "idempotency_key_digest",
    "target_count",
    "pricing_authority",
    "promotion_authority",
    "live_price_write_allowed"
  ]),
  exactTargetCount: 1,
  signedCapabilityRequired: true,
  signatureAlgorithm: "Ed25519",
  maximumCapabilitySeconds: 300,
  replayProtectionRequired: true,
  identityReceiptBindingRequired: true,
  evidenceEnvelopeDigestRequired: true,
  leaseBindingRequired: true,
  approvedCommitBindingRequired: true,
  idempotencyRequired: true,
  allowedOperation: "submit_evidence_envelope",
  providerSideBindingRequired: true,
  rawConnectionStringAllowed: false,
  implicitTargetAllowed: false,
  callerOverrideAllowed: false,
  pricingAuthority: false,
  promotionAuthority: false,
  configured: false,
  writerConnected: false
});

export const PRODUCTION_CONNECTION_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-production-connection-v1",
  transport: "disabled",
  networkAllowed: false,
  redirectsAllowed: false,
  rawTargetIdentifierAllowed: false,
  rawConnectionStringAllowed: false,
  credentialLookupAllowed: false,
  directDatabaseConnectionAllowed: false,
  dataApiConnectionAllowed: false,
  identityTokenExchangeConfigured: false,
  providerTargetConfigured: false,
  connectionAdapterConfigured: false,
  writerConnected: false,
  secretReads: 0,
  networkAttempts: 0,
  providerConnections: 0,
  databaseConnections: 0,
  productionAuthority: "none"
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
  "PUBLIC_RUNNER_LIFECYCLE_STATE"
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
