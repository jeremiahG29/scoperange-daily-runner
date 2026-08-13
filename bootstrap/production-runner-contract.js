export const PRODUCTION_RUNNER_BRIDGE_CONFIGURED = false;
export const PRODUCTION_RUNNER_ACTIVATION_AUTHORIZED = false;

export const PRODUCTION_RUNNER_AUTHORITY = Object.freeze({
  recurrence: true,
  publicSourceFetch: true,
  evidenceWrite: true,
  proposal: false,
  review: false,
  promotion: false,
  rollback: false,
  livePricing: false
});

export const PRODUCTION_RUNNER_PRIVATE_BUNDLE = "scoperange/pricing-intelligence/production-runner";
export const PRODUCTION_RUNNER_AUTHORIZATION = "scoperange-production-runner-non-secret-gate-accepted-v1";

export const PRODUCTION_RUNNER_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-public-production-runner-contract-v1",
  configured: PRODUCTION_RUNNER_BRIDGE_CONFIGURED,
  activationAuthorized: PRODUCTION_RUNNER_ACTIVATION_AUTHORIZED,
  exactPublicCommitRequired: true,
  exactPrivateCommitRequired: true,
  credentiallessPublicFetchRequired: true,
  durableDatabaseLeaseRequired: true,
  evidenceOnlyWriterRequired: true,
  dependencyCacheAllowed: false,
  recognizedWorkflowPlacement: true,
  authority: PRODUCTION_RUNNER_AUTHORITY
});
