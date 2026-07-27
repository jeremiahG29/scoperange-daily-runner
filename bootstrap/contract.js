export const ACTIVATION_AUTHORIZED = false;

export const EXPECTED_REPOSITORY = "jeremiahG29/scoperange-daily-runner";
export const EXPECTED_WORKFLOW_REF = `${EXPECTED_REPOSITORY}/.github/workflows/scoperange-daily.yml@refs/heads/main`;
export const EXPECTED_SCHEDULE = "17 09 * * *";
export const EXPECTED_REF = "refs/heads/main";

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
  "PUBLIC_RUNNER_SOURCE_LOCK_DIGEST",
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
