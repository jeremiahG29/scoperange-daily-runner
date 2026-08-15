import crypto from "node:crypto";

export const APPROVED_INITIAL_SOURCE_PLAN = Object.freeze({
  schemaVersion: "scoperange-public-source-plan-v1",
  sourceId: "src-atlanta-door-refinishing-blog",
  url: "https://atlantadoorrefinishing.com/blog/how-much-does-door-refinishing-cost-in-atlanta",
  publisher: "Atlanta Door Refinishing",
  sourceClass: "direct_contractor_published_pricing",
  trade: "painting",
  scopeFamily: "exterior-door",
  geographyLayer: "city_cluster",
  geographyCell: "atlanta",
  jobMode: "refinish",
  unitFamily: "item",
  priceType: "whole_job",
  discoveryPath: "approved_initial_recheck",
  lineageClusterId: "cluster-atlanta-door-refinishing",
  accessMethod: "public_page",
  robotsStatus: "allowed",
  termsStatus: "public_page_no_acceptance",
  maxBytes: 500_000,
  maxRedirects: 3,
  timeoutMs: 8_000
});

const BUDGETS = Object.freeze({
  maxCells: 1,
  maxSources: 1,
  maxRequests: 1,
  timeoutMs: APPROVED_INITIAL_SOURCE_PLAN.timeoutMs,
  maxBytes: APPROVED_INITIAL_SOURCE_PLAN.maxBytes,
  maxRedirects: APPROVED_INITIAL_SOURCE_PLAN.maxRedirects,
  maxRetries: 1,
  maxConcurrency: 1,
  minIntervalMs: 0,
  leaseMs: 600_000
});

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

function digest(value) {
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(ordered(value)), "utf8").digest("hex")}`;
}

function required(environment, key) {
  const value = environment?.[key];
  if (typeof value !== "string" || !value || value.includes("\0")) {
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_CONFIGURATION_REJECTED");
  }
  return value;
}

export function createApprovedProductionInput({ environment, observedAt, randomBytesImpl = crypto.randomBytes } = {}) {
  const observed = new Date(observedAt);
  if (!Number.isFinite(observed.valueOf()) || observed.toISOString() !== observedAt
    || typeof randomBytesImpl !== "function") {
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_CONFIGURATION_REJECTED");
  }
  const leaseBytes = randomBytesImpl(32);
  if (!Buffer.isBuffer(leaseBytes) || leaseBytes.length !== 32) {
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_CONFIGURATION_REJECTED");
  }
  const triggerEventName = required(environment, "SCOPERANGE_TRIGGER_EVENT_NAME");
  const triggerRunId = required(environment, "SCOPERANGE_TRIGGER_RUN_ID");
  if (!/^[1-9][0-9]{0,19}$/u.test(triggerRunId)
    || !["schedule", "workflow_dispatch"].includes(triggerEventName)) {
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_CONFIGURATION_REJECTED");
  }
  const day = observedAt.slice(0, 10);
  const manualRecovery = triggerEventName === "workflow_dispatch";
  const scheduledFor = manualRecovery ? observedAt : `${day}T09:17:00.000Z`;
  const runId = manualRecovery ? `manual:${triggerRunId}` : `daily:${day}`;

  return Object.freeze({
    schemaVersion: "scoperange-production-runner-input-v1",
    plan: APPROVED_INITIAL_SOURCE_PLAN,
    runId,
    workItemId: `${runId}:${APPROVED_INITIAL_SOURCE_PLAN.sourceId}`,
    coverageCellId: "coverage:painting:exterior-door:v1",
    ownerId: "public-runner-v1",
    leaseToken: `lease:v1:${leaseBytes.toString("hex")}`,
    scheduledFor,
    catalogCreatedAt: "2026-07-24T00:00:00.000Z",
    observedAt,
    planDigest: digest(APPROVED_INITIAL_SOURCE_PLAN),
    schedulePolicyVersion: manualRecovery
      ? "scoperange-pricing-intelligence-manual-recovery-policy-v1"
      : "scoperange-pricing-intelligence-schedule-policy-v1",
    budgets: BUDGETS,
    database: Object.freeze({
      host: required(environment, "SCOPERANGE_DB_HOST"),
      port: required(environment, "SCOPERANGE_DB_PORT") === "6543" ? 6543 : NaN,
      database: required(environment, "SCOPERANGE_DB_NAME"),
      user: required(environment, "SCOPERANGE_DB_USER"),
      password: required(environment, "SCOPERANGE_DB_PASSWORD"),
      tlsServerName: required(environment, "SCOPERANGE_DB_TLS_SERVER_NAME"),
      applicationName: "scoperange-intelligence-production-v1",
      maxConnections: 1,
      connectionTimeoutMs: 5_000,
      idleTimeoutMs: 5_000,
      statementTimeoutMs: 10_000,
      lockTimeoutMs: 5_000,
      configurationVersion: required(environment, "SCOPERANGE_CONFIG_VERSION"),
      credentialVersion: required(environment, "SCOPERANGE_CREDENTIAL_VERSION"),
      credentialNotBefore: required(environment, "SCOPERANGE_CREDENTIAL_NOT_BEFORE"),
      credentialExpiresAt: required(environment, "SCOPERANGE_CREDENTIAL_EXPIRES_AT"),
      expectedProjectRefDigest: required(environment, "SCOPERANGE_EXPECTED_PROJECT_DIGEST")
    })
  });
}
