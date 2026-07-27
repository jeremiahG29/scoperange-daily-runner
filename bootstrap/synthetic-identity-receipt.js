import crypto from "node:crypto";

const replayStores = new WeakMap();
const verifiedIdentities = new WeakSet();
const internalErrors = new WeakSet();
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const DECIMAL_ID = /^[1-9][0-9]{0,31}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9._:@/-]{1,256}$/u;
const CLAIM_KEYS = Object.freeze([
  "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "repository", "repository_id",
  "repository_owner", "repository_owner_id", "repository_visibility", "ref", "ref_type",
  "workflow_ref", "workflow_sha", "event_name", "event_schedule", "sha", "run_id", "run_attempt",
  "runner_environment", "environment", "approved_commit", "source_lock_digest", "lease_receipt"
]);
const EXPECTED_KEYS = Object.freeze([
  "issuer", "audience", "subject", "repository", "repositoryId", "repositoryOwner",
  "repositoryOwnerId", "repositoryVisibility", "ref", "refType", "workflowRef", "workflowSha",
  "eventName", "eventSchedule", "commit", "runAttempt", "runnerEnvironment", "environment",
  "approvedCommit", "sourceLockDigest", "leaseReceipt"
]);

function fail(reasonCode) {
  const error = new Error(`SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:${reasonCode}`);
  internalErrors.add(error);
  throw error;
}

function hasExactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function claimsAreExpected(claims, expected) {
  if (!hasExactKeys(claims, CLAIM_KEYS) || !hasExactKeys(expected, EXPECTED_KEYS)) return false;
  if (claims.iss !== "https://token.actions.githubusercontent.com" || claims.iss !== expected.issuer
    || claims.aud !== expected.audience || claims.sub !== expected.subject
    || claims.repository !== expected.repository || claims.repository_id !== expected.repositoryId
    || claims.repository_owner !== expected.repositoryOwner
    || claims.repository_owner_id !== expected.repositoryOwnerId
    || claims.repository_visibility !== expected.repositoryVisibility
    || claims.ref !== expected.ref || claims.ref_type !== expected.refType
    || claims.workflow_ref !== expected.workflowRef || claims.workflow_sha !== expected.workflowSha
    || claims.event_name !== expected.eventName || claims.event_schedule !== expected.eventSchedule
    || claims.sha !== expected.commit || claims.run_attempt !== expected.runAttempt
    || claims.runner_environment !== expected.runnerEnvironment || claims.environment !== expected.environment
    || claims.approved_commit !== expected.approvedCommit
    || claims.source_lock_digest !== expected.sourceLockDigest || claims.lease_receipt !== expected.leaseReceipt) {
    return false;
  }
  return SAFE_TOKEN.test(claims.aud) && SAFE_TOKEN.test(claims.sub) && SAFE_TOKEN.test(claims.jti)
    && SAFE_TOKEN.test(claims.repository) && SAFE_TOKEN.test(claims.repository_owner)
    && SAFE_TOKEN.test(claims.workflow_ref) && SAFE_TOKEN.test(claims.environment)
    && DECIMAL_ID.test(claims.repository_id) && DECIMAL_ID.test(claims.repository_owner_id)
    && DECIMAL_ID.test(claims.run_id) && claims.repository_visibility === "public"
    && claims.ref === "refs/heads/main" && claims.ref_type === "branch"
    && claims.event_name === "schedule" && claims.run_attempt === "1"
    && claims.runner_environment === "github-hosted"
    && COMMIT.test(claims.workflow_sha) && COMMIT.test(claims.sha) && COMMIT.test(claims.approved_commit)
    && claims.workflow_sha === claims.sha && claims.sha === claims.approved_commit
    && DIGEST.test(claims.source_lock_digest) && DIGEST.test(claims.lease_receipt)
    && Number.isInteger(claims.iat) && Number.isInteger(claims.nbf) && Number.isInteger(claims.exp);
}

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

export function createSyntheticIdentityReplayStore() {
  const store = Object.freeze({
    schemaVersion: "scoperange-synthetic-identity-replay-store-v1",
    storageKind: "shared_in_memory_fixture",
    productionAuthority: "none"
  });
  replayStores.set(store, new Set());
  return store;
}

export function isSyntheticIdentityVerification(value) {
  return Boolean(value && typeof value === "object" && verifiedIdentities.has(value));
}

function verifyIdentityReceipt({ envelope, publicKey, replayStore, expected, now } = {}) {
  if (!hasExactKeys(envelope, ["schemaVersion", "claims", "signature"])
    || envelope.schemaVersion !== "scoperange-synthetic-identity-receipt-v1"
    || !envelope.claims || typeof envelope.claims !== "object" || Array.isArray(envelope.claims)
    || !SIGNATURE.test(envelope.signature ?? "")) fail("envelope_rejected");
  if (!(publicKey instanceof crypto.KeyObject)
    || publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail("public_key_rejected");

  const payload = Buffer.from(JSON.stringify(ordered({
    claims: envelope.claims,
    schemaVersion: envelope.schemaVersion
  })), "utf8");
  const signature = Buffer.from(envelope.signature, "base64url");
  if (signature.length !== 64 || !crypto.verify(null, payload, publicKey, signature)) fail("signature_rejected");

  const claims = envelope.claims;
  if (!claimsAreExpected(claims, expected)) fail("claims_rejected");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) fail("time_rejected");
  const nowSeconds = Math.floor(now.valueOf() / 1000);
  if (claims.nbf > claims.iat || claims.iat > nowSeconds || claims.nbf > nowSeconds
    || claims.exp <= nowSeconds || claims.exp <= claims.iat
    || claims.exp - claims.iat > 300 || nowSeconds - claims.iat > 300) fail("time_rejected");
  const consumedTokens = replayStores.get(replayStore);
  if (!consumedTokens) fail("replay_store_rejected");
  const tokenDigest = crypto.createHash("sha256").update(claims.jti, "utf8").digest("hex");
  if (consumedTokens.has(tokenDigest)) fail("replay_rejected");
  consumedTokens.add(tokenDigest);
  const identityClaimsDigest = `sha256:${crypto.createHash("sha256")
    .update(JSON.stringify(ordered(claims)), "utf8").digest("hex")}`;
  const verification = Object.freeze({
    schemaVersion: "scoperange-synthetic-identity-verification-v1",
    disposition: "verified_synthetic_identity",
    identityClaimsDigest,
    expiresAt: new Date(claims.exp * 1000).toISOString(),
    credentialReads: 0,
    networkAttempts: 0,
    productionAuthority: "none"
  });
  verifiedIdentities.add(verification);
  return verification;
}

export function verifySyntheticIdentityReceipt(input) {
  try {
    return verifyIdentityReceipt(input);
  } catch (error) {
    if (internalErrors.has(error)) throw error;
    fail("input_rejected");
  }
}
