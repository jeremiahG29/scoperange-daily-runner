import crypto from "node:crypto";
import { isSyntheticIdentityVerification } from "./synthetic-identity-receipt.js";

const replayStores = new WeakMap();
const internalErrors = new WeakSet();
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const DECIMAL_ID = /^[1-9][0-9]{0,31}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9._:@/-]{1,256}$/u;
const CLAIM_KEYS = Object.freeze([
  "iss", "aud", "jti", "iat", "nbf", "exp", "identity_claims_digest",
  "provider_account_digest", "target_digest", "operation", "envelope_digest", "approved_commit",
  "source_lock_digest", "lease_receipt", "run_id", "run_attempt", "idempotency_key_digest",
  "target_count", "pricing_authority", "promotion_authority", "live_price_write_allowed"
]);
const EXPECTED_KEYS = Object.freeze([
  "issuer", "audience", "providerAccountDigest", "targetDigest", "operation", "envelopeDigest",
  "approvedCommit", "sourceLockDigest", "leaseReceipt", "runId", "runAttempt", "idempotencyKeyDigest"
]);

function fail(reasonCode) {
  const error = new Error(`SCOPERANGE_SYNTHETIC_TARGET_REJECTED:${reasonCode}`);
  internalErrors.add(error);
  throw error;
}

function hasExactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function claimsAreExpected(claims, expected, identityVerification) {
  if (!hasExactKeys(claims, CLAIM_KEYS) || !hasExactKeys(expected, EXPECTED_KEYS)) return false;
  if (claims.iss !== expected.issuer || claims.aud !== expected.audience
    || claims.identity_claims_digest !== identityVerification.identityClaimsDigest
    || claims.provider_account_digest !== expected.providerAccountDigest
    || claims.target_digest !== expected.targetDigest || claims.operation !== expected.operation
    || claims.envelope_digest !== expected.envelopeDigest || claims.approved_commit !== expected.approvedCommit
    || claims.source_lock_digest !== expected.sourceLockDigest || claims.lease_receipt !== expected.leaseReceipt
    || claims.run_id !== expected.runId || claims.run_attempt !== expected.runAttempt
    || claims.idempotency_key_digest !== expected.idempotencyKeyDigest) return false;
  return SAFE_TOKEN.test(claims.iss) && SAFE_TOKEN.test(claims.aud) && SAFE_TOKEN.test(claims.jti)
    && DIGEST.test(claims.identity_claims_digest) && DIGEST.test(claims.provider_account_digest)
    && DIGEST.test(claims.target_digest) && DIGEST.test(claims.envelope_digest)
    && DIGEST.test(claims.source_lock_digest) && DIGEST.test(claims.lease_receipt)
    && DIGEST.test(claims.idempotency_key_digest) && COMMIT.test(claims.approved_commit)
    && DECIMAL_ID.test(claims.run_id) && claims.run_attempt === "1"
    && claims.operation === "submit_evidence_envelope" && claims.target_count === 1
    && claims.pricing_authority === "none" && claims.promotion_authority === "none"
    && claims.live_price_write_allowed === false
    && Number.isInteger(claims.iat) && Number.isInteger(claims.nbf) && Number.isInteger(claims.exp);
}

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

export function createSyntheticTargetReplayStore() {
  const store = Object.freeze({
    schemaVersion: "scoperange-synthetic-target-replay-store-v1",
    storageKind: "shared_in_memory_fixture",
    productionAuthority: "none"
  });
  replayStores.set(store, { tokenDigests: new Set(), idempotencyDigests: new Set() });
  return store;
}

function verifyTargetCapability({
  capability,
  publicKey,
  replayStore,
  identityVerification,
  expected,
  now
} = {}) {
  if (!hasExactKeys(capability, ["schemaVersion", "claims", "signature"])
    || capability.schemaVersion !== "scoperange-synthetic-target-capability-v1"
    || !capability.claims || typeof capability.claims !== "object" || Array.isArray(capability.claims)
    || !SIGNATURE.test(capability.signature ?? "")) fail("envelope_rejected");
  if (!(publicKey instanceof crypto.KeyObject)
    || publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail("public_key_rejected");
  const payload = Buffer.from(JSON.stringify(ordered({
    claims: capability.claims,
    schemaVersion: capability.schemaVersion
  })), "utf8");
  const signature = Buffer.from(capability.signature, "base64url");
  if (signature.length !== 64 || !crypto.verify(null, payload, publicKey, signature)) fail("signature_rejected");

  const claims = capability.claims;
  if (!isSyntheticIdentityVerification(identityVerification)) fail("identity_rejected");
  if (!claimsAreExpected(claims, expected, identityVerification)) fail("claims_rejected");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) fail("time_rejected");
  const identityExpiresAt = new Date(identityVerification.expiresAt ?? "");
  if (!Number.isFinite(identityExpiresAt.valueOf())
    || identityExpiresAt.toISOString() !== identityVerification.expiresAt
    || identityExpiresAt.valueOf() <= now.valueOf()
    || claims.exp * 1000 > identityExpiresAt.valueOf()) fail("identity_rejected");
  const nowSeconds = Math.floor(now.valueOf() / 1000);
  if (claims.nbf > claims.iat || claims.iat > nowSeconds || claims.nbf > nowSeconds
    || claims.exp <= nowSeconds || claims.exp <= claims.iat
    || claims.exp - claims.iat > 300 || nowSeconds - claims.iat > 300) fail("time_rejected");
  const consumedCapabilities = replayStores.get(replayStore);
  if (!consumedCapabilities) fail("replay_store_rejected");
  const capabilityTokenDigest = crypto.createHash("sha256").update(claims.jti, "utf8").digest("hex");
  if (consumedCapabilities.tokenDigests.has(capabilityTokenDigest)) fail("replay_rejected");
  if (consumedCapabilities.idempotencyDigests.has(claims.idempotency_key_digest)) fail("idempotency_rejected");
  consumedCapabilities.tokenDigests.add(capabilityTokenDigest);
  consumedCapabilities.idempotencyDigests.add(claims.idempotency_key_digest);
  const targetCapabilityDigest = `sha256:${crypto.createHash("sha256")
    .update(JSON.stringify(ordered(claims)), "utf8").digest("hex")}`;
  return Object.freeze({
    schemaVersion: "scoperange-synthetic-target-verification-v1",
    disposition: "verified_synthetic_target_capability",
    identityClaimsDigest: identityVerification.identityClaimsDigest,
    targetCapabilityDigest,
    expiresAt: new Date(claims.exp * 1000).toISOString(),
    operation: claims.operation,
    targetCount: claims.target_count,
    credentialReads: 0,
    networkAttempts: 0,
    providerConnections: 0,
    databaseConnections: 0,
    pricingAuthority: "none",
    promotionAuthority: "none",
    productionAuthority: "none"
  });
}

export function verifySyntheticTargetCapability(input) {
  try {
    return verifyTargetCapability(input);
  } catch (error) {
    if (internalErrors.has(error)) throw error;
    fail("input_rejected");
  }
}
