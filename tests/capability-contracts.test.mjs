import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

function canonical(value) {
  return JSON.stringify(ordered(value));
}

function signEnvelope({ schemaVersion, claims }, privateKey) {
  const payload = Buffer.from(canonical({ claims, schemaVersion }), "utf8");
  return Object.freeze({
    schemaVersion,
    claims: Object.freeze({ ...claims }),
    signature: crypto.sign(null, payload, privateKey).toString("base64url")
  });
}

const now = new Date("2026-07-27T12:00:00.000Z");
const nowSeconds = Math.floor(now.valueOf() / 1000);
const approvedCommit = "a".repeat(40);
const sourceLockDigest = `sha256:${"b".repeat(64)}`;
const leaseReceipt = `sha256:${"c".repeat(64)}`;

const expectedIdentity = Object.freeze({
  issuer: "https://token.actions.githubusercontent.com",
  audience: "urn:scoperange:synthetic-ingress",
  subject: "repo:synthetic-owner@100/synthetic-repo@200:environment:synthetic-ingress",
  repository: "synthetic-owner/synthetic-repo",
  repositoryId: "200",
  repositoryOwner: "synthetic-owner",
  repositoryOwnerId: "100",
  repositoryVisibility: "public",
  ref: "refs/heads/main",
  refType: "branch",
  workflowRef: "synthetic-owner/synthetic-repo/.github/workflows/scoperange-daily.yml@refs/heads/main",
  workflowSha: approvedCommit,
  eventName: "schedule",
  eventSchedule: "17 09 * * *",
  commit: approvedCommit,
  runAttempt: "1",
  runnerEnvironment: "github-hosted",
  environment: "synthetic-ingress",
  approvedCommit,
  sourceLockDigest,
  leaseReceipt
});

function identityClaims(overrides = {}) {
  return {
    iss: expectedIdentity.issuer,
    aud: expectedIdentity.audience,
    sub: expectedIdentity.subject,
    jti: "synthetic-token-1",
    iat: nowSeconds - 30,
    nbf: nowSeconds - 30,
    exp: nowSeconds + 120,
    repository: expectedIdentity.repository,
    repository_id: expectedIdentity.repositoryId,
    repository_owner: expectedIdentity.repositoryOwner,
    repository_owner_id: expectedIdentity.repositoryOwnerId,
    repository_visibility: expectedIdentity.repositoryVisibility,
    ref: expectedIdentity.ref,
    ref_type: expectedIdentity.refType,
    workflow_ref: expectedIdentity.workflowRef,
    workflow_sha: expectedIdentity.workflowSha,
    event_name: expectedIdentity.eventName,
    event_schedule: expectedIdentity.eventSchedule,
    sha: expectedIdentity.commit,
    run_id: "300",
    run_attempt: expectedIdentity.runAttempt,
    runner_environment: expectedIdentity.runnerEnvironment,
    environment: expectedIdentity.environment,
    approved_commit: expectedIdentity.approvedCommit,
    source_lock_digest: expectedIdentity.sourceLockDigest,
    lease_receipt: expectedIdentity.leaseReceipt,
    ...overrides
  };
}

async function loadIdentityVerifier() {
  try {
    return await import("../bootstrap/synthetic-identity-receipt.js");
  } catch {
    return {};
  }
}

async function loadTargetVerifier() {
  try {
    return await import("../bootstrap/synthetic-target-capability.js");
  } catch {
    return {};
  }
}

async function loadDisabledConnection() {
  try {
    return await import("../bootstrap/disabled-production-connection.js");
  } catch {
    return {};
  }
}

async function createVerifiedIdentity() {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const envelope = signEnvelope({
    schemaVersion: "scoperange-synthetic-identity-receipt-v1",
    claims: identityClaims()
  }, privateKey);
  return identity.verifySyntheticIdentityReceipt({
    envelope,
    publicKey,
    replayStore: identity.createSyntheticIdentityReplayStore(),
    expected: expectedIdentity,
    now
  });
}

const providerAccountDigest = `sha256:${"d".repeat(64)}`;
const targetDigest = `sha256:${"e".repeat(64)}`;
const envelopeDigest = `sha256:${"f".repeat(64)}`;
const idempotencyKeyDigest = `sha256:${"1".repeat(64)}`;

const expectedTarget = Object.freeze({
  issuer: "urn:scoperange:synthetic-ingress",
  audience: "urn:scoperange:synthetic-evidence-writer",
  providerAccountDigest,
  targetDigest,
  operation: "submit_evidence_envelope",
  envelopeDigest,
  approvedCommit,
  sourceLockDigest,
  leaseReceipt,
  runId: "300",
  runAttempt: "1",
  idempotencyKeyDigest
});

function targetClaims(identityClaimsDigest, overrides = {}) {
  return {
    iss: expectedTarget.issuer,
    aud: expectedTarget.audience,
    jti: "synthetic-capability-1",
    iat: nowSeconds - 15,
    nbf: nowSeconds - 15,
    exp: nowSeconds + 120,
    identity_claims_digest: identityClaimsDigest,
    provider_account_digest: expectedTarget.providerAccountDigest,
    target_digest: expectedTarget.targetDigest,
    operation: expectedTarget.operation,
    envelope_digest: expectedTarget.envelopeDigest,
    approved_commit: expectedTarget.approvedCommit,
    source_lock_digest: expectedTarget.sourceLockDigest,
    lease_receipt: expectedTarget.leaseReceipt,
    run_id: expectedTarget.runId,
    run_attempt: expectedTarget.runAttempt,
    idempotency_key_digest: expectedTarget.idempotencyKeyDigest,
    target_count: 1,
    pricing_authority: "none",
    promotion_authority: "none",
    live_price_write_allowed: false,
    ...overrides
  };
}

test("a complete signed synthetic workload produces an opaque identity verification", async () => {
  const identity = await loadIdentityVerifier();
  assert.equal(typeof identity.verifySyntheticIdentityReceipt, "function");
  assert.equal(typeof identity.createSyntheticIdentityReplayStore, "function");

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const claims = identityClaims();
  const envelope = signEnvelope({
    schemaVersion: "scoperange-synthetic-identity-receipt-v1",
    claims
  }, privateKey);
  const verification = identity.verifySyntheticIdentityReceipt({
    envelope,
    publicKey,
    replayStore: identity.createSyntheticIdentityReplayStore(),
    expected: expectedIdentity,
    now
  });
  const identityClaimsDigest = `sha256:${crypto.createHash("sha256").update(canonical(claims), "utf8").digest("hex")}`;

  assert.deepEqual(verification, {
    schemaVersion: "scoperange-synthetic-identity-verification-v1",
    disposition: "verified_synthetic_identity",
    identityClaimsDigest,
    expiresAt: "2026-07-27T12:02:00.000Z",
    credentialReads: 0,
    networkAttempts: 0,
    productionAuthority: "none"
  });
  const serialized = JSON.stringify(verification);
  assert.equal(serialized.includes(claims.repository), false);
  assert.equal(serialized.includes(claims.sub), false);
  assert.equal(serialized.includes(claims.jti), false);
  assert.equal(serialized.includes(claims.run_id), false);
});

test("identity verification rejects a claim changed after signing", async () => {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signEnvelope({
    schemaVersion: "scoperange-synthetic-identity-receipt-v1",
    claims: identityClaims()
  }, privateKey);
  const tampered = {
    ...signed,
    claims: { ...signed.claims, aud: "urn:synthetic:tampered" }
  };

  assert.throws(() => identity.verifySyntheticIdentityReceipt({
    envelope: tampered,
    publicKey,
    replayStore: identity.createSyntheticIdentityReplayStore(),
    expected: expectedIdentity,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:signature_rejected"
  });
});

test("identity verification rejects unsigned top-level envelope metadata", async () => {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signEnvelope({
    schemaVersion: "scoperange-synthetic-identity-receipt-v1",
    claims: identityClaims()
  }, privateKey);

  assert.throws(() => identity.verifySyntheticIdentityReceipt({
    envelope: { ...signed, unsigned_metadata: "synthetic-canary" },
    publicKey,
    replayStore: identity.createSyntheticIdentityReplayStore(),
    expected: expectedIdentity,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:envelope_rejected"
  });
});

test("identity verification rejects incomplete, extra, or mismatched workload claims", async () => {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const missingWorkflowSha = identityClaims();
  delete missingWorkflowSha.workflow_sha;

  for (const [claims, expected] of [
    [missingWorkflowSha, expectedIdentity],
    [identityClaims({ unexpected_claim: "synthetic-canary" }), expectedIdentity],
    [identityClaims(), { ...expectedIdentity, audience: "urn:synthetic:wrong-audience" }]
  ]) {
    const envelope = signEnvelope({
      schemaVersion: "scoperange-synthetic-identity-receipt-v1",
      claims
    }, privateKey);
    assert.throws(() => identity.verifySyntheticIdentityReceipt({
      envelope,
      publicKey,
      replayStore: identity.createSyntheticIdentityReplayStore(),
      expected,
      now
    }), {
      message: "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:claims_rejected"
    });
  }
});

test("identity verification rejects expired, future, and overlong receipts", async () => {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

  for (const overrides of [
    { iat: nowSeconds - 180, nbf: nowSeconds - 180, exp: nowSeconds },
    { iat: nowSeconds, nbf: nowSeconds + 1, exp: nowSeconds + 120 },
    { iat: nowSeconds - 301, nbf: nowSeconds - 301, exp: nowSeconds + 1 }
  ]) {
    const envelope = signEnvelope({
      schemaVersion: "scoperange-synthetic-identity-receipt-v1",
      claims: identityClaims(overrides)
    }, privateKey);
    assert.throws(() => identity.verifySyntheticIdentityReceipt({
      envelope,
      publicKey,
      replayStore: identity.createSyntheticIdentityReplayStore(),
      expected: expectedIdentity,
      now
    }), {
      message: "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:time_rejected"
    });
  }
});

test("identity verification consumes each signed token identifier once", async () => {
  const identity = await loadIdentityVerifier();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const envelope = signEnvelope({
    schemaVersion: "scoperange-synthetic-identity-receipt-v1",
    claims: identityClaims()
  }, privateKey);
  const replayStore = identity.createSyntheticIdentityReplayStore();
  const input = { envelope, publicKey, replayStore, expected: expectedIdentity, now };

  identity.verifySyntheticIdentityReceipt(input);
  assert.throws(() => identity.verifySyntheticIdentityReceipt(input), {
    message: "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:replay_rejected"
  });
});

test("identity verification normalizes hostile input failures without reflecting them", async () => {
  const identity = await loadIdentityVerifier();
  const canary = "synthetic-hostile-identity-canary";
  const hostileEnvelope = new Proxy({}, {
    get() {
      throw new Error(canary);
    }
  });

  assert.throws(() => identity.verifySyntheticIdentityReceipt({ envelope: hostileEnvelope }), (error) => {
    assert.equal(error.message, "SCOPERANGE_SYNTHETIC_IDENTITY_REJECTED:envelope_rejected");
    assert.equal(error.message.includes(canary), false);
    return true;
  });
});

test("a signed synthetic target capability is opaque and evidence-only", async () => {
  const target = await loadTargetVerifier();
  assert.equal(typeof target.verifySyntheticTargetCapability, "function");
  assert.equal(typeof target.createSyntheticTargetReplayStore, "function");

  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const claims = targetClaims(identityVerification.identityClaimsDigest);
  const capability = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims
  }, privateKey);
  const verification = target.verifySyntheticTargetCapability({
    capability,
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification,
    expected: expectedTarget,
    now
  });
  const targetCapabilityDigest = `sha256:${crypto.createHash("sha256").update(canonical(claims), "utf8").digest("hex")}`;

  assert.deepEqual(verification, {
    schemaVersion: "scoperange-synthetic-target-verification-v1",
    disposition: "verified_synthetic_target_capability",
    identityClaimsDigest: identityVerification.identityClaimsDigest,
    targetCapabilityDigest,
    expiresAt: "2026-07-27T12:02:00.000Z",
    operation: "submit_evidence_envelope",
    targetCount: 1,
    credentialReads: 0,
    networkAttempts: 0,
    providerConnections: 0,
    databaseConnections: 0,
    pricingAuthority: "none",
    promotionAuthority: "none",
    productionAuthority: "none"
  });
  const serialized = JSON.stringify(verification);
  assert.equal(serialized.includes(providerAccountDigest), false);
  assert.equal(serialized.includes(targetDigest), false);
  assert.equal(serialized.includes(idempotencyKeyDigest), false);
});

test("target verification rejects a capability changed after signing", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest)
  }, privateKey);
  const tampered = {
    ...signed,
    claims: { ...signed.claims, operation: "synthetic-unauthorized-operation" }
  };

  assert.throws(() => target.verifySyntheticTargetCapability({
    capability: tampered,
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification,
    expected: expectedTarget,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:signature_rejected"
  });
});

test("target verification rejects unsigned top-level capability metadata", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest)
  }, privateKey);

  assert.throws(() => target.verifySyntheticTargetCapability({
    capability: { ...signed, unsigned_metadata: "synthetic-canary" },
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification,
    expected: expectedTarget,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:envelope_rejected"
  });
});

test("target verification rejects incomplete, broadened, or mismatched capability claims", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const missingEnvelopeDigest = targetClaims(identityVerification.identityClaimsDigest);
  delete missingEnvelopeDigest.envelope_digest;

  for (const [claims, expected] of [
    [missingEnvelopeDigest, expectedTarget],
    [targetClaims(identityVerification.identityClaimsDigest, { unexpected_claim: "synthetic-canary" }), expectedTarget],
    [targetClaims(identityVerification.identityClaimsDigest, { operation: "promote_pricing" }), expectedTarget],
    [targetClaims(identityVerification.identityClaimsDigest, { target_count: 2 }), expectedTarget],
    [targetClaims(identityVerification.identityClaimsDigest, { pricing_authority: "active" }), expectedTarget],
    [targetClaims(identityVerification.identityClaimsDigest), { ...expectedTarget, targetDigest: `sha256:${"9".repeat(64)}` }]
  ]) {
    const capability = signEnvelope({
      schemaVersion: "scoperange-synthetic-target-capability-v1",
      claims
    }, privateKey);
    assert.throws(() => target.verifySyntheticTargetCapability({
      capability,
      publicKey,
      replayStore: target.createSyntheticTargetReplayStore(),
      identityVerification,
      expected,
      now
    }), {
      message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:claims_rejected"
    });
  }
});

test("target verification rejects an unverified structural identity clone", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const capability = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest)
  }, privateKey);

  assert.throws(() => target.verifySyntheticTargetCapability({
    capability,
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification: { ...identityVerification },
    expected: expectedTarget,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:identity_rejected"
  });
});

test("target verification rejects a capability after its verified identity expires", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const later = new Date("2026-07-27T12:02:01.000Z");
  const laterSeconds = Math.floor(later.valueOf() / 1000);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const capability = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest, {
      iat: laterSeconds - 1,
      nbf: laterSeconds - 1,
      exp: laterSeconds + 120
    })
  }, privateKey);

  assert.throws(() => target.verifySyntheticTargetCapability({
    capability,
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification,
    expected: expectedTarget,
    now: later
  }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:identity_rejected"
  });
});

test("target verification rejects a capability that outlives its verified identity", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const capability = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest, { exp: nowSeconds + 180 })
  }, privateKey);

  assert.throws(() => target.verifySyntheticTargetCapability({
    capability,
    publicKey,
    replayStore: target.createSyntheticTargetReplayStore(),
    identityVerification,
    expected: expectedTarget,
    now
  }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:identity_rejected"
  });
});

test("target verification rejects expired, future, and overlong capabilities", async (t) => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

  for (const [name, overrides] of [
    ["expired", { iat: nowSeconds - 180, nbf: nowSeconds - 180, exp: nowSeconds }],
    ["future", { iat: nowSeconds, nbf: nowSeconds + 1, exp: nowSeconds + 120 }],
    ["overlong", { iat: nowSeconds - 301, nbf: nowSeconds - 301, exp: nowSeconds + 1 }]
  ]) {
    await t.test(name, () => {
      const capability = signEnvelope({
        schemaVersion: "scoperange-synthetic-target-capability-v1",
        claims: targetClaims(identityVerification.identityClaimsDigest, overrides)
      }, privateKey);
      assert.throws(() => target.verifySyntheticTargetCapability({
        capability,
        publicKey,
        replayStore: target.createSyntheticTargetReplayStore(),
        identityVerification,
        expected: expectedTarget,
        now
      }), {
        message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:time_rejected"
      });
    });
  }
});

test("target verification consumes each capability identifier once", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const capability = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest)
  }, privateKey);
  const replayStore = target.createSyntheticTargetReplayStore();
  const input = { capability, publicKey, replayStore, identityVerification, expected: expectedTarget, now };

  target.verifySyntheticTargetCapability(input);
  assert.throws(() => target.verifySyntheticTargetCapability(input), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:replay_rejected"
  });
});

test("target verification consumes each idempotency binding once", async () => {
  const target = await loadTargetVerifier();
  const identityVerification = await createVerifiedIdentity();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const first = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest, { jti: "synthetic-capability-first" })
  }, privateKey);
  const second = signEnvelope({
    schemaVersion: "scoperange-synthetic-target-capability-v1",
    claims: targetClaims(identityVerification.identityClaimsDigest, { jti: "synthetic-capability-second" })
  }, privateKey);
  const replayStore = target.createSyntheticTargetReplayStore();
  const input = { publicKey, replayStore, identityVerification, expected: expectedTarget, now };

  target.verifySyntheticTargetCapability({ ...input, capability: first });
  assert.throws(() => target.verifySyntheticTargetCapability({ ...input, capability: second }), {
    message: "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:idempotency_rejected"
  });
});

test("target verification normalizes hostile input failures without reflecting them", async () => {
  const target = await loadTargetVerifier();
  const canary = "synthetic-hostile-target-canary";
  const hostileCapability = new Proxy({}, {
    get() {
      throw new Error(canary);
    }
  });

  assert.throws(() => target.verifySyntheticTargetCapability({ capability: hostileCapability }), (error) => {
    assert.equal(error.message, "SCOPERANGE_SYNTHETIC_TARGET_REJECTED:envelope_rejected");
    assert.equal(error.message.includes(canary), false);
    return true;
  });
});

test("the disabled production connection rejects all connection-shaped input without reflection", async () => {
  const connection = await loadDisabledConnection();
  assert.equal(typeof connection.evaluateDisabledProductionConnection, "function");
  const canary = "synthetic-private-connection-canary";
  const attempted = connection.evaluateDisabledProductionConnection({
    connectionString: `postgres${"ql://"}${canary}@example.invalid/database`,
    apiKey: canary,
    target: canary,
    identityToken: canary
  });
  const empty = connection.evaluateDisabledProductionConnection();

  assert.deepEqual(attempted, {
    schemaVersion: "scoperange-disabled-production-connection-receipt-v1",
    disposition: "rejected",
    reasonCode: "connection_input_rejected",
    secretReads: 0,
    networkAttempts: 0,
    providerConnections: 0,
    databaseConnections: 0,
    pricingEffects: 0,
    productionAuthority: "none"
  });
  assert.deepEqual(empty, { ...attempted, reasonCode: "connection_not_configured" });
  assert.equal(JSON.stringify(attempted).includes(canary), false);
});
