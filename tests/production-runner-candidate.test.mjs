import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

test("production runner contract is implemented but activation remains false", async () => {
  const contract = await import("../bootstrap/production-runner-contract.js");
  assert.equal(contract.PRODUCTION_RUNNER_BRIDGE_CONFIGURED, false);
  assert.equal(contract.PRODUCTION_RUNNER_ACTIVATION_AUTHORIZED, false);
  assert.deepEqual(contract.PRODUCTION_RUNNER_AUTHORITY, {
    recurrence: true,
    publicSourceFetch: true,
    evidenceWrite: true,
    proposal: false,
    review: false,
    promotion: false,
    rollback: false,
    livePricing: false
  });
});

test("production source lock binds the exact reviewed private bundle without activation", () => {
  const lock = JSON.parse(fs.readFileSync("production-source-lock.example.json", "utf8"));
  assert.equal(lock.repository, "jeremiahG29/scopematch");
  assert.equal(lock.approvedCommit, "9a37ec0b96171423bc1ed605ffaa22debe88fa4f");
  assert.equal(lock.approvedParent, "126a37862b0afb43d25a90f8bc9f4d2625b1f1c6");
  assert.equal(lock.requiredAncestor, lock.approvedParent);
  assert.equal(lock.approvedTree, "802aae2732408c9948c57ff4310e8dfdade9f9dd");
  assert.equal(lock.bundleRoot, "scoperange/pricing-intelligence/production-runner");
  assert.equal(lock.allowedBundleDigest, "sha256:484aae9b7bdb67ebbd2cdd16bbbfb7596ac4eab8efccae4b893569b1c551bea0");
  assert.equal(lock.credential.created, false);
  assert.equal(lock.activationAuthorized, false);
});

test("direct production runner bridge stops before environment or secret access", async () => {
  const entry = await import("../bootstrap/production-runner-entry.js");
  const environment = new Proxy({}, { get() { throw new Error("secret canary"); }, ownKeys() { throw new Error("secret canary"); } });
  const lines = [];
  const receipt = await entry.execute({ environment, log: (line) => lines.push(line) });
  assert.deepEqual(receipt, {
    schemaVersion: "scoperange-public-production-runner-receipt-v1",
    disposition: "rejected",
    reasonCode: "production_runner_not_configured",
    secretReads: 0,
    privateSourceFetches: 0,
    publicSourceRequests: 0,
    databaseConnections: 0,
    evidenceWrites: 0,
    proposalEffects: 0,
    promotionEffects: 0,
    pricingEffects: 0,
    productionAuthority: "none"
  });
  assert.deepEqual(lines, [`${JSON.stringify(receipt)}`]);
});

test("configured bridge keeps secrets in stdin and accepts only a fixed private receipt", async () => {
  const entry = await import("../bootstrap/production-runner-entry.js");
  const canary = "synthetic-database-password-canary";
  const processCalls = [];
  const privateReceipt = {
    schemaVersion: "scoperange-production-runner-receipt-v1",
    disposition: "evidence_recorded",
    reasonCode: "accepted",
    sourceRequests: 1,
    databaseTransactions: 3,
    evidenceWrites: 1,
    numericEvidenceCount: 0,
    proposalEffects: 0,
    promotionEffects: 0,
    pricingEffects: 0,
    productionAuthority: "evidence_only"
  };
  const result = await entry.executeConfiguredProductionBridge({
    authorization: "scoperange-production-runner-non-secret-gate-accepted-v1",
    lock: { bundleRoot: "scoperange/pricing-intelligence/production-runner" },
    keyMaterial: "synthetic-private-source-key",
    privateInput: {
      schemaVersion: "scoperange-production-runner-input-v1",
      database: {
        password: canary,
        host: "synthetic.pooler.supabase.com"
      }
    },
    signal: new AbortController().signal,
    fetchImpl: async (value) => value.consumeVerifiedCheckout({
      checkoutPath: path.resolve("synthetic-checkout"),
      workspacePath: path.resolve("synthetic-workspace"),
      bundleRoot: value.lock.bundleRoot,
      runManagedProcess: async () => ({ exitCode: 0, stdout: "", stderr: "" })
    }),
    processImpl: async (value) => {
      processCalls.push(structuredClone(value));
      if (value.program === process.execPath) return { exitCode: 0, stdout: `${JSON.stringify(privateReceipt)}\n`, stderr: "" };
      return { exitCode: 0, stdout: "added 14 packages in 845ms\n", stderr: "" };
    }
  });
  assert.deepEqual(result, privateReceipt);
  assert.equal(processCalls.length, 2);
  assert.deepEqual(processCalls[1].args, ["bridge-entry.js"]);
  assert.equal(JSON.parse(processCalls[1].stdin).database.password, canary);
  const publicShape = processCalls.map(({ stdin, ...value }) => value);
  assert.equal(JSON.stringify(publicShape).includes(canary), false);
  assert.equal(JSON.stringify(result).includes(canary), false);
});

test("production candidate is exact-commit-bound, cacheless, disabled, and unregistered", () => {
  const candidatePath = path.resolve("inactive-production-daily-workflow.yml");
  const candidate = JSON.parse(fs.readFileSync(candidatePath, "utf8"));
  assert.deepEqual(candidate.on, { schedule: [{ cron: "17 09 * * *" }] });
  assert.deepEqual(candidate.permissions, { contents: "read" });
  assert.deepEqual(Object.keys(candidate.jobs), ["gate", "runner"]);
  assert.equal(candidate.jobs.gate.environment, undefined);
  assert.equal(JSON.stringify(candidate.jobs.gate).includes("secrets."), false);
  assert.equal(candidate.jobs.runner.environment, "scoperange-production-disabled-v1");
  assert.equal(candidate.jobs.runner.if, "needs.gate.outputs.authorization == 'scoperange-production-runner-non-secret-gate-accepted-v1'");
  const actions = Object.values(candidate.jobs).flatMap((job) => job.steps).filter((step) => step.uses).map((step) => step.uses);
  assert.deepEqual([...new Set(actions)].sort(), [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
  ]);
  const raw = fs.readFileSync(candidatePath, "utf8");
  assert.match(raw, /SCOPERANGE_APPROVED_PUBLIC_COMMIT/u);
  assert.match(raw, /SCOPERANGE_APPROVED_PRIVATE_COMMIT/u);
  assert.match(raw, /"package-manager-cache": false/u);
  assert.doesNotMatch(raw, /cache\/restore|cache\/save|upload-artifact|download-artifact/iu);
  assert.equal(fs.existsSync(path.resolve(".github/workflows/scoperange-production-daily.yml")), false);
  assert.deepEqual(
    Object.keys(candidate.jobs.runner.steps.at(-1).env).sort(),
    [
      "SCOPERANGE_CONFIG_VERSION",
      "SCOPERANGE_CREDENTIAL_EXPIRES_AT",
      "SCOPERANGE_CREDENTIAL_NOT_BEFORE",
      "SCOPERANGE_CREDENTIAL_VERSION",
      "SCOPERANGE_DB_HOST",
      "SCOPERANGE_DB_NAME",
      "SCOPERANGE_DB_PASSWORD",
      "SCOPERANGE_DB_PORT",
      "SCOPERANGE_DB_TLS_SERVER_NAME",
      "SCOPERANGE_DB_USER",
      "SCOPERANGE_EXPECTED_PROJECT_DIGEST",
      "SCOPERANGE_PRIVATE_SOURCE_DEPLOY_KEY"
    ]
  );
});

test("public exposure inventory identifies production artifacts as unregistered and unconfigured", () => {
  const exposure = JSON.parse(fs.readFileSync("public-exposure-contract.json", "utf8"));
  for (const file of [
    "bootstrap/production-runner-contract.js",
    "bootstrap/production-runner-entry.js",
    "inactive-production-daily-workflow.yml",
    "production-source-lock.example.json",
    "tests/production-runner-candidate.test.mjs"
  ]) {
    assert.ok(exposure.publicFiles.includes(file));
  }
  assert.deepEqual(exposure.productionRunner, {
    implementationPresent: true,
    recognizedWorkflowPlacement: false,
    configured: false,
    activationAuthorized: false,
    workflowRuns: 0,
    providerWrites: 0,
    productionConnections: 0,
    evidenceWrites: 0,
    pricingAuthority: false
  });
});
