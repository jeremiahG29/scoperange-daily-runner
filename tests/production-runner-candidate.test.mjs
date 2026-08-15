import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { sourceLockDigest } from "../bootstrap/source-lock.js";

const sha256 = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;

test("production runner bridge is implemented while provider activation remains false", async () => {
  const contract = await import("../bootstrap/production-runner-contract.js");
  assert.equal(contract.PRODUCTION_RUNNER_BRIDGE_CONFIGURED, true);
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

test("production gate emits authorization only for exact external commit and source-lock bindings", async () => {
  const entry = await import("../bootstrap/production-runner-entry.js");
  const lock = JSON.parse(fs.readFileSync("production-source-lock.example.json", "utf8"));
  const publicCommit = "f8c816c6f20fd7becff8d3da458ccc27fb85882a";
  const reads = [];
  const environment = new Proxy({
    SCOPERANGE_OBSERVED_PUBLIC_COMMIT: publicCommit,
    SCOPERANGE_APPROVED_PUBLIC_COMMIT: publicCommit,
    SCOPERANGE_APPROVED_PRIVATE_COMMIT: lock.approvedCommit,
    SCOPERANGE_SOURCE_LOCK_DIGEST: sourceLockDigest(lock),
    SCOPERANGE_RELEASE_STATE: "authorized"
  }, {
    get(target, key) {
      reads.push(String(key));
      if (/PASSWORD|DEPLOY_KEY/u.test(String(key))) throw new Error("secret canary");
      return target[key];
    }
  });

  const accepted = entry.evaluateProductionRunnerGate({ environment, lock });
  assert.deepEqual(accepted, {
    schemaVersion: "scoperange-public-production-runner-gate-receipt-v1",
    disposition: "accepted",
    reasonCode: "accepted",
    authorization: "scoperange-production-runner-non-secret-gate-accepted-v1"
  });
  assert.equal(reads.some((key) => /PASSWORD|DEPLOY_KEY/u.test(key)), false);

  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-production-gate-"));
  const outputPath = path.join(outputDirectory, "github-output");
  try {
    entry.writeAcceptedProductionRunnerOutput(outputPath, accepted);
    assert.equal(
      fs.readFileSync(outputPath, "utf8"),
      "authorization=scoperange-production-runner-non-secret-gate-accepted-v1\n"
    );
  } finally {
    fs.rmSync(outputDirectory, { recursive: true, force: true });
  }

  const rejected = entry.evaluateProductionRunnerGate({
    environment: { ...environment, SCOPERANGE_APPROVED_PRIVATE_COMMIT: "0".repeat(40) },
    lock
  });
  assert.equal(rejected.disposition, "rejected");
  assert.equal(rejected.authorization, null);
  assert.equal(rejected.reasonCode, "private_commit_rejected");
});

test("configured public entry builds one approved nonnumeric exterior-door recheck", async () => {
  const entry = await import("../bootstrap/production-runner-entry.js");
  const lock = JSON.parse(fs.readFileSync("production-source-lock.example.json", "utf8"));
  const publicCommit = "f8c816c6f20fd7becff8d3da458ccc27fb85882a";
  const password = "synthetic-database-password";
  const keyMaterial = "synthetic-private-source-key";
  const environment = {
    SCOPERANGE_OBSERVED_PUBLIC_COMMIT: publicCommit,
    SCOPERANGE_APPROVED_PUBLIC_COMMIT: publicCommit,
    SCOPERANGE_APPROVED_PRIVATE_COMMIT: lock.approvedCommit,
    SCOPERANGE_SOURCE_LOCK_DIGEST: sourceLockDigest(lock),
    SCOPERANGE_RELEASE_STATE: "authorized",
    SCOPERANGE_TRIGGER_EVENT_NAME: "schedule",
    SCOPERANGE_TRIGGER_RUN_ID: "123456788",
    SCOPERANGE_CONFIG_VERSION: "scoperange-runtime-config-v1",
    SCOPERANGE_CREDENTIAL_NOT_BEFORE: "2026-08-12T00:00:00Z",
    SCOPERANGE_CREDENTIAL_EXPIRES_AT: "2026-10-18T00:00:00Z",
    SCOPERANGE_CREDENTIAL_VERSION: "scoperange-runtime-credential-v1-20260812T000000Z",
    SCOPERANGE_PRIVATE_SOURCE_DEPLOY_KEY: keyMaterial,
    SCOPERANGE_DB_HOST: "aws-0-us-west-1.pooler.supabase.com",
    SCOPERANGE_DB_PORT: "6543",
    SCOPERANGE_DB_NAME: "postgres",
    SCOPERANGE_DB_USER: "scoperange_intelligence_runtime_v1.syntheticprojectref1",
    SCOPERANGE_DB_PASSWORD: password,
    SCOPERANGE_DB_TLS_SERVER_NAME: "aws-0-us-west-1.pooler.supabase.com",
    SCOPERANGE_EXPECTED_PROJECT_DIGEST: sha256("supabase-project-ref-v1:syntheticprojectref1")
  };
  const calls = [];
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
  const lines = [];
  const receipt = await entry.executeProductionRunner({
    environment,
    clock: () => "2026-08-12T09:17:05.000Z",
    randomBytesImpl: () => Buffer.alloc(32, 0xab),
    signal: new AbortController().signal,
    bridgeImpl: async (value) => { calls.push(value); return privateReceipt; },
    log: (line) => lines.push(line)
  });

  assert.deepEqual(receipt, privateReceipt);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].authorization, "scoperange-production-runner-non-secret-gate-accepted-v1");
  assert.equal(calls[0].keyMaterial, keyMaterial);
  assert.equal(calls[0].lock.approvedCommit, lock.approvedCommit);
  assert.deepEqual(calls[0].privateInput.plan, {
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
    maxBytes: 500000,
    maxRedirects: 3,
    timeoutMs: 8000
  });
  assert.equal(calls[0].privateInput.coverageCellId, "coverage:painting:exterior-door:v1");
  assert.equal(calls[0].privateInput.runId, "daily:2026-08-12");
  assert.equal(calls[0].privateInput.scheduledFor, "2026-08-12T09:17:00.000Z");
  assert.equal(calls[0].privateInput.observedAt, "2026-08-12T09:17:05.000Z");
  assert.equal(calls[0].privateInput.database.password, password);
  assert.match(calls[0].privateInput.planDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(calls[0].privateInput.budgets.maxRequests, 1);
  assert.equal(calls[0].privateInput.budgets.maxConcurrency, 1);
  assert.deepEqual(lines, [JSON.stringify(privateReceipt)]);
  assert.equal(lines.join("").includes(password), false);
  assert.equal(lines.join("").includes(keyMaterial), false);
});

test("manual recovery input is bound to the dispatch run and starts immediately", async () => {
  const plan = await import("../bootstrap/production-runner-plan.js");
  const environment = {
    SCOPERANGE_TRIGGER_EVENT_NAME: "workflow_dispatch",
    SCOPERANGE_TRIGGER_RUN_ID: "123456789",
    SCOPERANGE_DB_HOST: "aws-0-us-west-1.pooler.supabase.com",
    SCOPERANGE_DB_PORT: "6543",
    SCOPERANGE_DB_NAME: "postgres",
    SCOPERANGE_DB_USER: "scoperange_intelligence_runtime_v1.syntheticprojectref1",
    SCOPERANGE_DB_PASSWORD: "synthetic-database-password",
    SCOPERANGE_DB_TLS_SERVER_NAME: "aws-0-us-west-1.pooler.supabase.com",
    SCOPERANGE_CONFIG_VERSION: "scoperange-runtime-config-v1",
    SCOPERANGE_CREDENTIAL_VERSION: "scoperange-runtime-credential-v1-20260812T000000Z",
    SCOPERANGE_CREDENTIAL_NOT_BEFORE: "2026-08-12T00:00:00Z",
    SCOPERANGE_CREDENTIAL_EXPIRES_AT: "2026-10-18T00:00:00Z",
    SCOPERANGE_EXPECTED_PROJECT_DIGEST: sha256("supabase-project-ref-v1:syntheticprojectref1")
  };

  const input = plan.createApprovedProductionInput({
    environment,
    observedAt: "2026-08-15T03:30:00.000Z",
    randomBytesImpl: () => Buffer.alloc(32, 0xab)
  });

  assert.equal(input.runId, "manual:123456789");
  assert.equal(input.workItemId, "manual:123456789:src-atlanta-door-refinishing-blog");
  assert.equal(input.scheduledFor, input.observedAt);
  assert.equal(input.schedulePolicyVersion, "scoperange-pricing-intelligence-manual-recovery-policy-v1");
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

test("registered production workflow exactly matches the cacheless disabled candidate", () => {
  const candidatePath = path.resolve("inactive-production-daily-workflow.yml");
  const registeredPath = path.resolve(".github/workflows/scoperange-daily.yml");
  const candidate = JSON.parse(fs.readFileSync(candidatePath, "utf8"));
  const registered = JSON.parse(fs.readFileSync(registeredPath, "utf8"));
  assert.deepEqual(registered, candidate);
  assert.equal(fs.readFileSync(registeredPath, "utf8"), fs.readFileSync(candidatePath, "utf8"));
  assert.deepEqual(candidate.on, {
    schedule: [{ cron: "17 09 * * *" }],
    workflow_dispatch: {}
  });
  assert.deepEqual(candidate.permissions, { contents: "read" });
  assert.deepEqual(Object.keys(candidate.jobs), ["gate", "runner"]);
  assert.equal(candidate.jobs.gate.environment, undefined);
  assert.equal(JSON.stringify(candidate.jobs.gate).includes("secrets."), false);
  assert.equal(candidate.jobs.runner.environment, "scoperange-production-disabled-v1");
  assert.equal(candidate.jobs.runner.if, "needs.gate.outputs.authorization == 'scoperange-production-runner-non-secret-gate-accepted-v1'");
  assert.equal(candidate.jobs.gate.steps.at(-1).run, "node bootstrap/production-runner-entry.js gate");
  assert.equal(candidate.jobs.runner.steps.at(-1).run, "node bootstrap/production-runner-entry.js run");
  assert.equal(candidate.jobs.gate.steps.at(-1).env.SCOPERANGE_RELEASE_STATE, "${{ vars.SCOPERANGE_RELEASE_STATE }}");
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
  assert.equal(fs.existsSync(registeredPath), true);
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
      "SCOPERANGE_PRIVATE_SOURCE_DEPLOY_KEY",
      "SCOPERANGE_OBSERVED_PUBLIC_COMMIT",
      "SCOPERANGE_APPROVED_PUBLIC_COMMIT",
      "SCOPERANGE_APPROVED_PRIVATE_COMMIT",
      "SCOPERANGE_SOURCE_LOCK_DIGEST",
      "SCOPERANGE_RELEASE_STATE",
      "SCOPERANGE_TRIGGER_EVENT_NAME",
      "SCOPERANGE_TRIGGER_RUN_ID"
    ].sort()
  );
});

test("registered production workflow exposes only the scheduled and inputless manual recovery triggers", () => {
  const candidate = JSON.parse(fs.readFileSync("inactive-production-daily-workflow.yml", "utf8"));
  assert.deepEqual(candidate.on, {
    schedule: [{ cron: "17 09 * * *" }],
    workflow_dispatch: {}
  });
  assert.match(candidate.jobs.gate.if, /github\.event_name == 'workflow_dispatch'/u);
  assert.equal(
    candidate.jobs.runner.steps.at(-1).env.SCOPERANGE_TRIGGER_EVENT_NAME,
    "${{ github.event_name }}"
  );
  assert.equal(
    candidate.jobs.runner.steps.at(-1).env.SCOPERANGE_TRIGGER_RUN_ID,
    "${{ github.run_id }}"
  );
});

test("public exposure inventory identifies the production workflow as registered but unconfigured", () => {
  const exposure = JSON.parse(fs.readFileSync("public-exposure-contract.json", "utf8"));
  for (const file of [
    "bootstrap/production-runner-contract.js",
    "bootstrap/production-runner-entry.js",
    "bootstrap/production-runner-plan.js",
    ".github/workflows/scoperange-daily.yml",
    "inactive-production-daily-workflow.yml",
    "production-source-lock.example.json",
    "tests/production-runner-candidate.test.mjs"
  ]) {
    assert.ok(exposure.publicFiles.includes(file));
  }
  assert.deepEqual(exposure.productionRunner, {
    implementationPresent: true,
    recognizedWorkflowPlacement: true,
    configured: true,
    activationAuthorized: false,
    workflowRuns: 0,
    providerWrites: 0,
    productionConnections: 0,
    evidenceWrites: 0,
    pricingAuthority: false
  });
  assert.deepEqual(exposure.registeredProductionWorkflow, {
    path: ".github/workflows/scoperange-daily.yml",
    providerStateRequired: "disabled",
    allowedTriggers: ["schedule", "workflow_dispatch"],
    schedule: "17 09 * * *",
    topLevelPermissions: "contents:read",
    dependencyCacheAllowed: false,
    exactActionPinsRequired: true,
    externalCommitBindingConfigured: false,
    bridgeConfigured: true,
    activationAuthorized: false,
    executionAuthorized: false,
    productionAuthority: false,
    pricingAuthority: false
  });
});
