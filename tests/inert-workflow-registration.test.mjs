import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  ACTIVATION_AUTHORIZED,
  APPROVED_COMMIT_BINDING_CONTRACT,
  PRODUCTION_IDENTITY_CONTRACT,
  RECURRENCE_CONTRACT,
  TARGET_BINDING_CONTRACT
} from "../bootstrap/contract.js";
import * as publicContracts from "../bootstrap/contract.js";
import { execute } from "../bootstrap/entry.js";
import { createZeroEffectReceipt } from "../bootstrap/operational-receipt.js";
import { evaluateRecurrenceGate, evaluateRuntimeGate } from "../bootstrap/runtime-gate.js";
import * as syntheticSourceFetch from "../bootstrap/synthetic-source-fetch.js";
import * as syntheticRecurrence from "../bootstrap/synthetic-recurrence-adapter.js";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflowsRoot = path.join(root, ".github", "workflows");
const workflowRelativePath = ".github/workflows/scoperange-inert-shell.yml";
const workflowPath = path.join(root, ...workflowRelativePath.split("/"));
const exposurePath = path.join(root, "public-exposure-contract.json");
const candidatePath = path.join(root, "inactive-public-daily-workflow.yml");

function walkFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) return walkFiles(entryPath);
      return entry.isFile() ? [entryPath] : [];
    });
}

function repositoryFiles() {
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.name !== ".git")
    .flatMap((entry) => {
      const entryPath = path.join(root, entry.name);
      return entry.isDirectory() ? walkFiles(entryPath) : [entryPath];
    })
    .map((file) => path.relative(root, file).replaceAll("\\", "/"))
    .sort();
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function fixtureGit(repositoryPath, args) {
  const result = spawnSync("git", args, {
    cwd: repositoryPath,
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" }
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function createSyntheticSourceRepository() {
  const repositoryPath = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-source-fixture-"));
  fixtureGit(repositoryPath, ["init", "--quiet"]);
  fixtureGit(repositoryPath, ["config", "user.email", "synthetic@example.invalid"]);
  fixtureGit(repositoryPath, ["config", "user.name", "Synthetic Fixture"]);
  fixtureGit(repositoryPath, ["commit", "--quiet", "--allow-empty", "-m", "fixture parent"]);

  const bundleRoot = "synthetic/public-runner";
  const allowedPaths = ["contract.js", "entry.js", "operational-receipt.js", "package.json", "runtime-gate.js"]
    .map((file) => `${bundleRoot}/${file}`);
  fs.mkdirSync(path.join(repositoryPath, ...bundleRoot.split("/")), { recursive: true });
  for (const [index, file] of allowedPaths.entries()) {
    fs.writeFileSync(path.join(repositoryPath, ...file.split("/")), `synthetic-fixture-${index}\n`, "utf8");
  }
  fixtureGit(repositoryPath, ["add", "--", bundleRoot]);
  fixtureGit(repositoryPath, ["commit", "--quiet", "-m", "fixture bundle"]);

  const approvedCommit = fixtureGit(repositoryPath, ["rev-parse", "HEAD"]);
  const approvedParent = fixtureGit(repositoryPath, ["rev-parse", "HEAD^"]);
  const approvedTree = fixtureGit(repositoryPath, ["rev-parse", "HEAD^{tree}"]);
  const entries = fixtureGit(repositoryPath, ["ls-tree", "-r", approvedCommit, "--", bundleRoot])
    .split(/\r?\n/u)
    .map((line) => {
      const match = /^(\d{6}) blob ([0-9a-f]{40})\s+(.+)$/u.exec(line);
      assert.ok(match);
      return `${match[1]}\t${match[2]}\t${match[3]}\n`;
    })
    .sort()
    .join("");
  const allowedBundleDigest = `sha256:${crypto.createHash("sha256").update(entries, "utf8").digest("hex")}`;
  const lock = {
    schemaVersion: "scoperange-public-runner-source-lock-v1",
    lockVersion: "synthetic-fixture-v1",
    repository: "jeremiahG29/scopematch",
    approvedCommit,
    requiredAncestor: approvedParent,
    approvedParent,
    approvedTree,
    bundleRoot,
    allowedPaths,
    allowedBundleDigest,
    fetch: {
      refType: "commit_only",
      allowedRefs: [],
      fallbackAllowed: false,
      tagsAllowed: false,
      branchesAllowed: false,
      submodulesAllowed: false,
      lfsAllowed: false,
      credentialHelperAllowed: false,
      hostKeyChecking: "strict_github_host_keys_only"
    },
    credential: {
      type: "repository_scoped_read_only_deploy_key",
      repositoryCount: 1,
      write: false,
      created: false
    },
    activationAuthorized: false
  };
  return { allowedBundleDigest, lock, repositoryPath };
}

test("exactly one GitHub workflow is registered", () => {
  const workflows = walkFiles(workflowsRoot)
    .filter((file) => /\.ya?ml$/u.test(file))
    .map((file) => path.relative(root, file).replaceAll("\\", "/"));
  assert.deepEqual(workflows, [workflowRelativePath]);
});

test("the registered workflow exposes only an inputless reusable-workflow trigger", () => {
  const workflow = readJson(workflowPath);
  assert.deepEqual(Object.keys(workflow.on), ["workflow_call"]);
  assert.deepEqual(workflow.on.workflow_call, {});
  assert.equal("inputs" in workflow.on.workflow_call, false);
  assert.equal("outputs" in workflow.on.workflow_call, false);
  assert.equal("secrets" in workflow.on.workflow_call, false);
  assert.deepEqual(workflow.permissions, {});
});

test("the only job is unconditionally skipped and fails defensively if unskipped", () => {
  const workflow = readJson(workflowPath);
  assert.deepEqual(Object.keys(workflow.jobs), ["inert"]);
  const job = workflow.jobs.inert;
  assert.equal(job.name, "Inert ScopeRange shell - disabled and never executed");
  assert.equal(job.if, "${{ false }}");
  assert.equal(job["runs-on"], "ubuntu-24.04");
  assert.deepEqual(job.steps, [{
    name: "Defensive failure if the skip guard is removed",
    run: "exit 1"
  }]);
});

test("the registered shell has no caller output or execution authority", () => {
  const workflow = readJson(workflowPath);
  const job = workflow.jobs.inert;
  for (const key of [
    "concurrency", "container", "defaults", "environment", "env", "needs", "outputs",
    "permissions", "services", "strategy", "timeout-minutes", "uses", "with"
  ]) assert.equal(key in job, false, key);
  for (const step of job.steps) {
    for (const key of ["continue-on-error", "env", "id", "if", "shell", "uses", "with", "working-directory"]) {
      assert.equal(key in step, false, key);
    }
  }
  for (const key of ["concurrency", "defaults", "env", "jobs", "name", "on", "permissions", "run-name"]) {
    if (!["jobs", "name", "on", "permissions"].includes(key)) assert.equal(key in workflow, false, key);
  }
});

test("the scheduled candidate remains outside the registered workflow directory", () => {
  assert.equal(fs.existsSync(path.join(root, "inactive-public-daily-workflow.yml")), true);
  assert.equal(fs.existsSync(path.join(workflowsRoot, "inactive-public-daily-workflow.yml")), false);
  assert.equal(fs.readFileSync(workflowPath, "utf8").includes("schedule"), false);
});

test("the workflow contains no external action, runtime, credential, target, or provider reference", () => {
  const source = fs.readFileSync(workflowPath, "utf8");
  for (const forbidden of [
    "uses", "checkout", "setup-node", "node ", "npm ", "npx ", "curl ", "wget ",
    "secrets", "vars", "environment", "id-token", "token", "repository", "github.",
    "scope" + "match", "supa" + "base", "stripe", "cloud" + "flare", "http://", "https://"
  ]) assert.equal(source.toLowerCase().includes(forbidden), false, forbidden);
});

test("the public exposure contract closes the registered-shell authority boundary", () => {
  const exposure = readJson(exposurePath);
  assert.equal(exposure.schemaVersion, "scoperange-public-runner-exposure-v4");
  assert.equal(exposure.status, "inert_workflow_registered_disabled");
  assert.equal(exposure.publicRepositoryCreated, true);
  assert.deepEqual(exposure.registeredWorkflow, {
    path: workflowRelativePath,
    providerStateRequired: "disabled",
    onlyTrigger: "workflow_call",
    inputCount: 0,
    outputCount: 0,
    secretCount: 0,
    topLevelPermissions: "none",
    jobCount: 1,
    unconditionalJobSkip: true,
    defensiveFailure: true,
    externalActionCount: 0,
    runtimeInvocationCount: 0,
    executionAuthorized: false,
    productionAuthority: false,
    pricingAuthority: false
  });
});

test("the complete public inventory is explicit and contains no credential material", () => {
  const exposure = readJson(exposurePath);
  assert.deepEqual([...exposure.publicFiles].sort(), repositoryFiles());
  const source = repositoryFiles().map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  for (const pattern of [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
    /(?:postgres|postgresql):\/\//iu,
    /\b(?:SUPABASE|STRIPE|CLOUDFLARE)_[A-Z0-9_]+\b/u,
    /\bservice_role\b/u,
    /\bscoperange_private\b/u,
    /[\w.+-]+@(?!example\.invalid\b)[\w.-]+\.[A-Za-z]{2,}/u
  ]) assert.doesNotMatch(source.replaceAll("git@github.com", ""), pattern);
});

test("the inactive candidate reads its approved commit only from an external post-merge binding", () => {
  const candidate = readJson(candidatePath);
  const environment = candidate.jobs.gate.steps.at(-1).env;
  assert.equal(environment.PUBLIC_RUNNER_APPROVED_COMMIT, "${{ vars.SCOPERANGE_APPROVED_PUBLIC_COMMIT }}");
  assert.equal(
    environment.PUBLIC_RUNNER_APPROVED_COMMIT_BINDING_STATE,
    "${{ vars.SCOPERANGE_APPROVED_PUBLIC_COMMIT_BINDING_STATE }}"
  );
  assert.notEqual(environment.PUBLIC_RUNNER_APPROVED_COMMIT, environment.PUBLIC_RUNNER_COMMIT);
  assert.doesNotMatch(fs.readFileSync(candidatePath, "utf8"), /PUBLIC_RUNNER_APPROVED_COMMIT"\s*:\s*"0{40}"/u);
});

test("the inactive candidate explicitly disables dependency caching", () => {
  const candidate = readJson(candidatePath);
  const setupNode = candidate.jobs.gate.steps.find((step) => step.name === "Select pinned Node.js");
  assert.equal(setupNode.with["package-manager-cache"], false);
});

test("activation and signed identity authority remain unconfigured", () => {
  assert.equal(ACTIVATION_AUTHORIZED, false);
  assert.deepEqual(APPROVED_COMMIT_BINDING_CONTRACT, {
    schemaVersion: "scoperange-approved-public-commit-binding-v1",
    source: "external_post_merge_governance",
    exactCommitRequired: true,
    embeddedSelfHashAllowed: false,
    defaultBranchFallbackAllowed: false,
    configured: false
  });
  assert.deepEqual(PRODUCTION_IDENTITY_CONTRACT, {
    schemaVersion: "scoperange-production-identity-claims-v2",
    requiredClaims: [
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
    ],
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
});

test("the public exposure contract keeps synthetic authorization and production connection inert", () => {
  const exposure = readJson(exposurePath);
  assert.deepEqual(exposure.syntheticAuthorization, {
    identityReceipt: {
      signatureAlgorithm: "Ed25519",
      maximumReceiptSeconds: 300,
      replayProtection: "shared_in_memory_fixture",
      configured: false,
      credentialReads: 0,
      networkAttempts: 0,
      productionAuthority: false
    },
    targetCapability: {
      signatureAlgorithm: "Ed25519",
      maximumCapabilitySeconds: 300,
      exactTargetCount: 1,
      allowedOperation: "submit_evidence_envelope",
      replayProtection: "shared_in_memory_fixture",
      pricingAuthority: false,
      promotionAuthority: false,
      configured: false,
      credentialReads: 0,
      networkAttempts: 0,
      productionAuthority: false
    },
    productionConnection: {
      transport: "disabled",
      connectionAdapterConfigured: false,
      identityTokenExchangeConfigured: false,
      providerTargetConfigured: false,
      writerConnected: false,
      credentialReads: 0,
      networkAttempts: 0,
      providerConnections: 0,
      databaseConnections: 0,
      pricingAuthority: false,
      productionAuthority: false
    }
  });
});

test("exact-target authority remains unconfigured", () => {
  assert.deepEqual(TARGET_BINDING_CONTRACT, {
    schemaVersion: "scoperange-exact-target-binding-v2",
    requiredClaims: [
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
    ],
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
});

test("production connection authority is structurally disabled", () => {
  assert.deepEqual(publicContracts.PRODUCTION_CONNECTION_CONTRACT, {
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
});

test("caller-supplied identity and target state cannot enter runtime configuration", () => {
  assert.equal(publicContracts.CONFIGURATION_KEYS.includes("PUBLIC_RUNNER_IDENTITY_STATE"), false);
  assert.equal(publicContracts.CONFIGURATION_KEYS.includes("PUBLIC_RUNNER_TARGET_BINDING_STATE"), false);
  const candidate = readJson(candidatePath);
  const environment = candidate.jobs.gate.steps.at(-1).env;
  assert.equal("PUBLIC_RUNNER_IDENTITY_STATE" in environment, false);
  assert.equal("PUBLIC_RUNNER_TARGET_BINDING_STATE" in environment, false);
});

test("the recurrence contract accepts only a current durable lease and a fresh uncancelled invocation", async (t) => {
  const now = new Date("2026-07-27T09:17:00.000Z");
  const valid = {
    PUBLIC_RUNNER_LEASE_STATE: "held",
    PUBLIC_RUNNER_LEASE_RECEIPT: `sha256:${"a".repeat(64)}`,
    PUBLIC_RUNNER_LEASE_EXPIRES_AT: "2026-07-27T09:27:00.000Z",
    PUBLIC_RUNNER_MISSED_RUN_STATE: "on_time",
    PUBLIC_RUNNER_RESUME_STATE: "fresh",
    PUBLIC_RUNNER_CANCELLATION_STATE: "clear",
    PUBLIC_RUNNER_OVERLAP_STATE: "clear"
  };
  assert.deepEqual(evaluateRecurrenceGate(valid, now), { accepted: true });

  for (const [name, overrides, reasonCode] of [
    ["missing durable lease", { PUBLIC_RUNNER_LEASE_STATE: "unconfigured" }, "lease_not_held"],
    ["malformed lease receipt", { PUBLIC_RUNNER_LEASE_RECEIPT: "opaque-canary" }, "lease_receipt_rejected"],
    ["expired lease", { PUBLIC_RUNNER_LEASE_EXPIRES_AT: "2026-07-27T09:16:59.999Z" }, "lease_window_rejected"],
    ["overlong lease", { PUBLIC_RUNNER_LEASE_EXPIRES_AT: "2026-07-27T09:27:00.001Z" }, "lease_window_rejected"],
    ["missed execution", { PUBLIC_RUNNER_MISSED_RUN_STATE: "missed" }, "missed_run_no_catch_up"],
    ["implicit resume", { PUBLIC_RUNNER_RESUME_STATE: "resume" }, "resume_not_authorized"],
    ["cancellation", { PUBLIC_RUNNER_CANCELLATION_STATE: "cancelled" }, "invocation_cancelled"],
    ["overlap", { PUBLIC_RUNNER_OVERLAP_STATE: "active" }, "active_overlap"]
  ]) {
    await t.test(name, () => {
      assert.deepEqual(evaluateRecurrenceGate({ ...valid, ...overrides }, now), { reasonCode });
    });
  }
  assert.deepEqual(RECURRENCE_CONTRACT, {
    schemaVersion: "scoperange-public-runner-recurrence-v1",
    durableLeaseRequired: true,
    maximumLeaseSeconds: 600,
    missedRunCatchUpAllowed: false,
    implicitResumeAllowed: false,
    cancellationMustFailClosed: true,
    overlapMustFailClosed: true,
    adapterConfigured: false
  });
});

test("runtime evaluation rejects an unverified external commit binding before later gates", () => {
  const result = evaluateRuntimeGate({
    PUBLIC_RUNNER_EXPECTED_REPOSITORY: "jeremiahG29/scoperange-daily-runner",
    PUBLIC_RUNNER_REPOSITORY: "jeremiahG29/scoperange-daily-runner",
    PUBLIC_RUNNER_WORKFLOW_REF: "jeremiahG29/scoperange-daily-runner/.github/workflows/scoperange-daily.yml@refs/heads/main",
    PUBLIC_RUNNER_EVENT_NAME: "schedule",
    PUBLIC_RUNNER_EVENT_SCHEDULE: "17 09 * * *",
    PUBLIC_RUNNER_REF: "refs/heads/main",
    PUBLIC_RUNNER_RUN_ATTEMPT: "1",
    PUBLIC_RUNNER_COMMIT: "a".repeat(40),
    PUBLIC_RUNNER_APPROVED_COMMIT: "a".repeat(40),
    PUBLIC_RUNNER_APPROVED_COMMIT_BINDING_STATE: "unconfigured"
  }, new Date("2026-07-27T09:17:00.000Z"), `sha256:${"b".repeat(64)}`);
  assert.deepEqual(result, { reasonCode: "approved_commit_binding_unverified" });
});

test("zero-effect receipts never reflect untrusted reason or configuration values", () => {
  const canary = "private-value-canary";
  const receipt = createZeroEffectReceipt({
    reasonCode: canary,
    now: new Date("2026-07-27T09:17:00.000Z"),
    sourceLockDigest: `sha256:${"c".repeat(64)}`
  });
  assert.deepEqual(Object.keys(receipt), [
    "schemaVersion",
    "runDay",
    "disposition",
    "sourceLockDigestPrefix",
    "stage",
    "durationClass",
    "reasonCode",
    "finalClassification",
    "effects",
    "productionAuthority"
  ]);
  assert.equal(receipt.reasonCode, "unknown_rejection");
  assert.doesNotMatch(JSON.stringify(receipt), new RegExp(canary, "u"));

  const lines = [];
  execute({
    environment: {
      PUBLIC_RUNNER_MODE: "public_runner_candidate",
      PUBLIC_RUNNER_REPOSITORY: canary
    },
    now: new Date("2026-07-27T09:17:00.000Z"),
    log: (line) => lines.push(line)
  });
  assert.equal(lines.length, 1);
  assert.deepEqual(Object.keys(JSON.parse(lines[0])), Object.keys(receipt));
  assert.doesNotMatch(lines[0], new RegExp(canary, "u"));
});

test("synthetic-only source-fetch and recurrence adapter modules are part of the public inventory", () => {
  assert.equal(fs.existsSync(path.join(root, "bootstrap", "synthetic-source-fetch.js")), true);
  assert.equal(fs.existsSync(path.join(root, "bootstrap", "synthetic-recurrence-adapter.js")), true);
});

test("synthetic source fetch verifies local Git objects without exposing source or gaining authority", () => {
  const fixture = createSyntheticSourceRepository();
  const commands = [];
  try {
    assert.equal(typeof syntheticSourceFetch.verifySyntheticSourceFetch, "function");
    const receipt = syntheticSourceFetch.verifySyntheticSourceFetch({
      repositoryPath: fixture.repositoryPath,
      lock: fixture.lock,
      onCommand: (command) => commands.push(command)
    });
    assert.deepEqual(receipt, {
      schemaVersion: "scoperange-synthetic-source-fetch-receipt-v1",
      disposition: "verified_synthetic_fixture",
      sourceKind: "local_git_object_fixture",
      fileCount: 5,
      bundleDigest: fixture.allowedBundleDigest,
      credentialReads: 0,
      networkAttempts: 0,
      materializedBytes: 0,
      executionAttempts: 0,
      productionAuthority: "none"
    });
    assert.ok(commands.length > 0);
    assert.equal(commands.every((command) => command.network === false), true);
    const serialized = JSON.stringify(receipt);
    assert.doesNotMatch(serialized, /synthetic-fixture-[0-9]/u);
    assert.equal(serialized.includes(fixture.repositoryPath), false);
    assert.equal(serialized.includes(fixture.lock.approvedCommit), false);
    assert.deepEqual(syntheticSourceFetch.SYNTHETIC_SOURCE_FETCH_CONTRACT, {
      schemaVersion: "scoperange-synthetic-source-fetch-v1",
      sourceKind: "local_git_object_fixture",
      syntheticFixturesOnly: true,
      credentialReads: 0,
      networkAttempts: 0,
      materializedBytes: 0,
      executionAttempts: 0,
      adapterConfigured: false,
      productionAuthority: "none"
    });
  } finally {
    fs.rmSync(fixture.repositoryPath, { recursive: true, force: true });
  }
});

test("shared synthetic recurrence state rejects overlapping leases without reflecting identifiers", () => {
  assert.equal(typeof syntheticRecurrence.createSyntheticRecurrenceStore, "function");
  assert.equal(typeof syntheticRecurrence.createSyntheticRecurrenceAdapter, "function");
  const store = syntheticRecurrence.createSyntheticRecurrenceStore();
  const clock = () => new Date("2026-07-27T09:18:00.000Z");
  const first = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock });
  const second = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock });
  const acquired = first.acquire({
    scheduleKey: "daily:private-canary",
    runId: "run-private-canary",
    scheduledFor: "2026-07-27T09:17:00.000Z"
  });
  assert.equal(acquired.disposition, "acquired_synthetic_lease");
  assert.equal(acquired.reasonCode, null);
  assert.match(acquired.leaseReceipt, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(acquired.leaseExpiresAt, "2026-07-27T09:28:00.000Z");
  assert.equal(acquired.productionAuthority, "none");
  assert.equal(acquired.networkAttempts, 0);
  assert.doesNotMatch(JSON.stringify(acquired), /private-canary/u);

  const overlap = second.acquire({
    scheduleKey: "daily:private-canary",
    runId: "run-2-private-canary",
    scheduledFor: "2026-07-27T09:17:00.000Z"
  });
  assert.deepEqual(overlap, {
    schemaVersion: "scoperange-synthetic-recurrence-receipt-v1",
    disposition: "rejected",
    reasonCode: "active_overlap",
    leaseReceipt: null,
    leaseExpiresAt: null,
    networkAttempts: 0,
    productionAuthority: "none"
  });
  assert.deepEqual(syntheticRecurrence.SYNTHETIC_RECURRENCE_ADAPTER_CONTRACT, {
    schemaVersion: "scoperange-synthetic-recurrence-adapter-v1",
    storageKind: "shared_in_memory_fixture",
    syntheticFixturesOnly: true,
    productionDurability: false,
    networkAttempts: 0,
    adapterConfigured: false,
    productionAuthority: "none"
  });
});

test("synthetic recurrence cancellation is shared and fails the runtime contract closed", () => {
  let now = new Date("2026-07-27T09:18:00.000Z");
  const store = syntheticRecurrence.createSyntheticRecurrenceStore();
  const first = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock: () => new Date(now) });
  const second = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock: () => new Date(now) });
  const acquired = first.acquire({
    scheduleKey: "daily:2026-07-27",
    runId: "run-1",
    scheduledFor: "2026-07-27T09:17:00.000Z"
  });
  const initialState = second.runtimeState({ leaseReceipt: acquired.leaseReceipt });
  assert.deepEqual(evaluateRecurrenceGate(initialState, now), { accepted: true });
  assert.deepEqual(first.cancel({ leaseReceipt: acquired.leaseReceipt }), {
    schemaVersion: "scoperange-synthetic-recurrence-receipt-v1",
    disposition: "rejected",
    reasonCode: "invocation_cancelled",
    leaseReceipt: null,
    leaseExpiresAt: null,
    networkAttempts: 0,
    productionAuthority: "none"
  });
  const cancelledState = second.runtimeState({ leaseReceipt: acquired.leaseReceipt });
  assert.deepEqual(evaluateRecurrenceGate(cancelledState, now), { reasonCode: "invocation_cancelled" });
});

test("synthetic recurrence treats missed schedules and expired leases as terminal", () => {
  let now = new Date("2026-07-27T10:02:00.001Z");
  const missedStore = syntheticRecurrence.createSyntheticRecurrenceStore();
  const missed = syntheticRecurrence.createSyntheticRecurrenceAdapter({
    store: missedStore,
    clock: () => new Date(now)
  });
  const input = {
    scheduleKey: "daily:2026-07-27",
    runId: "run-late",
    scheduledFor: "2026-07-27T09:17:00.000Z"
  };
  assert.equal(missed.acquire(input).reasonCode, "missed_run_no_catch_up");
  now = new Date("2026-07-27T09:18:00.000Z");
  assert.equal(missed.acquire({ ...input, runId: "run-retry" }).reasonCode, "missed_run_no_catch_up");

  const leaseStore = syntheticRecurrence.createSyntheticRecurrenceStore();
  const lease = syntheticRecurrence.createSyntheticRecurrenceAdapter({
    store: leaseStore,
    clock: () => new Date(now)
  });
  lease.acquire({ ...input, runId: "run-on-time" });
  now = new Date("2026-07-27T09:28:00.001Z");
  assert.equal(lease.acquire({ ...input, runId: "run-after-expiry" }).reasonCode, "lease_replay_forbidden");
  assert.equal(lease.resume().reasonCode, "resume_not_authorized");
});

test("conflicting schedule metadata cannot overwrite an active synthetic lease", () => {
  const now = new Date("2026-07-27T09:18:00.000Z");
  const store = syntheticRecurrence.createSyntheticRecurrenceStore();
  const first = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock: () => new Date(now) });
  const second = syntheticRecurrence.createSyntheticRecurrenceAdapter({ store, clock: () => new Date(now) });
  const acquired = first.acquire({
    scheduleKey: "daily:2026-07-27",
    runId: "run-active",
    scheduledFor: "2026-07-27T09:17:00.000Z"
  });
  const conflict = second.acquire({
    scheduleKey: "daily:2026-07-27",
    runId: "run-conflict",
    scheduledFor: "2026-07-27T08:00:00.000Z"
  });
  assert.equal(conflict.reasonCode, "active_overlap");
  assert.deepEqual(evaluateRecurrenceGate(first.runtimeState({ leaseReceipt: acquired.leaseReceipt }), now), {
    accepted: true
  });
});
