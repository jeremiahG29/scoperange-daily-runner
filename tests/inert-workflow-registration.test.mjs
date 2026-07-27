import assert from "node:assert/strict";
import fs from "node:fs";
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
import { execute } from "../bootstrap/entry.js";
import { createZeroEffectReceipt } from "../bootstrap/operational-receipt.js";
import { evaluateRecurrenceGate, evaluateRuntimeGate } from "../bootstrap/runtime-gate.js";

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
  assert.equal(exposure.schemaVersion, "scoperange-public-runner-exposure-v2");
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
  ]) assert.doesNotMatch(source, pattern);
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

test("activation, identity, and exact-target authorities remain unconfigured", () => {
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
    schemaVersion: "scoperange-production-identity-claims-v1",
    requiredClaims: [
      "audience",
      "repository_id",
      "repository_owner_id",
      "ref",
      "workflow_ref",
      "event_name",
      "sha",
      "run_attempt",
      "environment"
    ],
    shortLivedIdentityRequired: true,
    broadFallbackAllowed: false,
    configured: false
  });
  assert.deepEqual(TARGET_BINDING_CONTRACT, {
    schemaVersion: "scoperange-exact-target-binding-v1",
    requiredClaims: ["provider_account_digest", "target_digest", "identity_claims_digest"],
    exactTargetCount: 1,
    providerSideBindingRequired: true,
    rawConnectionStringAllowed: false,
    implicitTargetAllowed: false,
    callerOverrideAllowed: false,
    configured: false,
    writerConnected: false
  });
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
