import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflowsRoot = path.join(root, ".github", "workflows");
const workflowRelativePath = ".github/workflows/scoperange-inert-shell.yml";
const workflowPath = path.join(root, ...workflowRelativePath.split("/"));
const exposurePath = path.join(root, "public-exposure-contract.json");

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
