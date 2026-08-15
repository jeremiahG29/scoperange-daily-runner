import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const approvedCommit = "a".repeat(40);
const expectedTlsCaSha256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7";
const expectedTlsCaFingerprint = "80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA";
const truncatedPrivateKeyMaterial = [
  ["-----BEGIN OPENSSH", "PRIVATE KEY-----"].join(" "),
  "b3BlbnNzaC1rZXktdjEAc3ludGhldGlj",
  ["-----END OPENSSH", "PRIVATE KEY-----"].join(" "),
  ""
].join("\n");

function validSyntheticGitHubEnvelope() {
  return {
    repository: "jeremiahG29/scoperange-daily-runner",
    repositoryId: "1313256299",
    ref: "refs/heads/main",
    refProtected: true,
    workflowRef: "jeremiahG29/scoperange-daily-runner/.github/workflows/scoperange-metadata-proof.yml@refs/heads/main",
    workflowSha: approvedCommit,
    eventName: "workflow_dispatch",
    inputCount: 0,
    runAttempt: 1,
    observedCommit: approvedCommit,
    approvedCommit,
    sourceLockDigest: `sha256:${"3".repeat(64)}`,
    expectedSourceLockDigest: `sha256:${"3".repeat(64)}`,
    lifecycleState: "clear",
    duplicateState: "clear",
    recurrenceAuthorized: false,
    acquisitionAuthorized: false,
    ingestionAuthorized: false,
    promotionAuthorized: false,
    pricingAuthorized: false
  };
}

const gateDriftMutators = [
  (value) => { value.refProtected = false; },
  (value) => { value.repositoryId = "123456789"; },
  (value) => { value.eventName = "schedule"; },
  (value) => { value.runAttempt = 2; },
  (value) => { value.approvedCommit = "b".repeat(40); },
  (value) => { value.sourceLockDigest = `sha256:${"4".repeat(64)}`; },
  (value) => { value.recurrenceAuthorized = true; },
  (value) => { value.inputCount = 1; },
  (value) => { value.unreviewed = true; }
];

const acceptedDecision = Object.freeze({
  disposition: "accepted",
  reasonCode: "metadata_proof_gate_accepted",
  authorization: "scoperange-metadata-proof-non-secret-gate-accepted-v1"
});

function git(cwd, args) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
    maxBuffer: 1024 * 1024
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function generateSyntheticDeployKey(root) {
  const identityPath = path.join(root, "synthetic-deploy-key");
  const result = spawnSync("ssh-keygen", [
    "-q", "-t", "ed25519", "-N", "", "-C", "synthetic@example.invalid", "-f", identityPath
  ], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env },
    windowsHide: true
  });
  assert.equal(result.status, 0, result.stderr);
  const derived = spawnSync("ssh-keygen", ["-y", "-f", identityPath], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env },
    windowsHide: true
  });
  assert.equal(derived.status, 0, derived.stderr);
  return {
    keyMaterial: fs.readFileSync(identityPath, "utf8"),
    publicKey: derived.stdout.trim()
  };
}

function fixtureLock(root) {
  const source = path.join(root, "source");
  const bare = path.join(root, "private.git");
  fs.mkdirSync(source);
  git(source, ["init", "--quiet"]);
  git(source, ["config", "user.name", "Synthetic Test"]);
  git(source, ["config", "user.email", "synthetic@example.invalid"]);
  git(source, ["commit", "--allow-empty", "-m", "synthetic base"]);
  const requiredAncestor = git(source, ["rev-parse", "HEAD"]);
  const bundleRoot = "scoperange/pricing-intelligence/connection-proof";
  const bundleDirectory = path.join(source, ...bundleRoot.split("/"));
  fs.mkdirSync(bundleDirectory, { recursive: true });
  const allowedPaths = [
    `${bundleRoot}/entry.js`,
    `${bundleRoot}/package-lock.json`,
    `${bundleRoot}/package.json`
  ];
  fs.writeFileSync(path.join(bundleDirectory, "entry.js"), "export const synthetic = true;\n", "utf8");
  fs.writeFileSync(path.join(bundleDirectory, "package.json"), "{\"private\":true,\"type\":\"module\"}\n", "utf8");
  fs.writeFileSync(path.join(bundleDirectory, "package-lock.json"), "{\"lockfileVersion\":3}\n", "utf8");
  git(source, ["add", "--", bundleRoot]);
  git(source, ["commit", "-m", "synthetic locked bundle"]);
  const commit = git(source, ["rev-parse", "HEAD"]);
  const tree = git(source, ["rev-parse", `${commit}^{tree}`]);
  const entries = git(source, ["ls-tree", "-r", commit, "--", bundleRoot])
    .split(/\r?\n/u)
    .map((line) => {
      const match = /^(\d{6}) blob ([0-9a-f]{40})\s+(.+)$/u.exec(line);
      assert.ok(match);
      return { mode: match[1], oid: match[2], path: match[3] };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
  const canonical = entries.map((entry) => `${entry.mode}\t${entry.oid}\t${entry.path}\n`).join("");
  const allowedBundleDigest = `sha256:${crypto.createHash("sha256").update(canonical, "utf8").digest("hex")}`;
  git(root, ["clone", "--quiet", "--bare", source, bare]);
  const { keyMaterial, publicKey } = generateSyntheticDeployKey(root);
  return {
    bare,
    keyMaterial,
    publicKey,
    lock: {
      schemaVersion: "scoperange-public-runner-source-lock-v1",
      lockVersion: "synthetic-connection-proof-v1",
      repository: "jeremiahG29/scopematch",
      approvedCommit: commit,
      requiredAncestor,
      approvedParent: requiredAncestor,
      approvedTree: tree,
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
    }
  };
}

function localGitSpawner(bare, records, publicKey) {
  const remote = "git@github.com:jeremiahG29/scopematch.git";
  return ({ program, args, cwd, env, signal }) => new Promise((resolve, reject) => {
    const mapped = args.map((arg) => arg === remote ? bare : arg);
    records.push({ program, args: [...args], cwd, env: { ...env } });
    if (program === "ssh-keygen") {
      resolve({ exitCode: 0, stdout: `${publicKey}\n`, stderr: "" });
      return;
    }
    if (signal.aborted) {
      reject(new Error("synthetic cancelled"));
      return;
    }
    const child = spawn(program, mapped, {
      cwd,
      env: { ...process.env, ...env },
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const onAbort = () => child.kill("SIGTERM");
    signal.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.on("error", (error) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.on("close", (code) => {
      signal.removeEventListener("abort", onAbort);
      resolve({ exitCode: code, stdout, stderr });
    });
  });
}

test("only an exact external post-merge binding accepts", async () => {
  const gate = await import("../bootstrap/metadata-connection-proof-gate.js");
  assert.deepEqual(gate.evaluateMetadataProofGate(validSyntheticGitHubEnvelope()), acceptedDecision);
  for (const mutate of gateDriftMutators) {
    const value = validSyntheticGitHubEnvelope();
    mutate(value);
    const rejected = gate.evaluateMetadataProofGate(value);
    assert.equal(rejected.disposition, "rejected");
    assert.equal(rejected.authorization, null);
    assert.equal(JSON.stringify(rejected).includes("unreviewed"), false);
  }
});

test("accepted output writes only one fixed line to a caller-supplied test file", async (context) => {
  const gate = await import("../bootstrap/metadata-connection-proof-gate.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-output-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "github-output");
  gate.writeAcceptedOutput(outputPath, acceptedDecision);
  assert.equal(
    fs.readFileSync(outputPath, "utf8"),
    "authorization=scoperange-metadata-proof-non-secret-gate-accepted-v1\n"
  );
  assert.throws(() => gate.writeAcceptedOutput(outputPath, { ...acceptedDecision, authorization: "other" }), {
    message: "SCOPERANGE_METADATA_PROOF_OUTPUT_REJECTED"
  });
});

test("exact fetch uses one commit-only local fixture operation and deletes the key", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-fetch-fixture-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { bare, keyMaterial, lock, publicKey } = fixtureLock(directory);
  const records = [];
  const result = await sourceLock.fetchLockedPrivateSource({
    lock,
    keyMaterial,
    spawnImpl: localGitSpawner(bare, records, publicKey),
    signal: new AbortController().signal
  });

  assert.deepEqual(result, {
    verified: true,
    commit: lock.approvedCommit,
    tree: lock.approvedTree,
    bundleDigest: lock.allowedBundleDigest
  });
  assert.equal(records.filter((record) => record.args.includes("fetch")).length, 1);
  const fetchRecord = records.find((record) => record.args.includes("fetch"));
  assert.ok(fetchRecord.args.includes("--no-tags"));
  assert.ok(fetchRecord.args.includes("--no-recurse-submodules"));
  assert.ok(fetchRecord.args.includes("--depth=2"));
  assert.equal(fetchRecord.args.at(-1), lock.approvedCommit);
  assert.equal(records.some((record) => record.args.some((arg) => /refs\/heads|refs\/tags|\bmain\b/iu.test(arg))), false);
  assert.equal(fetchRecord.env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(fetchRecord.env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(fetchRecord.env.GIT_CONFIG_KEY_0, "credential.helper");
  assert.equal(fetchRecord.env.GIT_CONFIG_VALUE_0, "");
  assert.match(fetchRecord.env.GIT_SSH_COMMAND, /IdentitiesOnly=yes/iu);
  assert.match(fetchRecord.env.GIT_SSH_COMMAND, /StrictHostKeyChecking=yes/iu);
  assert.match(fetchRecord.env.GIT_SSH_COMMAND, /UserKnownHostsFile=/iu);
  const keyPath = /-i\s+"([^"]+)"/u.exec(fetchRecord.env.GIT_SSH_COMMAND)?.[1];
  assert.ok(keyPath);
  assert.equal(fs.existsSync(keyPath), false);
});

test("real deploy-key material is normalized from Windows transport before SSH use", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-key-normalization-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { keyMaterial } = generateSyntheticDeployKey(directory);
  const transported = `\ufeff${keyMaterial.replace(/\n/gu, "\r\n")}`;
  const observed = await sourceLock.withEphemeralWorkspace({
    keyMaterial: transported,
    timeoutMs: 1000,
    operation: ({ identityPath }) => fs.readFileSync(identityPath, "utf8")
  });

  assert.equal(observed, keyMaterial);
  assert.equal(observed.includes("\r"), false);
  assert.equal(observed.startsWith("\ufeff"), false);
});

test("malformed deploy-key material is rejected before any Git command", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-key-preflight-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { lock } = fixtureLock(directory);
  let processCalls = 0;

  await assert.rejects(
    sourceLock.fetchLockedPrivateSource({
      lock,
      keyMaterial: "ssh-ed25519 synthetic-public-key-must-not-be-used-as-private-material",
      spawnImpl: async () => {
        processCalls += 1;
        return { exitCode: 0, stdout: "", stderr: "" };
      },
      signal: new AbortController().signal
    }),
    (error) => error.message === "SCOPERANGE_PUBLIC_SOURCE_FETCH_REJECTED"
      && error.reasonCode === "private_source_key_rejected"
  );
  assert.equal(processCalls, 0);

  const programs = [];
  await assert.rejects(
    sourceLock.fetchLockedPrivateSource({
      lock,
      keyMaterial: truncatedPrivateKeyMaterial,
      spawnImpl: async ({ program }) => {
        programs.push(program);
        return { exitCode: 1, stdout: "", stderr: "synthetic-key-validation-rejection" };
      },
      signal: new AbortController().signal
    }),
    (error) => error.message === "SCOPERANGE_PUBLIC_SOURCE_FETCH_REJECTED"
      && error.reasonCode === "private_source_key_rejected"
  );
  assert.deepEqual(programs, ["ssh-keygen"]);
});

test("a verified checkout can be consumed only inside its ephemeral workspace", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-fetch-consumer-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { bare, keyMaterial, lock, publicKey } = fixtureLock(directory);
  let checkoutPath;
  const consumed = await sourceLock.fetchLockedPrivateSource({
    lock,
    keyMaterial,
    spawnImpl: localGitSpawner(bare, [], publicKey),
    signal: new AbortController().signal,
    consumeVerifiedCheckout: async (value) => {
      assert.deepEqual(
        Object.keys(value).sort(),
        ["bundleRoot", "checkoutPath", "runManagedProcess", "workspacePath"]
      );
      assert.equal(typeof value.runManagedProcess, "function");
      checkoutPath = value.checkoutPath;
      assert.equal(fs.existsSync(path.join(value.checkoutPath, ...value.bundleRoot.split("/"), "entry.js")), true);
      return Object.freeze({ consumed: true });
    }
  });
  assert.deepEqual(consumed, { consumed: true });
  assert.equal(fs.existsSync(checkoutPath), false);
});

test("fetch cancellation and failure are sanitized and leave no ephemeral workspace", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-fetch-failure-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { keyMaterial, lock } = fixtureLock(directory);
  const canary = "synthetic-private-key-path-canary";
  const before = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("scoperange-public-runner-")));
  await assert.rejects(
    sourceLock.fetchLockedPrivateSource({
      lock,
      keyMaterial,
      spawnImpl: async () => { throw new Error(canary); },
      signal: new AbortController().signal
    }),
    (error) => error.message === "SCOPERANGE_PUBLIC_SOURCE_FETCH_REJECTED"
      && !error.message.includes(canary)
  );
  const cancelled = new AbortController();
  cancelled.abort(new Error(canary));
  await assert.rejects(
    sourceLock.fetchLockedPrivateSource({
      lock,
      keyMaterial,
      spawnImpl: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
      signal: cancelled.signal
    }),
    (error) => error.message === "SCOPERANGE_PUBLIC_SOURCE_FETCH_CANCELLED"
      && !error.message.includes(canary)
  );
  const after = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("scoperange-public-runner-")));
  assert.deepEqual(after, before);
});

test("source fetch failures expose only fixed non-sensitive substages", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-fetch-stages-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { keyMaterial, lock, publicKey } = fixtureLock(directory);
  const canary = "synthetic-source-stage-canary";
  const cases = [
    { reasonCode: "private_source_key_rejected", keyMaterial: `key\0${canary}`, rejectAt: null },
    { reasonCode: "private_source_git_init_rejected", keyMaterial, rejectAt: 2 },
    { reasonCode: "private_source_git_fetch_rejected", keyMaterial, rejectAt: 3 },
    { reasonCode: "private_source_checkout_rejected", keyMaterial, rejectAt: 4 },
    { reasonCode: "private_source_verification_rejected", keyMaterial, rejectAt: null }
  ];

  for (const testCase of cases) {
    let calls = 0;
    await assert.rejects(
      sourceLock.fetchLockedPrivateSource({
        lock,
        keyMaterial: testCase.keyMaterial,
        signal: new AbortController().signal,
        spawnImpl: async ({ program }) => {
          calls += 1;
          if (calls === testCase.rejectAt) return { exitCode: 1, stdout: "", stderr: canary };
          return {
            exitCode: 0,
            stdout: program === "ssh-keygen" ? `${publicKey}\n` : "",
            stderr: ""
          };
        }
      }),
      (error) => error.message === "SCOPERANGE_PUBLIC_SOURCE_FETCH_REJECTED"
        && error.reasonCode === testCase.reasonCode
        && !error.message.includes(canary)
    );
  }
});

test("a stubborn real child is forcibly terminated before ephemeral cleanup completes", async (context) => {
  const sourceLock = await import("../bootstrap/source-lock.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-stubborn-child-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const pidPath = path.join(directory, "child.pid");
  const before = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("scoperange-public-runner-")));
  const startedAt = Date.now();
  await assert.rejects(
    sourceLock.withEphemeralWorkspace({
      fakeKeyMaterial: "synthetic-key-material",
      timeoutMs: 500,
      operation: ({ checkoutPath, runManagedProcess, signal }) => runManagedProcess({
        program: process.execPath,
        args: [
          "-e",
          "const fs=require('node:fs');fs.writeFileSync(process.argv[1],String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000)",
          pidPath
        ],
        cwd: checkoutPath,
        env: {},
        stdin: "",
        signal,
        maxOutputBytes: 1024
      })
    }),
    (error) => error.message === "ephemeral_operation_timeout"
  );
  assert.ok(Date.now() - startedAt < 5000, "cleanup must remain bounded");
  assert.equal(fs.existsSync(pidPath), true, "the real child must start before timeout");
  const pid = Number.parseInt(fs.readFileSync(pidPath, "utf8"), 10);
  assert.ok(Number.isInteger(pid) && pid > 0);
  let childAlive = true;
  try {
    process.kill(pid, 0);
  } catch {
    childAlive = false;
  }
  assert.equal(childAlive, false, "the stubborn child must not survive cleanup");
  const after = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("scoperange-public-runner-")));
  assert.deepEqual(after, before);
});

test("the checked-in public entry is disabled before environment access", async () => {
  const entry = await import("../bootstrap/metadata-connection-proof-entry.js");
  const environment = new Proxy({}, {
    get() { throw new Error("synthetic-environment-canary"); },
    ownKeys() { throw new Error("synthetic-environment-canary"); }
  });
  const lines = [];
  const receipt = await entry.execute({
    environment,
    log: (line) => lines.push(line),
    now: new Date("2026-07-30T12:00:00.000Z")
  });
  assert.deepEqual(receipt, {
    schemaVersion: "scoperange-public-metadata-proof-receipt-v1",
    disposition: "rejected",
    reasonCode: "connection_proof_not_configured",
    secretReads: 0,
    sourceCheckoutAttempts: 0,
    childProcesses: 0,
    networkAttempts: 0,
    databaseConnections: 0,
    pricingEffects: 0,
    productionAuthority: "none"
  });
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0]), receipt);
  assert.equal(lines[0].includes("synthetic-environment-canary"), false);
});

test("the public bridge loads only the reviewed Supabase root CA artifact", async () => {
  const entry = await import("../bootstrap/metadata-connection-proof-entry.js");
  const { METADATA_CONNECTION_PROOF_CONTRACT: contract } = await import("../bootstrap/metadata-connection-proof-contract.js");
  const caPath = path.resolve("bootstrap/supabase-root-2021-ca.crt");
  assert.equal(
    fs.readFileSync(path.resolve(".gitattributes"), "utf8"),
    ".gitattributes text eol=lf\nbootstrap/supabase-root-2021-ca.crt text eol=lf\n"
  );
  assert.deepEqual(contract.tlsCa, {
    source: "checked_in_public_artifact",
    path: "bootstrap/supabase-root-2021-ca.crt",
    sha256: expectedTlsCaSha256,
    runtimeDownloadAllowed: false,
    environmentSecretRequired: false,
    callerOverrideAllowed: false,
    verifyFullRequired: true
  });
  assert.equal(fs.existsSync(caPath), true);
  const pem = fs.readFileSync(caPath, "utf8");
  assert.equal(crypto.createHash("sha256").update(pem, "utf8").digest("hex"), expectedTlsCaSha256);

  const value = entry.loadPinnedTlsCa();
  assert.deepEqual(value, {
    tlsCaPem: pem,
    tlsCaDigest: `sha256:${expectedTlsCaSha256}`
  });
  const certificate = new crypto.X509Certificate(value.tlsCaPem);
  assert.equal(certificate.ca, true);
  assert.equal(certificate.subject, certificate.issuer);
  assert.equal(certificate.fingerprint256, expectedTlsCaFingerprint);
  assert.ok(Date.parse(certificate.validFrom) <= Date.now());
  assert.ok(Date.parse(certificate.validTo) > Date.now());

  assert.throws(
    () => entry.loadPinnedTlsCa({ readFileImpl: () => pem.replace("MIIDxD", "NIIDxD") }),
    { message: "SCOPERANGE_PUBLIC_TLS_CA_REJECTED" }
  );
});

test("the future bridge keeps secrets out of argv, environment, cache, and output", async (context) => {
  const entry = await import("../bootstrap/metadata-connection-proof-entry.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-bridge-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const checkoutPath = path.join(directory, "checkout");
  const workspacePath = path.join(directory, "workspace");
  const bundleRoot = "scoperange/pricing-intelligence/connection-proof";
  fs.mkdirSync(path.join(checkoutPath, ...bundleRoot.split("/")), { recursive: true });
  fs.mkdirSync(workspacePath);
  const canary = "synthetic-bridge-private-canary";
  const privateInput = {
    configurationVersion: "scoperange-runtime-config-v1",
    credentialVersion: "scoperange-runtime-credential-v1-20260701T000000.000Z",
    credentialNotBefore: "2026-07-01T00:00:00.000Z",
    credentialExpiresAt: "2026-09-06T00:00:00.000Z",
    databaseHost: "synthetic.pooler.example.test",
    databasePort: 6543,
    databaseName: "postgres",
    databaseUser: "scoperange_intelligence_runtime_v1.syntheticprojectref0",
    databasePassword: canary,
    tlsServerName: "synthetic.pooler.example.test",
    expectedProjectRefDigest: `sha256:${"1".repeat(64)}`,
    observedAt: "2026-07-30T12:00:00.000Z"
  };
  const privateReceipt = {
    schemaVersion: "scoperange-metadata-connection-proof-receipt-v1",
    disposition: "rejected",
    reasonCode: "connection_proof_not_authorized",
    observedAt: "2026-07-30T12:00:00.000Z",
    digests: { contract: `sha256:${"3".repeat(64)}`, metadata: null, source: null },
    counts: {
      expectedForcedRlsTables: 19,
      expectedResearchFunctions: 11,
      expectedClientPrivateGrants: 0,
      expectedRuntimeDirectPrivateGrants: 0,
      expectedRuntimeSessions: 1,
      expectedSessionsAfterCleanup: 0,
      expectedClientConstructions: 1,
      expectedConnectionAttempts: 1
    },
    secretReads: 0,
    clientConstructions: 0,
    connectionAttempts: 0,
    metadataQueries: 0,
    cleanup: { rollbackAttempted: false, rollbackSucceeded: false, clientClosed: false },
    databaseWrites: 0,
    researchFunctionCalls: 0,
    recurrenceEffects: 0,
    acquisitionEffects: 0,
    ingestionEffects: 0,
    promotionEffects: 0,
    pricingEffects: 0,
    productionAuthority: "none"
  };
  const processCalls = [];
  const result = await entry.executeConfiguredMetadataProof({
    authorization: acceptedDecision.authorization,
    lock: { bundleRoot },
    keyMaterial: canary,
    privateInput,
    signal: new AbortController().signal,
    fetchImpl: async (value) => value.consumeVerifiedCheckout({ checkoutPath, workspacePath, bundleRoot }),
    processImpl: async (value) => {
      processCalls.push(structuredClone(value));
      if (value.program === process.execPath) {
        return { exitCode: 0, stdout: `${JSON.stringify(privateReceipt)}\n`, stderr: "" };
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    }
  });
  assert.deepEqual(result, privateReceipt);
  assert.equal(processCalls.length, 2);
  assert.equal(processCalls[0].args[0], "ci");
  assert.ok(processCalls[0].args.includes("--ignore-scripts"));
  assert.ok(processCalls[0].args.includes("--cache"));
  assert.ok(processCalls[0].args.includes(path.join(workspacePath, "npm-cache")));
  assert.deepEqual(processCalls[1].args, ["entry.js"]);
  assert.deepEqual(JSON.parse(processCalls[1].stdin), {
    ...privateInput,
    ...entry.loadPinnedTlsCa()
  });
  const publicProcessShape = processCalls.map(({ stdin, ...value }) => value);
  assert.equal(JSON.stringify(publicProcessShape).includes(canary), false);
  assert.equal(JSON.stringify(result).includes(canary), false);

  let rejectedFetches = 0;
  await assert.rejects(
    entry.executeConfiguredMetadataProof({
      authorization: acceptedDecision.authorization,
      lock: { bundleRoot },
      keyMaterial: canary,
      privateInput: {
        ...privateInput,
        tlsCaPem: "synthetic-caller-ca-canary",
        tlsCaDigest: `sha256:${"2".repeat(64)}`
      },
      signal: new AbortController().signal,
      fetchImpl: async () => { rejectedFetches += 1; }
    }),
    { message: "SCOPERANGE_PUBLIC_METADATA_PROOF_BRIDGE_REJECTED" }
  );
  assert.equal(rejectedFetches, 0);
});

test("the metadata proof workflow candidate is manual, closed, and unregistered", () => {
  const candidatePath = path.resolve("inactive-metadata-connection-proof-workflow.yml");
  const value = JSON.parse(fs.readFileSync(candidatePath, "utf8"));
  assert.deepEqual(Object.keys(value), ["name", "on", "permissions", "concurrency", "jobs"]);
  assert.deepEqual(value.on, { workflow_dispatch: {} });
  assert.deepEqual(value.permissions, {});
  assert.deepEqual(value.concurrency, {
    group: "scoperange-metadata-connection-proof-v1",
    "cancel-in-progress": false
  });
  assert.deepEqual(Object.keys(value.jobs), ["gate", "proof"]);
  assert.equal(value.jobs.gate.environment, undefined);
  assert.equal(JSON.stringify(value.jobs.gate).includes("secrets."), false);
  assert.equal(value.jobs.gate["timeout-minutes"], 1);
  assert.deepEqual(value.jobs.proof.needs, ["gate"]);
  assert.equal(
    value.jobs.proof.if,
    "needs.gate.outputs.authorization == 'scoperange-metadata-proof-non-secret-gate-accepted-v1'"
  );
  assert.equal(value.jobs.proof.environment, "scoperange-production-disabled-v1");
  assert.equal(value.jobs.proof["timeout-minutes"], 3);
  assert.deepEqual(value.jobs.proof.permissions, { contents: "read" });
  const actionSteps = Object.values(value.jobs).flatMap((job) => job.steps).filter((step) => step.uses);
  assert.deepEqual([...new Set(actionSteps.map((step) => step.uses))].sort(), [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
  ]);
  const proofEnvironment = value.jobs.proof.steps.at(-1).env;
  assert.deepEqual(Object.keys(proofEnvironment).sort(), [
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
  ]);
  const raw = fs.readFileSync(candidatePath, "utf8");
  assert.doesNotMatch(raw, /cache\/restore|cache\/save|upload-artifact|download-artifact|schedule|workflow_call/iu);
  assert.doesNotMatch(raw, /SCOPERANGE_DB_TLS_CA|BEGIN CERTIFICATE|postgres(?:ql)?:\/\//iu);
  assert.equal(fs.existsSync(path.resolve(".github/workflows/scoperange-metadata-proof.yml")), false);
});

test("candidate command entry points fail closed with fixed output", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-proof-cli-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "github-output");
  const envelope = validSyntheticGitHubEnvelope();
  const gateResult = spawnSync(process.execPath, [path.resolve("bootstrap/metadata-connection-proof-gate.js")], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      SCOPERANGE_METADATA_REPOSITORY: envelope.repository,
      SCOPERANGE_METADATA_REPOSITORY_ID: envelope.repositoryId,
      SCOPERANGE_METADATA_REF: envelope.ref,
      SCOPERANGE_METADATA_REF_PROTECTED: "true",
      SCOPERANGE_METADATA_WORKFLOW_REF: envelope.workflowRef,
      SCOPERANGE_METADATA_WORKFLOW_SHA: envelope.workflowSha,
      SCOPERANGE_METADATA_EVENT_NAME: envelope.eventName,
      SCOPERANGE_METADATA_RUN_ATTEMPT: "1",
      SCOPERANGE_METADATA_OBSERVED_COMMIT: envelope.observedCommit,
      SCOPERANGE_METADATA_APPROVED_COMMIT: envelope.approvedCommit,
      SCOPERANGE_METADATA_SOURCE_LOCK_DIGEST: envelope.sourceLockDigest,
      SCOPERANGE_METADATA_EXPECTED_SOURCE_LOCK_DIGEST: envelope.expectedSourceLockDigest,
      SCOPERANGE_METADATA_LIFECYCLE_STATE: "clear",
      SCOPERANGE_METADATA_DUPLICATE_STATE: "clear",
      SCOPERANGE_METADATA_RECURRENCE_AUTHORIZED: "false",
      SCOPERANGE_METADATA_ACQUISITION_AUTHORIZED: "false",
      SCOPERANGE_METADATA_INGESTION_AUTHORIZED: "false",
      SCOPERANGE_METADATA_PROMOTION_AUTHORIZED: "false",
      SCOPERANGE_METADATA_PRICING_AUTHORIZED: "false",
      GITHUB_OUTPUT: outputPath
    }
  });
  assert.equal(gateResult.status, 0, gateResult.stderr);
  assert.equal(gateResult.stdout, "");
  assert.equal(
    fs.readFileSync(outputPath, "utf8"),
    "authorization=scoperange-metadata-proof-non-secret-gate-accepted-v1\n"
  );

  const canary = "synthetic-cli-secret-canary";
  const entryResult = spawnSync(process.execPath, [path.resolve("bootstrap/metadata-connection-proof-entry.js")], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, SCOPERANGE_DB_PASSWORD: canary }
  });
  assert.equal(entryResult.status, 1);
  const receipt = JSON.parse(entryResult.stdout);
  assert.equal(receipt.reasonCode, "connection_proof_not_configured");
  assert.equal(entryResult.stdout.includes(canary), false);
  assert.equal(entryResult.stderr, "");
});
