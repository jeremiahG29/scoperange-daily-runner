import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  PRODUCTION_RUNNER_AUTHORIZATION,
  PRODUCTION_RUNNER_BRIDGE_CONFIGURED,
  PRODUCTION_RUNNER_PRIVATE_BUNDLE
} from "./production-runner-contract.js";
import { loadPinnedTlsCa } from "./metadata-connection-proof-entry.js";
import { createApprovedProductionInput } from "./production-runner-plan.js";
import { fetchLockedPrivateSource, sourceLockDigest } from "./source-lock.js";

const COMMIT = /^[0-9a-f]{40}$/u;
const SOURCE_LOCK_PATH = fileURLToPath(new URL("../production-source-lock.example.json", import.meta.url));

const DISABLED_RECEIPT = Object.freeze({
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
const PRIVATE_RECEIPT_KEYS = Object.freeze([
  "schemaVersion", "disposition", "reasonCode", "sourceRequests", "databaseTransactions",
  "evidenceWrites", "numericEvidenceCount", "proposalEffects", "promotionEffects",
  "pricingEffects", "productionAuthority"
]);

const ACCEPTED_GATE_RECEIPT = Object.freeze({
  schemaVersion: "scoperange-public-production-runner-gate-receipt-v1",
  disposition: "accepted",
  reasonCode: "accepted",
  authorization: PRODUCTION_RUNNER_AUTHORIZATION
});

function rejectedGate(reasonCode) {
  return Object.freeze({
    schemaVersion: "scoperange-public-production-runner-gate-receipt-v1",
    disposition: "rejected",
    reasonCode,
    authorization: null
  });
}

export function loadProductionSourceLock() {
  const raw = fs.readFileSync(SOURCE_LOCK_PATH, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 64 * 1024) throw new Error("SCOPERANGE_PUBLIC_SOURCE_LOCK_REJECTED");
  return JSON.parse(raw);
}

export function evaluateProductionRunnerGate({ environment, lock = loadProductionSourceLock() } = {}) {
  const observedPublicCommit = environment?.SCOPERANGE_OBSERVED_PUBLIC_COMMIT;
  const approvedPublicCommit = environment?.SCOPERANGE_APPROVED_PUBLIC_COMMIT;
  const approvedPrivateCommit = environment?.SCOPERANGE_APPROVED_PRIVATE_COMMIT;
  const expectedSourceLockDigest = environment?.SCOPERANGE_SOURCE_LOCK_DIGEST;
  const releaseState = environment?.SCOPERANGE_RELEASE_STATE;
  if (releaseState !== "authorized") return rejectedGate("release_state_rejected");
  if (!COMMIT.test(observedPublicCommit ?? "") || approvedPublicCommit !== observedPublicCommit) {
    return rejectedGate("public_commit_rejected");
  }
  if (!COMMIT.test(approvedPrivateCommit ?? "") || approvedPrivateCommit !== lock?.approvedCommit) {
    return rejectedGate("private_commit_rejected");
  }
  if (expectedSourceLockDigest !== sourceLockDigest(lock)) return rejectedGate("source_lock_rejected");
  if (lock?.activationAuthorized !== false || lock?.bundleRoot !== PRODUCTION_RUNNER_PRIVATE_BUNDLE) {
    return rejectedGate("source_lock_rejected");
  }
  return ACCEPTED_GATE_RECEIPT;
}

export function writeAcceptedProductionRunnerOutput(outputPath, decision) {
  if (decision !== ACCEPTED_GATE_RECEIPT || typeof outputPath !== "string" || !path.isAbsolute(outputPath)
    || outputPath.includes("\0") || /[\r\n]/u.test(outputPath)) {
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_OUTPUT_REJECTED");
  }
  fs.appendFileSync(outputPath, `authorization=${PRODUCTION_RUNNER_AUTHORIZATION}\n`, { encoding: "utf8" });
}

function validPrivateReceipt(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...PRIVATE_RECEIPT_KEYS].sort())
    && value.schemaVersion === "scoperange-production-runner-receipt-v1"
    && ["evidence_recorded", "rejected"].includes(value.disposition)
    && typeof value.reasonCode === "string" && /^[a-z_]{3,64}$/u.test(value.reasonCode)
    && ["sourceRequests", "databaseTransactions", "evidenceWrites", "numericEvidenceCount",
      "proposalEffects", "promotionEffects", "pricingEffects"]
      .every((key) => Number.isInteger(value[key]) && value[key] >= 0)
    && value.numericEvidenceCount === 0 && value.proposalEffects === 0
    && value.promotionEffects === 0 && value.pricingEffects === 0
    && ["none", "evidence_only"].includes(value.productionAuthority);
}

async function runProcess(processImpl, value) {
  const result = await processImpl({ ...value, maxOutputBytes: 64 * 1024 });
  if (!result || result.exitCode !== 0 || typeof result.stdout !== "string" || typeof result.stderr !== "string"
    || Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > 64 * 1024) {
    throw new Error("process rejected");
  }
  return result;
}

export async function execute({ environment, log = console.log } = {}) {
  void environment;
  log(JSON.stringify(DISABLED_RECEIPT));
  return DISABLED_RECEIPT;
}

export async function executeProductionRunner({ environment, log = console.log,
  clock = () => new Date().toISOString(), randomBytesImpl, signal = AbortSignal.timeout(9 * 60 * 1000),
  bridgeImpl = executeConfiguredProductionBridge } = {}) {
  try {
    const lock = loadProductionSourceLock();
    const decision = evaluateProductionRunnerGate({ environment, lock });
    if (decision !== ACCEPTED_GATE_RECEIPT || PRODUCTION_RUNNER_BRIDGE_CONFIGURED !== true) {
      log(JSON.stringify(DISABLED_RECEIPT));
      return DISABLED_RECEIPT;
    }
    const observedAt = clock();
    const privateInput = createApprovedProductionInput({ environment, observedAt, randomBytesImpl });
    const receipt = await bridgeImpl({
      authorization: decision.authorization,
      lock,
      keyMaterial: environment?.SCOPERANGE_PRIVATE_SOURCE_DEPLOY_KEY,
      privateInput,
      signal
    });
    if (!validPrivateReceipt(receipt)) throw new Error("receipt rejected");
    log(JSON.stringify(receipt));
    return receipt;
  } catch {
    const receipt = Object.freeze({ ...DISABLED_RECEIPT, reasonCode: "production_run_failed" });
    log(JSON.stringify(receipt));
    return receipt;
  }
}

export async function executeConfiguredProductionBridge({ authorization, lock, keyMaterial, privateInput, signal,
  fetchImpl = fetchLockedPrivateSource, processImpl } = {}) {
  try {
    if (authorization !== PRODUCTION_RUNNER_AUTHORIZATION || lock?.bundleRoot !== PRODUCTION_RUNNER_PRIVATE_BUNDLE
      || typeof keyMaterial !== "string" || !keyMaterial || keyMaterial.length > 16_384
      || !privateInput || typeof privateInput !== "object" || Array.isArray(privateInput)
      || Buffer.byteLength(JSON.stringify(privateInput), "utf8") > 64 * 1024
      || !signal || typeof signal.aborted !== "boolean" || signal.aborted
      || typeof fetchImpl !== "function" || (processImpl !== undefined && typeof processImpl !== "function")) {
      throw new Error("bridge input rejected");
    }
    let consumed = false;
    let consumedResult;
    const deliveredPrivateInput = privateInput.database
      ? Object.freeze({ ...privateInput, database: Object.freeze({ ...privateInput.database, tlsCa: loadPinnedTlsCa().tlsCaPem }) })
      : privateInput;
    const result = await fetchImpl({
      lock, keyMaterial, signal,
      consumeVerifiedCheckout: async ({ checkoutPath, workspacePath, bundleRoot, runManagedProcess }) => {
        if (!path.isAbsolute(checkoutPath) || !path.isAbsolute(workspacePath) || bundleRoot !== lock.bundleRoot) throw new Error("checkout rejected");
        const bundlePath = path.resolve(checkoutPath, ...bundleRoot.split("/"));
        if (!bundlePath.startsWith(`${path.resolve(checkoutPath)}${path.sep}`)) throw new Error("checkout rejected");
        const selectedProcess = processImpl ?? runManagedProcess;
        if (typeof selectedProcess !== "function") throw new Error("process rejected");
        const cachePath = path.join(workspacePath, "npm-cache");
        await runProcess(selectedProcess, {
          program: process.platform === "win32" ? "npm.cmd" : "npm",
          args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", cachePath, "--prefer-offline=false"],
          cwd: bundlePath,
          env: { npm_config_cache: cachePath, npm_config_ignore_scripts: "true", npm_config_audit: "false", npm_config_fund: "false" },
          stdin: "", signal
        });
        const child = await runProcess(selectedProcess, {
          program: process.execPath, args: ["bridge-entry.js"], cwd: bundlePath,
          env: { NODE_ENV: "production" }, stdin: `${JSON.stringify(deliveredPrivateInput)}\n`, signal
        });
        if (child.stderr !== "" || !child.stdout.endsWith("\n") || child.stdout.trim().includes("\n")) throw new Error("child output rejected");
        const receipt = JSON.parse(child.stdout);
        if (!validPrivateReceipt(receipt)) throw new Error("receipt rejected");
        consumed = true;
        consumedResult = Object.freeze(receipt);
        return consumedResult;
      }
    });
    if (!consumed || result !== consumedResult) throw new Error("consumption rejected");
    return consumedResult;
  } catch {
    if (signal?.aborted) throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_BRIDGE_CANCELLED");
    throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_BRIDGE_REJECTED");
  }
}

const directEntry = process.argv[1] ? pathToFileURL(process.argv[1]).href === import.meta.url : false;
if (directEntry) {
  const mode = process.argv[2];
  if (mode === "gate") {
    const decision = evaluateProductionRunnerGate({ environment: process.env });
    console.log(JSON.stringify(decision));
    if (decision === ACCEPTED_GATE_RECEIPT) writeAcceptedProductionRunnerOutput(process.env.GITHUB_OUTPUT, decision);
    process.exitCode = decision === ACCEPTED_GATE_RECEIPT ? 0 : 1;
  } else if (mode === "run") {
    const receipt = await executeProductionRunner({ environment: process.env });
    process.exitCode = receipt.disposition === "evidence_recorded" ? 0 : 1;
  } else {
    await execute({ environment: process.env });
    process.exitCode = 1;
  }
}
