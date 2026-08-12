import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  PRODUCTION_RUNNER_AUTHORIZATION,
  PRODUCTION_RUNNER_BRIDGE_CONFIGURED,
  PRODUCTION_RUNNER_PRIVATE_BUNDLE
} from "./production-runner-contract.js";
import { loadPinnedTlsCa } from "./metadata-connection-proof-entry.js";
import { fetchLockedPrivateSource } from "./source-lock.js";

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
  if (PRODUCTION_RUNNER_BRIDGE_CONFIGURED !== true) {
    log(JSON.stringify(DISABLED_RECEIPT));
    return DISABLED_RECEIPT;
  }
  void environment;
  throw new Error("SCOPERANGE_PUBLIC_PRODUCTION_RUNNER_CONFIGURATION_MISSING");
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
  await execute({ environment: process.env });
  process.exitCode = 1;
}
