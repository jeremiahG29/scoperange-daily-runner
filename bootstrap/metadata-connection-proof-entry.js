import { METADATA_CONNECTION_PROOF_CONTRACT } from "./metadata-connection-proof-contract.js";
import { spawn } from "node:child_process";
import path from "node:path";
import { fetchLockedPrivateSource } from "./source-lock.js";

const DISABLED_RECEIPT = Object.freeze({
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

export async function execute({ environment, log }) {
  if (METADATA_CONNECTION_PROOF_CONTRACT.configured !== true) {
    log(JSON.stringify(DISABLED_RECEIPT));
    return DISABLED_RECEIPT;
  }
  void environment;
  throw new Error("SCOPERANGE_METADATA_CONNECTION_PROOF_NOT_CONFIGURED");
}

const PRIVATE_INPUT_KEYS = Object.freeze([
  "configurationVersion",
  "credentialVersion",
  "credentialNotBefore",
  "credentialExpiresAt",
  "databaseHost",
  "databasePort",
  "databaseName",
  "databaseUser",
  "databasePassword",
  "tlsServerName",
  "expectedProjectRefDigest",
  "tlsCaPem",
  "tlsCaDigest",
  "observedAt"
]);
const PRIVATE_RECEIPT_KEYS = Object.freeze([
  "schemaVersion",
  "disposition",
  "reasonCode",
  "observedAt",
  "digests",
  "counts",
  "secretReads",
  "clientConstructions",
  "connectionAttempts",
  "metadataQueries",
  "cleanup",
  "databaseWrites",
  "researchFunctionCalls",
  "recurrenceEffects",
  "acquisitionEffects",
  "ingestionEffects",
  "promotionEffects",
  "pricingEffects",
  "productionAuthority"
]);
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function validPrivateReceipt(value) {
  return exactKeys(value, PRIVATE_RECEIPT_KEYS)
    && value.schemaVersion === "scoperange-metadata-connection-proof-receipt-v1"
    && ["verified", "rejected"].includes(value.disposition)
    && typeof value.reasonCode === "string" && /^[a-z_]{3,64}$/u.test(value.reasonCode)
    && TIMESTAMP.test(value.observedAt ?? "")
    && exactKeys(value.digests, ["contract", "metadata", "source"])
    && DIGEST.test(value.digests.contract ?? "")
    && (value.digests.metadata === null || DIGEST.test(value.digests.metadata ?? ""))
    && (value.digests.source === null || DIGEST.test(value.digests.source ?? ""))
    && exactKeys(value.counts, [
      "expectedForcedRlsTables",
      "expectedResearchFunctions",
      "expectedClientPrivateGrants",
      "expectedRuntimeDirectPrivateGrants",
      "expectedRuntimeSessions",
      "expectedSessionsAfterCleanup",
      "expectedClientConstructions",
      "expectedConnectionAttempts"
    ])
    && JSON.stringify(value.counts) === JSON.stringify({
      expectedForcedRlsTables: 19,
      expectedResearchFunctions: 11,
      expectedClientPrivateGrants: 0,
      expectedRuntimeDirectPrivateGrants: 0,
      expectedRuntimeSessions: 1,
      expectedSessionsAfterCleanup: 0,
      expectedClientConstructions: 1,
      expectedConnectionAttempts: 1
    })
    && exactKeys(value.cleanup, ["rollbackAttempted", "rollbackSucceeded", "clientClosed"])
    && Object.values(value.cleanup).every((item) => typeof item === "boolean")
    && [
      "secretReads", "clientConstructions", "connectionAttempts", "metadataQueries",
      "databaseWrites", "researchFunctionCalls", "recurrenceEffects", "acquisitionEffects",
      "ingestionEffects", "promotionEffects", "pricingEffects"
    ].every((key) => Number.isInteger(value[key]) && value[key] >= 0)
    && value.databaseWrites === 0
    && value.researchFunctionCalls === 0
    && value.recurrenceEffects === 0
    && value.acquisitionEffects === 0
    && value.ingestionEffects === 0
    && value.promotionEffects === 0
    && value.pricingEffects === 0
    && value.productionAuthority === "none";
}

function defaultProcessImpl({ program, args, cwd, env, stdin, signal, maxOutputBytes }) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, {
      cwd,
      env: {
        PATH: process.env.PATH ?? "",
        SystemRoot: process.env.SystemRoot ?? "",
        ...env
      },
      windowsHide: true,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let outputRejected = false;
    const onData = (target) => (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) {
        outputRejected = true;
        child.kill("SIGTERM");
      } else if (target === "stdout") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
    };
    const onAbort = () => child.kill("SIGTERM");
    signal.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", onData("stdout"));
    child.stderr.on("data", onData("stderr"));
    child.once("error", (error) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.once("close", (exitCode) => {
      signal.removeEventListener("abort", onAbort);
      if (outputRejected || signal.aborted) reject(new Error("bridge process rejected"));
      else resolve({ exitCode, stdout, stderr });
    });
    child.stdin.end(stdin ?? "");
  });
}

async function runBridgeProcess(processImpl, value) {
  const result = await processImpl({ ...value, maxOutputBytes: 64 * 1024 });
  if (!result || result.exitCode !== 0
    || typeof result.stdout !== "string" || typeof result.stderr !== "string"
    || Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > 64 * 1024) {
    throw new Error("bridge process rejected");
  }
  return result;
}

export async function executeConfiguredMetadataProof({
  authorization,
  lock,
  keyMaterial,
  privateInput,
  signal,
  fetchImpl = fetchLockedPrivateSource,
  processImpl = defaultProcessImpl
} = {}) {
  try {
    if (authorization !== "scoperange-metadata-proof-non-secret-gate-accepted-v1"
      || !lock || lock.bundleRoot !== "scoperange/pricing-intelligence/connection-proof"
      || typeof keyMaterial !== "string" || !keyMaterial || keyMaterial.length > 16_384
      || !exactKeys(privateInput, PRIVATE_INPUT_KEYS)
      || !signal || typeof signal.aborted !== "boolean" || signal.aborted
      || typeof fetchImpl !== "function" || typeof processImpl !== "function") {
      throw new Error("bridge input rejected");
    }
    let consumed = false;
    let consumedResult;
    const result = await fetchImpl({
      lock,
      keyMaterial,
      signal,
      consumeVerifiedCheckout: async ({ checkoutPath, workspacePath, bundleRoot }) => {
        if (!path.isAbsolute(checkoutPath) || !path.isAbsolute(workspacePath)
          || bundleRoot !== lock.bundleRoot) throw new Error("checkout rejected");
        const bundlePath = path.resolve(checkoutPath, ...bundleRoot.split("/"));
        if (!bundlePath.startsWith(`${path.resolve(checkoutPath)}${path.sep}`)) throw new Error("checkout rejected");
        const cachePath = path.join(workspacePath, "npm-cache");
        const install = await runBridgeProcess(processImpl, {
          program: process.platform === "win32" ? "npm.cmd" : "npm",
          args: [
            "ci", "--ignore-scripts", "--no-audit", "--no-fund",
            "--cache", cachePath, "--prefer-offline=false"
          ],
          cwd: bundlePath,
          env: {
            npm_config_cache: cachePath,
            npm_config_ignore_scripts: "true",
            npm_config_audit: "false",
            npm_config_fund: "false"
          },
          stdin: "",
          signal
        });
        if (install.stdout !== "" || install.stderr !== "") throw new Error("install output rejected");
        const child = await runBridgeProcess(processImpl, {
          program: process.execPath,
          args: ["entry.js"],
          cwd: bundlePath,
          env: { NODE_ENV: "production" },
          stdin: `${JSON.stringify(privateInput)}\n`,
          signal
        });
        if (child.stderr !== "" || !child.stdout.endsWith("\n")
          || child.stdout.trim().includes("\n")) throw new Error("child output rejected");
        const receipt = JSON.parse(child.stdout);
        if (!validPrivateReceipt(receipt)) throw new Error("receipt rejected");
        consumed = true;
        consumedResult = Object.freeze(receipt);
        return consumedResult;
      }
    });
    if (!consumed || result !== consumedResult) throw new Error("verified consumption rejected");
    return consumedResult;
  } catch {
    if (signal?.aborted) throw new Error("SCOPERANGE_PUBLIC_METADATA_PROOF_BRIDGE_CANCELLED");
    throw new Error("SCOPERANGE_PUBLIC_METADATA_PROOF_BRIDGE_REJECTED");
  }
}
