import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { CONFIGURATION_KEYS } from "./contract.js";
import { createZeroEffectReceipt } from "./operational-receipt.js";
import { evaluateRuntimeGate } from "./runtime-gate.js";
import { sourceLockDigest } from "./source-lock.js";

const sourceLock = JSON.parse(fs.readFileSync(new URL("../source-lock.example.json", import.meta.url), "utf8"));
const expectedSourceLockDigest = sourceLockDigest(sourceLock);

function readConfiguration(environment) {
  const mode = environment.PUBLIC_RUNNER_MODE;
  if (mode !== "public_runner_candidate") return Object.freeze({ shortCircuitReason: "runner_disabled" });
  const configuration = { PUBLIC_RUNNER_MODE: mode };
  for (const key of CONFIGURATION_KEYS.slice(1)) configuration[key] = environment[key];
  return Object.freeze(configuration);
}

export function execute({ environment = process.env, now = new Date(), log = console.log } = {}) {
  let gate;
  try {
    const configuration = readConfiguration(environment);
    gate = configuration.shortCircuitReason
      ? Object.freeze({ reasonCode: configuration.shortCircuitReason })
      : evaluateRuntimeGate(configuration, now, expectedSourceLockDigest);
  } catch {
    gate = Object.freeze({ reasonCode: "configuration_unreadable" });
  }
  const receipt = createZeroEffectReceipt({ reasonCode: gate.reasonCode, now, sourceLockDigest: expectedSourceLockDigest });
  log(JSON.stringify(receipt));
  return receipt;
}

export { sourceLockDigest } from "./source-lock.js";

const directEntry = process.argv[1] ? pathToFileURL(process.argv[1]).href === import.meta.url : false;
if (directEntry) execute();
