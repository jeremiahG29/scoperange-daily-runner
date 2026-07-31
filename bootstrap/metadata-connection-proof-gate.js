import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const INPUT_KEYS = Object.freeze([
  "repository",
  "repositoryId",
  "ref",
  "refProtected",
  "workflowRef",
  "workflowSha",
  "eventName",
  "inputCount",
  "runAttempt",
  "observedCommit",
  "approvedCommit",
  "sourceLockDigest",
  "expectedSourceLockDigest",
  "lifecycleState",
  "duplicateState",
  "recurrenceAuthorized",
  "acquisitionAuthorized",
  "ingestionAuthorized",
  "promotionAuthorized",
  "pricingAuthorized"
]);

const ACCEPTED = Object.freeze({
  disposition: "accepted",
  reasonCode: "metadata_proof_gate_accepted",
  authorization: "scoperange-metadata-proof-non-secret-gate-accepted-v1"
});
const REJECTED = Object.freeze({
  disposition: "rejected",
  reasonCode: "metadata_proof_gate_rejected",
  authorization: null
});

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

export function evaluateMetadataProofGate(value) {
  try {
    if (!exactKeys(value, INPUT_KEYS)
      || value.repository !== "jeremiahG29/scoperange-daily-runner"
      || value.repositoryId !== "1313256299"
      || value.ref !== "refs/heads/main"
      || value.refProtected !== true
      || value.workflowRef !== "jeremiahG29/scoperange-daily-runner/.github/workflows/scoperange-metadata-proof.yml@refs/heads/main"
      || !COMMIT.test(value.workflowSha ?? "")
      || value.eventName !== "workflow_dispatch"
      || value.inputCount !== 0
      || value.runAttempt !== 1
      || !COMMIT.test(value.observedCommit ?? "")
      || !COMMIT.test(value.approvedCommit ?? "")
      || value.workflowSha !== value.approvedCommit
      || value.observedCommit !== value.approvedCommit
      || !DIGEST.test(value.sourceLockDigest ?? "")
      || value.sourceLockDigest !== value.expectedSourceLockDigest
      || value.lifecycleState !== "clear"
      || value.duplicateState !== "clear"
      || value.recurrenceAuthorized !== false
      || value.acquisitionAuthorized !== false
      || value.ingestionAuthorized !== false
      || value.promotionAuthorized !== false
      || value.pricingAuthorized !== false) return REJECTED;
    return ACCEPTED;
  } catch {
    return REJECTED;
  }
}

export function writeAcceptedOutput(outputPath, decision) {
  if (typeof outputPath !== "string" || !path.isAbsolute(outputPath)
    || !exactKeys(decision, ["disposition", "reasonCode", "authorization"])
    || JSON.stringify(decision) !== JSON.stringify(ACCEPTED)) {
    throw new Error("SCOPERANGE_METADATA_PROOF_OUTPUT_REJECTED");
  }
  try {
    const parent = fs.realpathSync(path.dirname(outputPath));
    if (parent !== path.dirname(outputPath) || (fs.existsSync(outputPath) && fs.lstatSync(outputPath).isSymbolicLink())) {
      throw new Error("output rejected");
    }
    fs.writeFileSync(
      outputPath,
      "authorization=scoperange-metadata-proof-non-secret-gate-accepted-v1\n",
      { encoding: "utf8", mode: 0o600 }
    );
  } catch {
    throw new Error("SCOPERANGE_METADATA_PROOF_OUTPUT_REJECTED");
  }
}

function directEnvelope(environment) {
  return {
    repository: environment.SCOPERANGE_METADATA_REPOSITORY,
    repositoryId: environment.SCOPERANGE_METADATA_REPOSITORY_ID,
    ref: environment.SCOPERANGE_METADATA_REF,
    refProtected: environment.SCOPERANGE_METADATA_REF_PROTECTED === "true",
    workflowRef: environment.SCOPERANGE_METADATA_WORKFLOW_REF,
    workflowSha: environment.SCOPERANGE_METADATA_WORKFLOW_SHA,
    eventName: environment.SCOPERANGE_METADATA_EVENT_NAME,
    inputCount: 0,
    runAttempt: Number(environment.SCOPERANGE_METADATA_RUN_ATTEMPT),
    observedCommit: environment.SCOPERANGE_METADATA_OBSERVED_COMMIT,
    approvedCommit: environment.SCOPERANGE_METADATA_APPROVED_COMMIT,
    sourceLockDigest: environment.SCOPERANGE_METADATA_SOURCE_LOCK_DIGEST,
    expectedSourceLockDigest: environment.SCOPERANGE_METADATA_EXPECTED_SOURCE_LOCK_DIGEST,
    lifecycleState: environment.SCOPERANGE_METADATA_LIFECYCLE_STATE,
    duplicateState: environment.SCOPERANGE_METADATA_DUPLICATE_STATE,
    recurrenceAuthorized: environment.SCOPERANGE_METADATA_RECURRENCE_AUTHORIZED !== "false",
    acquisitionAuthorized: environment.SCOPERANGE_METADATA_ACQUISITION_AUTHORIZED !== "false",
    ingestionAuthorized: environment.SCOPERANGE_METADATA_INGESTION_AUTHORIZED !== "false",
    promotionAuthorized: environment.SCOPERANGE_METADATA_PROMOTION_AUTHORIZED !== "false",
    pricingAuthorized: environment.SCOPERANGE_METADATA_PRICING_AUTHORIZED !== "false"
  };
}

const directEntry = process.argv[1] ? pathToFileURL(process.argv[1]).href === import.meta.url : false;
if (directEntry) {
  const decision = evaluateMetadataProofGate(directEnvelope(process.env));
  if (decision.disposition === "accepted") {
    writeAcceptedOutput(process.env.GITHUB_OUTPUT, decision);
  } else {
    process.exitCode = 1;
  }
}
