import fs from "node:fs";
import path from "node:path";

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
