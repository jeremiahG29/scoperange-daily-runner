import { ZERO_EFFECTS } from "./contract.js";

const SHA256 = /^sha256:([0-9a-f]{64})$/u;

export function createZeroEffectReceipt({ reasonCode, now, sourceLockDigest = null }) {
  const match = typeof sourceLockDigest === "string" ? SHA256.exec(sourceLockDigest) : null;
  const validNow = now instanceof Date && Number.isFinite(now.valueOf());
  return Object.freeze({
    schemaVersion: "scoperange-public-runner-zero-effect-receipt-v1",
    runDay: validNow ? now.toISOString().slice(0, 10) : null,
    disposition: "rejected",
    sourceLockDigestPrefix: match ? match[1].slice(0, 12) : null,
    stage: "non_secret_gate",
    durationClass: "bounded_under_10_minutes",
    reasonCode,
    finalClassification: "zero_effect_fail_closed",
    effects: ZERO_EFFECTS,
    productionAuthority: "none"
  });
}
