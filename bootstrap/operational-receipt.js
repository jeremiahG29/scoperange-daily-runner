import { SAFE_REASON_CODES, ZERO_EFFECTS } from "./contract.js";

const SHA256 = /^sha256:([0-9a-f]{64})$/u;
const SAFE_REASONS = new Set(SAFE_REASON_CODES);

export function createZeroEffectReceipt({ reasonCode, now, sourceLockDigest = null }) {
  const match = typeof sourceLockDigest === "string" ? SHA256.exec(sourceLockDigest) : null;
  const validNow = now instanceof Date && Number.isFinite(now.valueOf());
  const safeReasonCode = SAFE_REASONS.has(reasonCode) ? reasonCode : "unknown_rejection";
  return Object.freeze({
    schemaVersion: "scoperange-public-runner-zero-effect-receipt-v1",
    runDay: validNow ? now.toISOString().slice(0, 10) : null,
    disposition: "rejected",
    sourceLockDigestPrefix: match ? match[1].slice(0, 12) : null,
    stage: "non_secret_gate",
    durationClass: "bounded_under_10_minutes",
    reasonCode: safeReasonCode,
    finalClassification: "zero_effect_fail_closed",
    effects: ZERO_EFFECTS,
    productionAuthority: "none"
  });
}
