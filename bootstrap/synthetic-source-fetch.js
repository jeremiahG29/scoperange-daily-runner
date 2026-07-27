import { verifyGitObjectLock } from "./source-lock.js";

export const SYNTHETIC_SOURCE_FETCH_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-synthetic-source-fetch-v1",
  sourceKind: "local_git_object_fixture",
  syntheticFixturesOnly: true,
  credentialReads: 0,
  networkAttempts: 0,
  materializedBytes: 0,
  executionAttempts: 0,
  adapterConfigured: false,
  productionAuthority: "none"
});

export function verifySyntheticSourceFetch({ repositoryPath, lock, onCommand } = {}) {
  if (onCommand !== undefined && typeof onCommand !== "function") {
    throw new Error("SCOPERANGE_SYNTHETIC_SOURCE_REJECTED:observer_invalid");
  }
  const verification = verifyGitObjectLock({
    repositoryPath,
    lock,
    onCommand: (command) => {
      if (!command || command.network !== false) {
        throw new Error("SCOPERANGE_SYNTHETIC_SOURCE_REJECTED:network_forbidden");
      }
      onCommand?.(Object.freeze({
        program: "git",
        operation: command.operation,
        network: false
      }));
    }
  });
  return Object.freeze({
    schemaVersion: "scoperange-synthetic-source-fetch-receipt-v1",
    disposition: "verified_synthetic_fixture",
    sourceKind: SYNTHETIC_SOURCE_FETCH_CONTRACT.sourceKind,
    fileCount: lock.allowedPaths.length,
    bundleDigest: verification.bundleDigest,
    credentialReads: 0,
    networkAttempts: 0,
    materializedBytes: 0,
    executionAttempts: 0,
    productionAuthority: "none"
  });
}
