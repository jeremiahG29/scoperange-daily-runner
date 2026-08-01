export const METADATA_CONNECTION_PROOF_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-public-metadata-connection-proof-v1",
  configured: false,
  externalPostMergeBindingRequired: true,
  exactCommitRequired: true,
  dependencyCacheAllowed: false,
  recognizedWorkflowPlacement: false,
  tlsCa: Object.freeze({
    source: "checked_in_public_artifact",
    path: "bootstrap/supabase-root-2021-ca.crt",
    sha256: "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7",
    runtimeDownloadAllowed: false,
    environmentSecretRequired: false,
    callerOverrideAllowed: false,
    verifyFullRequired: true
  }),
  authority: Object.freeze({
    connectionProof: false,
    recurrence: false,
    acquisition: false,
    ingestion: false,
    promotion: false,
    pricing: false
  })
});
