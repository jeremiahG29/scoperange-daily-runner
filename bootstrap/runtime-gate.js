import {
  APPROVED_COMMIT_BINDING_CONTRACT,
  EXPECTED_REF,
  EXPECTED_REPOSITORY,
  EXPECTED_SCHEDULE,
  EXPECTED_WORKFLOW_REF,
  PRODUCTION_IDENTITY_CONTRACT,
  RECURRENCE_CONTRACT
} from "./contract.js";

const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const EARLIEST_UTC_MILLISECONDS = ((9 * 60) + 17) * 60 * 1000;
const LATEST_UTC_MILLISECONDS = ((10 * 60) + 2) * 60 * 1000;

function reject(reasonCode) {
  return Object.freeze({ reasonCode });
}

export function evaluateRecurrenceGate(configuration, now) {
  if (configuration.PUBLIC_RUNNER_LEASE_STATE !== "held") return reject("lease_not_held");
  if (!DIGEST.test(configuration.PUBLIC_RUNNER_LEASE_RECEIPT ?? "")) return reject("lease_receipt_rejected");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) return reject("lease_window_rejected");
  const expiresAt = new Date(configuration.PUBLIC_RUNNER_LEASE_EXPIRES_AT ?? "");
  const leaseMilliseconds = expiresAt.valueOf() - now.valueOf();
  if (!Number.isFinite(expiresAt.valueOf())
    || expiresAt.toISOString() !== configuration.PUBLIC_RUNNER_LEASE_EXPIRES_AT
    || leaseMilliseconds <= 0
    || leaseMilliseconds > RECURRENCE_CONTRACT.maximumLeaseSeconds * 1000) {
    return reject("lease_window_rejected");
  }
  if (configuration.PUBLIC_RUNNER_MISSED_RUN_STATE !== "on_time") return reject("missed_run_no_catch_up");
  if (configuration.PUBLIC_RUNNER_RESUME_STATE !== "fresh") return reject("resume_not_authorized");
  if (configuration.PUBLIC_RUNNER_CANCELLATION_STATE !== "clear") return reject("invocation_cancelled");
  if (configuration.PUBLIC_RUNNER_OVERLAP_STATE !== "clear") return reject("active_overlap");
  return Object.freeze({ accepted: true });
}

export function evaluateRuntimeGate(configuration, now, expectedSourceLockDigest) {
  if (configuration.PUBLIC_RUNNER_EXPECTED_REPOSITORY !== EXPECTED_REPOSITORY
    || configuration.PUBLIC_RUNNER_REPOSITORY !== EXPECTED_REPOSITORY) return reject("repository_rejected");
  if (configuration.PUBLIC_RUNNER_WORKFLOW_REF !== EXPECTED_WORKFLOW_REF) return reject("workflow_path_rejected");
  if (configuration.PUBLIC_RUNNER_EVENT_NAME !== "schedule") return reject("event_rejected");
  if (configuration.PUBLIC_RUNNER_EVENT_SCHEDULE !== EXPECTED_SCHEDULE) return reject("schedule_rejected");
  if (configuration.PUBLIC_RUNNER_REF !== EXPECTED_REF) return reject("default_branch_rejected");
  if (configuration.PUBLIC_RUNNER_RUN_ATTEMPT !== "1") return reject("rerun_forbidden");
  if (!APPROVED_COMMIT_BINDING_CONTRACT.configured
    || configuration.PUBLIC_RUNNER_APPROVED_COMMIT_BINDING_STATE !== "verified") {
    return reject("approved_commit_binding_unverified");
  }
  if (!COMMIT.test(configuration.PUBLIC_RUNNER_COMMIT ?? "")
    || configuration.PUBLIC_RUNNER_APPROVED_COMMIT !== configuration.PUBLIC_RUNNER_COMMIT) {
    return reject("runner_commit_unapproved");
  }
  if (configuration.PUBLIC_RUNNER_SOURCE_LOCK_DIGEST !== expectedSourceLockDigest) return reject("source_lock_mismatch");
  const recurrence = evaluateRecurrenceGate(configuration, now);
  if (!recurrence.accepted) return recurrence;
  if (configuration.PUBLIC_RUNNER_LIFECYCLE_STATE !== "ready") return reject("invocation_cancelled");
  if (!PRODUCTION_IDENTITY_CONTRACT.configured) return reject("identity_contract_unconfigured");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) return reject("timing_rejected");

  const utcMilliseconds = (((now.getUTCHours() * 60) + now.getUTCMinutes()) * 60 * 1000)
    + (now.getUTCSeconds() * 1000) + now.getUTCMilliseconds();
  if (utcMilliseconds < EARLIEST_UTC_MILLISECONDS) return reject("schedule_not_due");
  if (utcMilliseconds > LATEST_UTC_MILLISECONDS) return reject("missed_run_no_catch_up");
  return reject("identity_unverified");
}
