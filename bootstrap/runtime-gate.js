import {
  ACTIVATION_AUTHORIZED,
  EXPECTED_REF,
  EXPECTED_REPOSITORY,
  EXPECTED_SCHEDULE,
  EXPECTED_WORKFLOW_REF
} from "./contract.js";

const COMMIT = /^[0-9a-f]{40}$/u;
const EARLIEST_UTC_MILLISECONDS = ((9 * 60) + 17) * 60 * 1000;
const LATEST_UTC_MILLISECONDS = ((10 * 60) + 2) * 60 * 1000;

function reject(reasonCode) {
  return Object.freeze({ reasonCode });
}

export function evaluateRuntimeGate(configuration, now, expectedSourceLockDigest) {
  if (configuration.PUBLIC_RUNNER_EXPECTED_REPOSITORY !== EXPECTED_REPOSITORY
    || configuration.PUBLIC_RUNNER_REPOSITORY !== EXPECTED_REPOSITORY) return reject("repository_rejected");
  if (configuration.PUBLIC_RUNNER_WORKFLOW_REF !== EXPECTED_WORKFLOW_REF) return reject("workflow_path_rejected");
  if (configuration.PUBLIC_RUNNER_EVENT_NAME !== "schedule") return reject("event_rejected");
  if (configuration.PUBLIC_RUNNER_EVENT_SCHEDULE !== EXPECTED_SCHEDULE) return reject("schedule_rejected");
  if (configuration.PUBLIC_RUNNER_REF !== EXPECTED_REF) return reject("default_branch_rejected");
  if (configuration.PUBLIC_RUNNER_RUN_ATTEMPT !== "1") return reject("rerun_forbidden");
  if (!COMMIT.test(configuration.PUBLIC_RUNNER_COMMIT ?? "")
    || configuration.PUBLIC_RUNNER_APPROVED_COMMIT !== configuration.PUBLIC_RUNNER_COMMIT) {
    return reject("runner_commit_unapproved");
  }
  if (configuration.PUBLIC_RUNNER_SOURCE_LOCK_DIGEST !== expectedSourceLockDigest) return reject("source_lock_mismatch");
  if (configuration.PUBLIC_RUNNER_OVERLAP_STATE !== "clear") return reject("active_overlap");
  if (configuration.PUBLIC_RUNNER_LIFECYCLE_STATE !== "ready") return reject("invocation_cancelled");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) return reject("timing_rejected");

  const utcMilliseconds = (((now.getUTCHours() * 60) + now.getUTCMinutes()) * 60 * 1000)
    + (now.getUTCSeconds() * 1000) + now.getUTCMilliseconds();
  if (utcMilliseconds < EARLIEST_UTC_MILLISECONDS) return reject("schedule_not_due");
  if (utcMilliseconds > LATEST_UTC_MILLISECONDS) return reject("missed_run_no_catch_up");
  if (!ACTIVATION_AUTHORIZED) return reject("activation_not_authorized");
  return reject("activation_not_authorized");
}
