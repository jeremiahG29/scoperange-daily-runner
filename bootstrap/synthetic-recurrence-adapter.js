import crypto from "node:crypto";

export const SYNTHETIC_RECURRENCE_ADAPTER_CONTRACT = Object.freeze({
  schemaVersion: "scoperange-synthetic-recurrence-adapter-v1",
  storageKind: "shared_in_memory_fixture",
  syntheticFixturesOnly: true,
  productionDurability: false,
  networkAttempts: 0,
  adapterConfigured: false,
  productionAuthority: "none"
});

const SAFE_IDENTIFIER = /^[a-z0-9][a-z0-9:_-]{0,127}$/u;
const LEASE_RECEIPT = /^sha256:[0-9a-f]{64}$/u;
const stores = new WeakMap();

function reject(reasonCode) {
  return Object.freeze({
    schemaVersion: "scoperange-synthetic-recurrence-receipt-v1",
    disposition: "rejected",
    reasonCode,
    leaseReceipt: null,
    leaseExpiresAt: null,
    networkAttempts: 0,
    productionAuthority: "none"
  });
}

function currentTime(clock) {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) {
    throw new Error("SCOPERANGE_SYNTHETIC_RECURRENCE_REJECTED:clock_invalid");
  }
  return new Date(now.valueOf());
}

function scheduledTime(value) {
  const date = new Date(value ?? "");
  if (!Number.isFinite(date.valueOf()) || date.toISOString() !== value) {
    throw new Error("SCOPERANGE_SYNTHETIC_RECURRENCE_REJECTED:schedule_invalid");
  }
  return date;
}

export function createSyntheticRecurrenceStore() {
  const store = Object.freeze({
    schemaVersion: "scoperange-synthetic-recurrence-store-v1",
    storageKind: SYNTHETIC_RECURRENCE_ADAPTER_CONTRACT.storageKind,
    productionAuthority: "none"
  });
  stores.set(store, new Map());
  return store;
}

export function createSyntheticRecurrenceAdapter({ store, clock } = {}) {
  const records = stores.get(store);
  if (!records || typeof clock !== "function") {
    throw new Error("SCOPERANGE_SYNTHETIC_RECURRENCE_REJECTED:adapter_invalid");
  }

  const acquire = ({ scheduleKey, runId, scheduledFor } = {}) => {
    if (!SAFE_IDENTIFIER.test(scheduleKey ?? "") || !SAFE_IDENTIFIER.test(runId ?? "")) {
      throw new Error("SCOPERANGE_SYNTHETIC_RECURRENCE_REJECTED:identifier_invalid");
    }
    const now = currentTime(clock);
    const scheduled = scheduledTime(scheduledFor);
    const existing = records.get(scheduleKey);
    if (existing) {
      if (existing.status === "held" && now.valueOf() <= existing.expiresAt.valueOf()) {
        return reject("active_overlap");
      }
      if (existing.status === "missed") return reject("missed_run_no_catch_up");
      if (existing.status === "cancelled") return reject("invocation_cancelled");
      return reject("lease_replay_forbidden");
    }

    const delayMilliseconds = now.valueOf() - scheduled.valueOf();
    if (delayMilliseconds < 0) return reject("schedule_not_due");
    if (delayMilliseconds > 45 * 60 * 1000) {
      records.set(scheduleKey, Object.freeze({ status: "missed" }));
      return reject("missed_run_no_catch_up");
    }

    const expiresAt = new Date(now.valueOf() + (10 * 60 * 1000));
    const leaseReceipt = `sha256:${crypto.createHash("sha256").update(JSON.stringify({
      scheduleKey,
      runId,
      scheduledFor,
      acquiredAt: now.toISOString(),
      expiresAt: expiresAt.toISOString()
    }), "utf8").digest("hex")}`;
    records.set(scheduleKey, Object.freeze({
      status: "held",
      leaseReceipt,
      expiresAt
    }));
    return Object.freeze({
      schemaVersion: "scoperange-synthetic-recurrence-receipt-v1",
      disposition: "acquired_synthetic_lease",
      reasonCode: null,
      leaseReceipt,
      leaseExpiresAt: expiresAt.toISOString(),
      networkAttempts: 0,
      productionAuthority: "none"
    });
  };

  const findLease = (leaseReceipt) => {
    if (!LEASE_RECEIPT.test(leaseReceipt ?? "")) return null;
    for (const [scheduleKey, record] of records.entries()) {
      if (record.leaseReceipt === leaseReceipt) return { scheduleKey, record };
    }
    return null;
  };

  const cancel = ({ leaseReceipt } = {}) => {
    const match = findLease(leaseReceipt);
    if (!match) return reject("lease_receipt_rejected");
    records.set(match.scheduleKey, Object.freeze({ ...match.record, status: "cancelled" }));
    return reject("invocation_cancelled");
  };

  const runtimeState = ({ leaseReceipt } = {}) => {
    const match = findLease(leaseReceipt);
    if (!match) throw new Error("SCOPERANGE_SYNTHETIC_RECURRENCE_REJECTED:lease_receipt_rejected");
    const now = currentTime(clock);
    const expired = now.valueOf() > match.record.expiresAt.valueOf();
    return Object.freeze({
      PUBLIC_RUNNER_LEASE_STATE: expired ? "expired" : "held",
      PUBLIC_RUNNER_LEASE_RECEIPT: match.record.leaseReceipt,
      PUBLIC_RUNNER_LEASE_EXPIRES_AT: match.record.expiresAt.toISOString(),
      PUBLIC_RUNNER_MISSED_RUN_STATE: "on_time",
      PUBLIC_RUNNER_RESUME_STATE: "fresh",
      PUBLIC_RUNNER_CANCELLATION_STATE: match.record.status === "cancelled" ? "cancelled" : "clear",
      PUBLIC_RUNNER_OVERLAP_STATE: "clear"
    });
  };

  const resume = () => reject("resume_not_authorized");

  return Object.freeze({ acquire, cancel, resume, runtimeState });
}
