import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

export function sourceLockDigest(lock) {
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(ordered(lock)), "utf8").digest("hex")}`;
}

function fail(reasonCode) {
  throw new Error(`SCOPERANGE_PUBLIC_SOURCE_LOCK_REJECTED:${reasonCode}`);
}

function validateSourceLock(lock) {
  if (!lock || lock.schemaVersion !== "scoperange-public-runner-source-lock-v1"
    || typeof lock.lockVersion !== "string" || !lock.lockVersion
    || lock.repository !== "jeremiahG29/scopematch"
    || !COMMIT.test(lock.approvedCommit ?? "")
    || !COMMIT.test(lock.requiredAncestor ?? "")
    || !COMMIT.test(lock.approvedParent ?? "")
    || !COMMIT.test(lock.approvedTree ?? "")
    || !DIGEST.test(lock.allowedBundleDigest ?? "")
    || typeof lock.bundleRoot !== "string" || !SAFE_PATH.test(lock.bundleRoot)
    || !Array.isArray(lock.allowedPaths) || lock.allowedPaths.length === 0
    || lock.allowedPaths.some((file) => typeof file !== "string" || !SAFE_PATH.test(file)
      || !(file === lock.bundleRoot || file.startsWith(`${lock.bundleRoot}/`)))
    || new Set(lock.allowedPaths).size !== lock.allowedPaths.length
    || lock.activationAuthorized !== false) fail("source_lock_shape_rejected");

  const fetch = lock.fetch;
  if (!fetch || fetch.refType !== "commit_only" || !Array.isArray(fetch.allowedRefs)
    || fetch.allowedRefs.length !== 0 || fetch.fallbackAllowed !== false
    || fetch.tagsAllowed !== false || fetch.branchesAllowed !== false
    || fetch.submodulesAllowed !== false || fetch.lfsAllowed !== false
    || fetch.credentialHelperAllowed !== false
    || fetch.hostKeyChecking !== "strict_github_host_keys_only") fail("source_ref_policy_rejected");

  const credential = lock.credential;
  if (!credential || credential.type !== "repository_scoped_read_only_deploy_key"
    || credential.repositoryCount !== 1 || credential.write !== false
    || credential.created !== false) fail("source_credential_policy_rejected");
  return lock;
}

function git(repositoryPath, args, { input, onCommand, allowFailure = false } = {}) {
  onCommand?.(Object.freeze({ program: "git", operation: args[0], network: false }));
  const result = spawnSync("git", args, {
    cwd: repositoryPath,
    encoding: "utf8",
    input,
    maxBuffer: 1024 * 1024,
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" }
  });
  if (!allowFailure && result.status !== 0) fail("source_git_command_failed");
  return result;
}

function objectExists(repositoryPath, revision, onCommand) {
  return git(repositoryPath, ["cat-file", "-e", revision], { onCommand, allowFailure: true }).status === 0;
}

function stdout(repositoryPath, args, onCommand) {
  return git(repositoryPath, args, { onCommand }).stdout.trim();
}

function treeEntries(repositoryPath, commit, bundleRoot, onCommand) {
  const raw = stdout(repositoryPath, ["ls-tree", "-r", commit, "--", bundleRoot], onCommand);
  if (!raw) return [];
  return raw.split(/\r?\n/u).map((line) => {
    const match = /^(\d{6}) (blob|commit) ([0-9a-f]{40})\s+(.+)$/u.exec(line);
    if (!match) fail("source_tree_entry_rejected");
    return Object.freeze({ mode: match[1], type: match[2], oid: match[3], path: match[4] });
  });
}

function blob(repositoryPath, oid, onCommand) {
  return git(repositoryPath, ["cat-file", "blob", oid], { onCommand }).stdout;
}

function verifyTreePolicy(repositoryPath, lock, entries, onCommand) {
  if (entries.some((entry) => entry.mode === "160000" || entry.type === "commit")) fail("source_submodule_forbidden");
  if (entries.some((entry) => entry.mode === "120000")) fail("source_symlink_forbidden");

  const attributes = git(repositoryPath, [
    "check-attr",
    "--source",
    lock.approvedCommit,
    "filter",
    "--",
    ...lock.allowedPaths
  ], { onCommand }).stdout;
  if (/(?:^|\r?\n)[^\r\n]+: filter: lfs(?:\r?\n|$)/u.test(attributes)) fail("source_lfs_forbidden");

  for (const entry of entries) {
    if (entry.path.endsWith("/.gitattributes") || entry.path === ".gitattributes") {
      if (/\bfilter=lfs\b/u.test(blob(repositoryPath, entry.oid, onCommand))) fail("source_lfs_forbidden");
    }
    if (/^version https:\/\/git-lfs\.github\.com\/spec\/v1(?:\r?\n|$)/u.test(blob(repositoryPath, entry.oid, onCommand))) {
      fail("source_lfs_forbidden");
    }
  }

  const expected = [...lock.allowedPaths].sort();
  const actual = entries.map((entry) => entry.path).sort();
  if (actual.some((file) => !expected.includes(file)) || expected.some((file) => !actual.includes(file))) {
    fail("source_unexpected_file");
  }
  if (entries.some((entry) => entry.type !== "blob" || !["100644", "100755"].includes(entry.mode))) {
    fail("source_file_mode_rejected");
  }

  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const canonical = expected.map((file) => {
    const entry = byPath.get(file);
    return `${entry.mode}\t${entry.oid}\t${entry.path}\n`;
  }).join("");
  const digest = `sha256:${crypto.createHash("sha256").update(canonical, "utf8").digest("hex")}`;
  if (digest !== lock.allowedBundleDigest) fail("source_bundle_digest_mismatch");
  return digest;
}

export function verifyGitObjectLock({ repositoryPath, lock, onCommand } = {}) {
  validateSourceLock(lock);
  if (typeof repositoryPath !== "string" || !path.isAbsolute(repositoryPath)) fail("source_repository_path_rejected");
  if (!objectExists(repositoryPath, `${lock.approvedCommit}^{commit}`, onCommand)) fail("source_commit_unreachable");
  if (!objectExists(repositoryPath, `${lock.requiredAncestor}^{commit}`, onCommand)) fail("source_ancestor_unreachable");
  const ancestry = git(repositoryPath, ["merge-base", "--is-ancestor", lock.requiredAncestor, lock.approvedCommit], {
    onCommand,
    allowFailure: true
  });
  if (ancestry.status !== 0) fail("source_ancestor_unreachable");
  if (stdout(repositoryPath, ["rev-parse", `${lock.approvedCommit}^`], onCommand) !== lock.approvedParent) {
    fail("source_parent_mismatch");
  }
  if (stdout(repositoryPath, ["rev-parse", `${lock.approvedCommit}^{tree}`], onCommand) !== lock.approvedTree) {
    fail("source_tree_mismatch");
  }
  const entries = treeEntries(repositoryPath, lock.approvedCommit, lock.bundleRoot, onCommand);
  const bundleDigest = verifyTreePolicy(repositoryPath, lock, entries, onCommand);
  return Object.freeze({ verified: true, commit: lock.approvedCommit, tree: lock.approvedTree, bundleDigest });
}

export function verifyLocalCheckout({ checkoutPath, lock, onCommand } = {}) {
  const result = verifyGitObjectLock({ repositoryPath: checkoutPath, lock, onCommand });
  if (stdout(checkoutPath, ["rev-parse", "HEAD"], onCommand) !== lock.approvedCommit) fail("source_checkout_commit_mismatch");
  const status = git(checkoutPath, ["status", "--porcelain=v1", "--untracked-files=all"], { onCommand }).stdout.trim();
  if (status) fail("source_checkout_dirty");
  return result;
}

export function createFutureFetchContract(lock) {
  validateSourceLock(lock);
  return Object.freeze({
    status: "future_only_not_executable",
    credential: "repository_scoped_read_only_deploy_key",
    repositoryCount: 1,
    writeAccess: false,
    refType: "commit_only",
    fallbackAllowed: false,
    branchAllowed: false,
    tagAllowed: false,
    submodulesAllowed: false,
    lfsAllowed: false,
    credentialHelperAllowed: false,
    sshHostVerification: "strict_github_host_keys_only",
    persistCredentials: false,
    commandExecutionPresent: false,
    networkAttempts: 0
  });
}

function childIsRunning(child) {
  return child.exitCode === null && child.signalCode === null;
}

function waitForChildExit(child, timeoutMs) {
  if (!childIsRunning(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    let timeout;
    const finish = (exited) => {
      if (timeout) clearTimeout(timeout);
      child.removeListener("close", onClose);
      resolve(exited);
    };
    const onClose = () => finish(true);
    child.once("close", onClose);
    timeout = setTimeout(() => finish(!childIsRunning(child)), timeoutMs);
  });
}

async function terminateManagedChild(child) {
  if (!childIsRunning(child)) return true;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
      timeout: 1000
    });
  } else {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {
      try { child.kill("SIGTERM"); } catch {}
    }
  }
  if (await waitForChildExit(child, 500)) return true;
  try {
    if (process.platform === "win32") {
      spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 1000
      });
    } else {
      process.kill(-child.pid, "SIGKILL");
    }
  } catch {}
  return waitForChildExit(child, 1000);
}

export async function withEphemeralWorkspace({ fakeKeyMaterial, keyMaterial, operation, signal, timeoutMs = 1000 } = {}) {
  const usingFakeKey = fakeKeyMaterial !== undefined && keyMaterial === undefined;
  const selectedKeyMaterial = usingFakeKey ? fakeKeyMaterial : keyMaterial;
  if (typeof selectedKeyMaterial !== "string" || !selectedKeyMaterial
    || selectedKeyMaterial.length > 16_384 || selectedKeyMaterial.includes("\0")
    || (usingFakeKey && /PRIVATE KEY|ssh-(?:rsa|ed25519)/iu.test(selectedKeyMaterial))
    || (!usingFakeKey && fakeKeyMaterial !== undefined)
    || typeof operation !== "function" || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 90_000) {
    fail("ephemeral_input_rejected");
  }
  const workspacePath = fs.mkdtempSync(path.join(os.tmpdir(), "scoperange-public-runner-"));
  const sshDirectory = path.join(workspacePath, "ssh");
  const checkoutPath = path.join(workspacePath, "checkout");
  fs.mkdirSync(sshDirectory, { mode: 0o700 });
  fs.mkdirSync(checkoutPath, { mode: 0o700 });
  const identityPath = path.join(sshDirectory, "identity");
  fs.writeFileSync(identityPath, selectedKeyMaterial, { encoding: "utf8", mode: 0o600 });

  let timeout;
  let abortListener;
  let result;
  let operationError;
  let cleanupFailed = false;
  const cleanupCallbacks = [];
  const managedChildren = new Set();
  const managedTerminations = new Map();
  const operationController = new AbortController();
  const terminateTrackedChild = (child) => {
    if (!managedTerminations.has(child)) {
      managedTerminations.set(
        child,
        Promise.resolve().then(() => terminateManagedChild(child)).catch(() => false)
      );
    }
    return managedTerminations.get(child);
  };
  const registerCleanup = (callback) => {
    if (typeof callback !== "function") fail("ephemeral_cleanup_rejected");
    cleanupCallbacks.push(callback);
  };
  const spawnManaged = (executable, args = [], options = {}) => {
    if (typeof executable !== "string" || !executable || !Array.isArray(args)
      || args.some((arg) => typeof arg !== "string")
      || !options || typeof options !== "object" || options.shell !== undefined
      || options.stdio !== undefined || options.detached !== undefined) {
      fail("ephemeral_process_rejected");
    }
    const child = spawn(executable, args, {
      cwd: checkoutPath,
      env: options.env ?? {},
      windowsHide: true,
      shell: false,
      stdio: "ignore",
      detached: process.platform !== "win32"
    });
    if (!Number.isInteger(child.pid) || child.pid < 1) fail("ephemeral_process_start_failed");
    managedChildren.add(child);
    child.once("close", () => managedChildren.delete(child));
    return Object.freeze({ pid: child.pid });
  };
  const runManagedProcess = ({ program, args, cwd, env, stdin = "", maxOutputBytes } = {}) => {
    const relativeCwd = typeof cwd === "string" ? path.relative(workspacePath, cwd) : "..";
    if (typeof program !== "string" || !program || !Array.isArray(args)
      || args.some((arg) => typeof arg !== "string")
      || typeof cwd !== "string" || !path.isAbsolute(cwd)
      || relativeCwd.startsWith("..") || path.isAbsolute(relativeCwd)
      || !env || typeof env !== "object" || Array.isArray(env)
      || Object.entries(env).some(([key, value]) => !key || typeof value !== "string")
      || typeof stdin !== "string" || Buffer.byteLength(stdin, "utf8") > 64 * 1024
      || !Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 64 * 1024) {
      return Promise.reject(new Error("managed process rejected"));
    }
    return new Promise((resolve, reject) => {
      const child = spawn(program, args, {
        cwd,
        env: {
          PATH: process.env.PATH ?? "",
          SystemRoot: process.env.SystemRoot ?? "",
          ...env
        },
        windowsHide: true,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
        detached: process.platform !== "win32"
      });
      let stdout = "";
      let stderr = "";
      let outputBytes = 0;
      let rejectionReason = null;
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        operationController.signal.removeEventListener("abort", onAbort);
        managedChildren.delete(child);
        if (error) reject(error);
        else resolve(value);
      };
      const requestTermination = (reason) => {
        rejectionReason ??= reason;
        void terminateTrackedChild(child);
      };
      const onAbort = () => requestTermination("managed process cancelled");
      const onData = (target) => (chunk) => {
        outputBytes += chunk.length;
        if (outputBytes > maxOutputBytes) {
          requestTermination("managed process output rejected");
        } else if (target === "stdout") {
          stdout += chunk.toString("utf8");
        } else {
          stderr += chunk.toString("utf8");
        }
      };
      child.stdout.on("data", onData("stdout"));
      child.stderr.on("data", onData("stderr"));
      child.once("error", (error) => finish(error));
      child.once("close", (exitCode) => {
        if (rejectionReason || operationController.signal.aborted) {
          finish(new Error(rejectionReason ?? "managed process cancelled"));
        } else {
          finish(null, { exitCode, stdout, stderr });
        }
      });
      if (!Number.isInteger(child.pid) || child.pid < 1) {
        finish(new Error("managed process start failed"));
        return;
      }
      managedChildren.add(child);
      operationController.signal.addEventListener("abort", onAbort, { once: true });
      child.stdin.end(stdin);
    });
  };
  try {
    if (signal?.aborted) throw new Error("ephemeral_operation_cancelled");
    const operationPromise = Promise.resolve().then(() => operation({
      workspacePath,
      checkoutPath,
      identityPath,
      signal: operationController.signal,
      registerCleanup,
      spawnManaged,
      runManagedProcess
    }));
    const timeoutPromise = new Promise((_, reject) => {
      timeout = setTimeout(() => {
        operationController.abort();
        reject(new Error("ephemeral_operation_timeout"));
      }, timeoutMs);
    });
    const contenders = [operationPromise, timeoutPromise];
    if (signal) {
      contenders.push(new Promise((_, reject) => {
        abortListener = () => {
          operationController.abort();
          reject(new Error("ephemeral_operation_cancelled"));
        };
        signal.addEventListener("abort", abortListener, { once: true });
      }));
    }
    result = await Promise.race(contenders);
  } catch (error) {
    operationError = (error?.message === "ephemeral_operation_timeout" || error?.message === "ephemeral_operation_cancelled")
      ? error
      : new Error("ephemeral_operation_failed");
  } finally {
    if (timeout) clearTimeout(timeout);
    if (signal && abortListener) signal.removeEventListener("abort", abortListener);
    operationController.abort();
    for (const child of [...managedChildren]) {
      if (!(await terminateTrackedChild(child))) cleanupFailed = true;
      managedChildren.delete(child);
    }
    for (const callback of cleanupCallbacks.reverse()) {
      let cleanupTimeout;
      try {
        await Promise.race([
          Promise.resolve().then(callback),
          new Promise((_, reject) => {
            cleanupTimeout = setTimeout(() => reject(new Error("cleanup timeout")), Math.min(timeoutMs, 1000));
          })
        ]);
      } catch {
        cleanupFailed = true;
      } finally {
        if (cleanupTimeout) clearTimeout(cleanupTimeout);
      }
    }
    try {
      fs.rmSync(workspacePath, { recursive: true, force: true });
    } catch {
      cleanupFailed = true;
    }
  }
  if (cleanupFailed) throw new Error("ephemeral_cleanup_failed");
  if (operationError) throw operationError;
  return result;
}

const GITHUB_REMOTE = "git@github.com:jeremiahG29/scopematch.git";
const KNOWN_HOSTS_PATH = fileURLToPath(new URL("./github-known-hosts", import.meta.url));

function portableQuotedPath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value) || /[\r\n"\0]/u.test(value)) {
    fail("source_process_path_rejected");
  }
  return `"${value.replace(/\\/gu, "/")}"`;
}

async function runFetchCommand({ spawnImpl, args, cwd, env, signal }) {
  const result = await spawnImpl({
    program: "git",
    args,
    cwd,
    env,
    signal,
    maxOutputBytes: 64 * 1024
  });
  if (!result || result.exitCode !== 0
    || typeof result.stdout !== "string" || typeof result.stderr !== "string"
    || Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > 64 * 1024) {
    throw new Error("source command rejected");
  }
}

export async function fetchLockedPrivateSource({
  lock,
  keyMaterial,
  spawnImpl,
  signal,
  consumeVerifiedCheckout
} = {}) {
  try {
    validateSourceLock(lock);
    if (lock.requiredAncestor !== lock.approvedParent
      || (spawnImpl !== undefined && typeof spawnImpl !== "function")
      || (consumeVerifiedCheckout !== undefined && typeof consumeVerifiedCheckout !== "function")
      || !signal || typeof signal.aborted !== "boolean"
      || typeof signal.addEventListener !== "function") {
      throw new Error("source fetch input rejected");
    }
    return await withEphemeralWorkspace({
      keyMaterial,
      signal,
      timeoutMs: 90_000,
      operation: async ({
        workspacePath,
        checkoutPath,
        identityPath,
        signal: operationSignal,
        runManagedProcess
      }) => {
        const selectedSpawnImpl = spawnImpl ?? runManagedProcess;
        const sshCommand = [
          "ssh",
          "-F", "/dev/null",
          "-i", portableQuotedPath(identityPath),
          "-o", "IdentitiesOnly=yes",
          "-o", "StrictHostKeyChecking=yes",
          "-o", `UserKnownHostsFile=${portableQuotedPath(KNOWN_HOSTS_PATH)}`,
          "-o", "GlobalKnownHostsFile=/dev/null",
          "-o", "BatchMode=yes"
        ].join(" ");
        const env = {
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_TERMINAL_PROMPT: "0",
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "credential.helper",
          GIT_CONFIG_VALUE_0: "",
          GIT_SSH_COMMAND: sshCommand
        };
        await runFetchCommand({
          spawnImpl: selectedSpawnImpl,
          args: ["init", "--quiet", checkoutPath],
          cwd: workspacePath,
          env,
          signal: operationSignal
        });
        await runFetchCommand({
          spawnImpl: selectedSpawnImpl,
          args: [
            "-C", checkoutPath,
            "-c", "protocol.version=2",
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth=2",
            GITHUB_REMOTE,
            lock.approvedCommit
          ],
          cwd: workspacePath,
          env,
          signal: operationSignal
        });
        await runFetchCommand({
          spawnImpl: selectedSpawnImpl,
          args: ["-C", checkoutPath, "checkout", "--quiet", "--detach", lock.approvedCommit],
          cwd: workspacePath,
          env,
          signal: operationSignal
        });
        const verification = verifyLocalCheckout({ checkoutPath, lock });
        if (consumeVerifiedCheckout === undefined) return verification;
        return consumeVerifiedCheckout({
          workspacePath,
          checkoutPath,
          bundleRoot: lock.bundleRoot,
          runManagedProcess
        });
      }
    });
  } catch {
    if (signal?.aborted) throw new Error("SCOPERANGE_PUBLIC_SOURCE_FETCH_CANCELLED");
    throw new Error("SCOPERANGE_PUBLIC_SOURCE_FETCH_REJECTED");
  }
}
