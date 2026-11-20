/**
 * One custom step, walled: the probe that decides whether a step may run at all, and the run itself.
 *
 * NO WALL, NO STEP. `probeWall` asks three questions and a no to any of them refuses the step:
 * bubblewrap is installed, it can make an unprivileged user namespace and a PID namespace on this
 * computer, and the seccomp filter for this architecture can be built. A refusal is answered with
 * one sentence and a fixed code (`no_wall`) and NOTHING is spawned: there is no lighter tier here, no
 * "run it bare this once", and no probe that answers maybe.
 *
 * The run, once the wall is there:
 *  - a relay in this process (`pi_egress.mjs`) is the step's only way out. Its allowed hosts are the
 *    report's approved and verified hosts and nothing else, and `inject` carries the credential rules
 *    the approvals module built, so a step never holds a credential and never sees one;
 *  - the plan (`plan.mjs`) is the bind set: the env read-only, the bundle read-only, each asset
 *    read-only, one fresh writable work dir, no `$HOME` data, no crow.db, no workspace;
 *  - stdin is one JSON object `{input, state, params}`; stdout must be ONE JSON object with at most
 *    8 MB, and stderr is capped at 64 KB;
 *  - the stdout text is passed through `redactSecrets` with EVERY secret in play before it is parsed,
 *    so a step that prints a credential the relay handed upstream cannot put it in a run's items;
 *  - the time cap kills the process group this run created (the pid that was spawned and its group,
 *    never a name pattern), and the memory cap is `prlimit --as=<bytes>` for Python, and for Node a V8
 *    heap cap plus `prlimit --as=<bytes>` at four times the cap (V8 reserves far more address space
 *    than it uses). `prlimit` takes plain BYTES and does not accept a unit suffix, so the number is
 *    the cap in bytes: a suffix would be read as 1024 bytes and the step would die at its first page.
 *    Both prlimits sit INSIDE the wall, on the step's own command: the Node that runs the
 *    in-namespace entry needs far more address space than a step's cap, so the cap can never be put
 *    in front of the wall.
 *  - the child's exit code, its signal, a spawn error, a timeout and an oversized answer each become
 *    one fixed code. No message from a child, from node or from TLS is ever handed back as text.
 *
 * Every refusal here is data (`{ok: false, code, error}`), never a throw.
 */
import { spawn as spawnChild } from "node:child_process";
import { mkdtempSync, closeSync, openSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";

import { createEgressRelay } from "../pi-bots/pi_egress.mjs";
import { probePiSandbox } from "../pi-bots/pi_sandbox.mjs";
import { buildSeccompProgram, seccompSupported } from "../pi-bots/pi_seccomp.mjs";
import { redactSecrets } from "../../servers/shared/redact-secrets.js";
import { buildStepPlan, STEP_PROXY_PORT } from "./plan.mjs";

/** The one sentence a step on a computer with no sandbox is refused with (the plan's exact words). */
export const NO_WALL_TEXT = "Custom steps can't run on this Crow (no sandbox available)";
/** The code that sentence travels with. */
export const NO_WALL_CODE = "no_wall";
/** The most stdout one step may answer with. */
export const OUTPUT_MAX_BYTES = 8 * 1024 * 1024;
/** How much of a step's stderr is kept. */
export const STDERR_MAX_BYTES = 64 * 1024;
/** The default wall-clock cap for one step. */
export const DEFAULT_TIMEOUT_MS = 300_000;
/** The default memory cap, in megabytes. */
export const DEFAULT_MEMORY_MB = 1024;
/** How many bytes a megabyte is, for the address-space cap below. */
export const BYTES_PER_MB = 1024 * 1024;
/** Node's address-space cap is this many times the heap cap (V8 reserves far more than it uses). */
export const NODE_ADDRESS_SPACE_FACTOR = 4;
/** bwrap reads the seccomp program from this fd. */
const SECCOMP_CHILD_FD = 3;
/** The keys a step's stdout object may carry, and nothing else. */
const OUTPUT_KEYS = Object.freeze(["items", "data", "sections", "email", "state"]);
/** `prlimit` is what makes an address-space cap possible without a user unit. */
const PRLIMIT_CANDIDATES = ["/usr/bin/prlimit", "/bin/prlimit"];
const PRLIMIT = process.platform === "linux"
  ? PRLIMIT_CANDIDATES.find((p) => { try { return statSync(p).isFile(); } catch { return false; } }) || null
  : null;
/** The fixed codes a run can end with. */
export const RUN_CODES = Object.freeze([
  "no_wall", "bad_input", "relay_failed", "timeout", "output_too_large", "bad_output",
  "exit_nonzero", "memory",
]);

/** A refusal as data, with a fixed code as its text. */
const refuse = (code, error = code) => ({ ok: false, code, error });

/**
 * The address-space cap one step runs under, in BYTES.
 *
 * util-linux `prlimit` takes a plain number of bytes: it has no `M`/`G` suffix, so `--as=1024M` is one
 * thousand and twenty-four BYTES and every step would die at its first page. Python gets the cap
 * itself, Node four times it (V8 reserves far more address space than it ever uses; its own heap cap
 * is the `--max-old-space-size` argument).
 *
 * @param {"python"|"node"} language
 * @param {number} memoryMb
 * @returns {number}
 */
export function addressSpaceBytes(language, memoryMb) {
  const mb = Number.isInteger(memoryMb) && memoryMb > 0 ? memoryMb : DEFAULT_MEMORY_MB;
  const factor = language === "node" ? NODE_ADDRESS_SPACE_FACTOR : 1;
  return mb * factor * BYTES_PER_MB;
}

/**
 * The command prefix that puts the address-space cap on the step itself, inside the wall. Empty only
 * for a caller that passes no `prlimit`: `runCustomStep` refuses a step at all in that case (`no_wall`),
 * because a step with no memory cap is not a walled step.
 *
 * @param {{"python"|"node"} language, memoryMb: number, prlimit?: string|null}} o
 * @returns {string[]}
 */
export function addressSpacePrefix({ language, memoryMb, prlimit = PRLIMIT } = {}) {
  if (typeof prlimit !== "string" || !prlimit) return [];
  return [prlimit, "--as=" + addressSpaceBytes(language, memoryMb), "--"];
}

/** The relay options a run may carry from its caller. A report's run owns its egress list, its
 *  credential rules, its hook set and its listener, and nothing the caller passes may widen them:
 *  `lookup` (how a name resolves on this computer) and `local` (the own-address view) are the two
 *  harmless members, and without `deps.testSeams === true` nothing else is read at all, including
 *  every `_`-prefixed seam and every key below. A test harness is the only caller that sets that
 *  flag (custom-step.js drops it, with `relayOptions`, from the deps it forwards). */
export function relayOptionsFor(deps = {}) {
  const raw = deps && typeof deps.relayOptions === "object" && deps.relayOptions ? deps.relayOptions : null;
  if (!raw) return {};
  const testSeams = deps.testSeams === true;
  const out = {};
  for (const [key, value] of Object.entries(raw)) {
    if (testSeams) { out[key] = value; continue; }
    if (key.startsWith("_") || RELAY_RESERVED_KEYS.includes(key)) continue;
    if (key !== "lookup" && key !== "local") continue;
    out[key] = value;
  }
  return out;
}

/** The relay keys a caller's option bag may never carry unless it is a test harness. */
const RELAY_RESERVED_KEYS = Object.freeze(["addon", "doorFilter", "egressAllow", "inject"]);

/** A bwrap binary this computer has, or null. */
function findBwrap() {
  for (const candidate of ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]) {
    try { if (statSync(candidate).isFile()) return candidate; } catch { /* keep looking */ }
  }
  return null;
}

/**
 * Can a step run on this computer? A `no` for any of the three questions is a no:
 *  - bubblewrap is installed (so a user namespace can be made with it);
 *  - it can make an unprivileged user namespace AND a PID namespace with a fresh /proc (the plan
 *    demands both, and a host where either is refused cannot run a step's wall);
 *  - the seccomp filter for this architecture builds.
 *
 * @param {object} [deps] seams: `probe` (a probePiSandbox-shaped answer), `seccompSupported`, `bwrap`
 * @returns {{ok: true, bwrap: string}|{ok: false, reason: string}}
 */
export function probeWall(deps = {}) {
  const seam = deps && typeof deps === "object" ? deps : {};
  let probe = null;
  try {
    probe = typeof seam.probe === "function" ? seam.probe() : probePiSandbox();
  } catch (err) {
    return { ok: false, reason: err && err.message ? String(err.message) : "the probe failed" };
  }
  if (!probe || probe.ok !== true) {
    return { ok: false, reason: probe && typeof probe.reason === "string" && probe.reason ? probe.reason : "no bubblewrap" };
  }
  if (probe.pidns === false) {
    return { ok: false, reason: probe.pidnsReason || "no PID namespace" };
  }
  const supports = typeof seam.seccompSupported === "function" ? seam.seccompSupported : seccompSupported;
  let seccompOk = false;
  try { seccompOk = supports() === true; } catch { seccompOk = false; }
  if (!seccompOk) return { ok: false, reason: "no seccomp filter for this architecture" };
  const bwrap = typeof seam.bwrap === "string" && seam.bwrap ? seam.bwrap : (probe.bwrap || findBwrap());
  if (!bwrap) return { ok: false, reason: "no bubblewrap" };
  return { ok: true, bwrap };
}

/** A seccomp program on an already-unlinked fd, so nothing is left on disk for anyone to find. */
function openSeccompProgram(build, tmpdirFn) {
  const dir = mkdtempSync(join(tmpdirFn(), "crow-report-step-seccomp-" + process.pid + "-"));
  const file = join(dir, "filter.bpf");
  let fd = null;
  try {
    writeFileSync(file, build(), { mode: 0o600 });
    fd = openSync(file, "r");
    unlinkSync(file);
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* already gone */ }
  }
  return fd;
}

/**
 * One JSON object, or null. The contract is exact: the five keys below, with `items` and `sections` as
 * arrays, `data` and `email` as objects and `state` as an object. Anything else is `bad_output`, so a
 * step cannot invent a field a later stage would trust.
 */
export function normalizeStepOutput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  for (const key of Object.keys(value)) if (!OUTPUT_KEYS.includes(key)) return null;
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (value.items !== undefined && !Array.isArray(value.items)) return null;
  if (value.sections !== undefined && !Array.isArray(value.sections)) return null;
  if (value.data !== undefined && !isObject(value.data)) return null;
  if (value.email !== undefined && !isObject(value.email)) return null;
  if (value.state !== undefined && !isObject(value.state)) return null;
  return value;
}

/**
 * Run one approved custom step inside its wall.
 *
 * `deps` is the seam, and every member falls back to the real thing:
 *  - `language`, `entry`, `envDir`, `assetsDir`, `assetBinds` (`[{name, path}]`), `egressAllow` (the
 *    report's approved and verified hosts), `injectRules` (from `injectRulesFor`), `nodeBin`,
 *    `uvCacheDir`, `home`;
 *  - `secrets` and `extraSecrets`: literal values redacted out of the answer (the caller's credentials,
 *    plus anything it wants gone);
 *  - `relayOptions`: extra options for the relay (a test's `lookup`, `local`, and with
 *    `testSeams: true` a socket override or a trust anchor). It can never relax the two lists
 *    this run owns, and without `testSeams` only `lookup` and `local` are read at all;
 *  - `testSeams`: true only from a test harness, and never from a gateway caller (custom-step.js
 *    drops both members from the deps it forwards);
 *  - `probe`, `seccompSupported`, `buildSeccompProgram`, `buildPlan`, `spawn`, `createRelay`,
 *    `prlimit`, `tmpdir`, `now`.
 *
 * @param {object} o reportId, stepKey, input, state, params, timeoutMs, memoryMb, deps
 * @returns {Promise<{ok: true, output: object}|
 *   {ok: false, code: string, error: string, stderr?: string}>} `stderr` is the kept, redacted stderr
 *   tail (for the run's own log, never shown as prose)
 */
export async function runCustomStep(o = {}) {
  const deps = o.deps && typeof o.deps === "object" ? o.deps : {};
  const wall = probeWall(deps);
  if (wall.ok !== true) return refuse(NO_WALL_CODE, NO_WALL_TEXT);

  const language = deps.language;
  if (language !== "python" && language !== "node") return refuse("bad_input");
  if (typeof deps.entry !== "string" || !deps.entry) return refuse("bad_input");
  if (typeof deps.envDir !== "string" || !deps.envDir) return refuse("bad_input");
  if (typeof deps.assetsDir !== "string" || !deps.assetsDir) return refuse("bad_input");
  const nodeBin = typeof deps.nodeBin === "string" && deps.nodeBin ? deps.nodeBin : process.execPath;
  const home = typeof deps.home === "string" && deps.home ? deps.home : homedir();
  const timeoutMs = Number.isFinite(Number(o.timeoutMs)) && Number(o.timeoutMs) > 0 ? Number(o.timeoutMs) : DEFAULT_TIMEOUT_MS;
  const memoryMb = Number.isInteger(o.memoryMb) && o.memoryMb > 0 ? o.memoryMb : DEFAULT_MEMORY_MB;

  const spawnFn = typeof deps.spawn === "function" ? deps.spawn : spawnChild;
  const createRelay = typeof deps.createRelay === "function" ? deps.createRelay : createEgressRelay;
  const buildPlan = typeof deps.buildPlan === "function" ? deps.buildPlan : buildStepPlan;
  const supportsSeccomp = typeof deps.seccompSupported === "function" ? deps.seccompSupported : seccompSupported;
  const buildProgram = typeof deps.buildSeccompProgram === "function" ? deps.buildSeccompProgram : buildSeccompProgram;
  const tmpdirFn = typeof deps.tmpdir === "function" ? deps.tmpdir : osTmpdir;
  const prlimit = deps.prlimit === undefined ? PRLIMIT : deps.prlimit;
  // The address-space cap is part of the wall: without `prlimit` there is no memory cap at all,
  // and a step that can take the whole machine is not a walled step. Nothing is spawned.
  if (typeof prlimit !== "string" || !prlimit) return refuse(NO_WALL_CODE, NO_WALL_TEXT);

  // EVERY secret in play: the run's own, whatever else the caller wants gone, and each rule's own
  // value (a rule that cannot answer is not a reason to run unredacted).
  const secretValues = new Set();
  const addSecret = (value) => { if (typeof value === "string" && value) secretValues.add(value); };
  for (const value of Array.isArray(deps.secrets) ? deps.secrets : []) addSecret(value);
  for (const value of Array.isArray(deps.extraSecrets) ? deps.extraSecrets : []) addSecret(value);
  const injectRules = Array.isArray(deps.injectRules) ? deps.injectRules : [];
  for (const rule of injectRules) {
    try { addSecret(typeof rule?.secret === "function" ? rule.secret() : null); } catch { /* not readable yet */ }
  }
  const secrets = [...secretValues];
  const redact = (text) => redactSecrets(String(text), secrets);

  const egressAllow = Array.isArray(deps.egressAllow) ? deps.egressAllow.filter((h) => typeof h === "string" && h) : [];
  const injectHosts = injectRules.map((rule) => (rule && typeof rule.host === "string" ? rule.host : "")).filter(Boolean);
  const connectHosts = egressAllow.filter((host) => !injectHosts.includes(host));
  // The address-space cap the step runs under, applied by `prlimit` INSIDE the wall, in BYTES: Python
  // at the cap itself, Node at four times it (V8 reserves far more address space than it uses).
  const commandPrefix = addressSpacePrefix({ language, memoryMb, prlimit });

  const relayDir = mkdtempSync(join(tmpdirFn(), "crow-report-step-net-" + process.pid + "-"));
  const workDir = mkdtempSync(join(tmpdirFn(), "crow-report-step-work-" + process.pid + "-"));
  let relay = null;
  let seccompFd = null;
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    if (Number.isInteger(seccompFd)) { try { closeSync(seccompFd); } catch { /* closed */ } seccompFd = null; }
    if (relay) {
      try {
        const done = relay.close?.();
        if (done && typeof done.then === "function") done.catch(() => {});
      } catch { /* already down */ }
      relay = null;
    }
    try { rmSync(relayDir, { recursive: true, force: true }); } catch { /* already gone */ }
    try { rmSync(workDir, { recursive: true, force: true }); } catch { /* already gone */ }
  };

  try {
    // 1. The relay this step's namespace is wired to: approved hosts only, and no gateway port (a step
    //    has no door to anything). A rule the relay refuses is a construction error: no step runs with
    //    an egress list this process could not stand behind.
    try {
      relay = createRelay({
        ...relayOptionsFor(deps),
        dir: relayDir,
        botId: "report:" + String(o.reportId || "?") + ":" + String(o.stepKey || "?"),
        gatewayPort: 0,
        egressPorts: [443],
        egressAllow,
        inject: injectRules,
      });
    } catch {
      return refuse("relay_failed");
    }
    if (!relay || typeof relay.close !== "function") return refuse("relay_failed");
    try { await relay.ready; } catch { return refuse("relay_failed"); }

    // 2. The seccomp filter, on an unlinked fd.
    if (supportsSeccomp() !== true) return refuse(NO_WALL_CODE, NO_WALL_TEXT);
    seccompFd = openSeccompProgram(buildProgram, tmpdirFn);
    if (!Number.isInteger(seccompFd)) return refuse(NO_WALL_CODE, NO_WALL_TEXT);

    // 3. The plan.
    let plan = null;
    try {
      plan = buildPlan({
        reportId: o.reportId,
        stepKey: o.stepKey,
        language,
        entry: deps.entry,
        envDir: deps.envDir,
        bundleDir: deps.bundleDir,
        assetsDir: deps.assetsDir,
        assetBinds: Array.isArray(deps.assetBinds) ? deps.assetBinds : [],
        relaySock: relay.socketPath || join(relayDir, "relay.sock"),
        proxyPort: Number.isInteger(deps.proxyPort) ? deps.proxyPort : STEP_PROXY_PORT,
        workDir,
        nodeBin,
        uvCacheDir: typeof deps.uvCacheDir === "string" && deps.uvCacheDir ? deps.uvCacheDir : null,
        seccompFd: SECCOMP_CHILD_FD,
        // A Node step caps its own heap; the address-space cap (four times as wide) is the `prlimit` this
        // step runs under, because V8 reserves far more address space than it ever uses.
        runtimeArgs: language === "node" ? ["--max-old-space-size=" + memoryMb] : [],
        // `prlimit` INSIDE the wall, on the step's own process only: the Node that runs the entry needs
        // far more address space than a step's cap, so the cap can never sit in front of the wall.
        commandPrefix,
        injectHosts,
        connectHosts,
        home,
      });
    } catch (err) {
      return refuse(err && typeof err.code === "string" ? err.code : "bad_input");
    }

    // 4. The run.
    const outcome = await spawnStep({
      cmd: wall.bwrap, args: plan.args, env: plan.env, seccompFd, spawnFn, timeoutMs,
      stdin: JSON.stringify({
        input: o.input === undefined ? null : o.input,
        state: o.state === undefined ? null : o.state,
        params: o.params === undefined ? null : o.params,
      }),
    });

    const stderr = redact(outcome.stderrText || "").slice(0, STDERR_MAX_BYTES);
    if (outcome.timedOut) return { ...refuse("timeout"), stderr };
    if (outcome.outputTooLarge) return { ...refuse("output_too_large"), stderr };
    if (outcome.spawnError) return { ...refuse("exit_nonzero"), stderr };
    if (outcome.signal === "SIGKILL" || outcome.signal === "SIGABRT" || outcome.code === 137 || outcome.code === 134) {
      return { ...refuse("memory"), stderr };
    }
    if (outcome.code !== 0) return { ...refuse("exit_nonzero"), stderr };

    // 6. The answer: redacted BEFORE it is parsed, then exactly one JSON object.
    const text = redact(outcome.stdoutText || "");
    let parsed;
    try {
      parsed = JSON.parse(text.trim() || "null");
    } catch {
      return { ...refuse("bad_output"), stderr };
    }
    const output = normalizeStepOutput(parsed);
    if (!output) return { ...refuse("bad_output"), stderr };
    return { ok: true, output };
  } catch {
    return refuse("exit_nonzero");
  } finally {
    cleanup();
  }
}

/**
 * Spawn the walled command, write its JSON document, and collect its answer under the three caps.
 * Never throws.
 */
function spawnStep({ cmd, args, env, seccompFd, spawnFn, timeoutMs, stdin }) {
  return new Promise((resolveRun) => {
    const chunks = [];
    let stdoutBytes = 0;
    let outputTooLarge = false;
    let stderrBytes = 0;
    const stderrChunks = [];
    let timedOut = false;
    let spawnError = null;
    let settled = false;
    let timer = null;
    let child = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolveRun({
        ...result,
        stdoutText: result.stdoutText === undefined
          ? Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)))).toString("utf8")
          : result.stdoutText,
        stderrText: Buffer.concat(stderrChunks).toString("utf8"),
      });
    };

    const killGroup = () => {
      if (!child || !child.pid) return;
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* the group is gone */ }
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
    };

    const stdio = ["pipe", "pipe", "pipe"];
    if (Number.isInteger(seccompFd)) stdio[SECCOMP_CHILD_FD] = seccompFd;
    try {
      child = spawnFn(cmd, args, { env, cwd: "/", stdio, detached: true, shell: false });
    } catch (err) {
      finish({ code: null, signal: null, spawnError: err });
      return;
    }
    child.on("error", (err) => {
      spawnError = err;
      finish({ code: null, signal: null, spawnError });
    });
    child.stdout?.on("data", (chunk) => {
      if (outputTooLarge) return;
      const buf = Buffer.from(chunk);
      stdoutBytes += buf.length;
      if (stdoutBytes > OUTPUT_MAX_BYTES) {
        outputTooLarge = true;
        chunks.length = 0;
        killGroup();
        return;
      }
      chunks.push(buf);
    });
    child.stderr?.on("data", (chunk) => {
      // Read past the cap (a child that keeps writing must not block), but keep no more of it.
      if (stderrBytes >= STDERR_MAX_BYTES) return;
      const buf = Buffer.from(chunk);
      const keep = buf.subarray(0, STDERR_MAX_BYTES - stderrBytes);
      stderrBytes += keep.length;
      stderrChunks.push(keep);
    });
    child.on("close", (code, signal) => {
      if (timedOut) return finish({ code, signal, timedOut });
      if (outputTooLarge) return finish({ code, signal, outputTooLarge });
      if (spawnError) return finish({ code, signal, spawnError });
      return finish({ code, signal });
    });

    // The document the step reads, then EOF: a step that never reads stdin is not held by it.
    try {
      child.stdin?.on("error", () => { /* the step may have closed it */ });
      child.stdin?.end(stdin);
    } catch { /* the child is gone already */ }

    timer = setTimeout(() => {
      timedOut = true;
      killGroup();
    }, timeoutMs);
    timer.unref?.();
  });
}