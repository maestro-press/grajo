/**
 * Per-report, per-language dependency envs for custom steps: the walled build and the wall it runs in.
 *
 * A step's dependencies are installed ONCE per (report, language, requirements hash) and then mounted
 * READ-ONLY into every run of that step, so the code a step executes is the code the warm-up resolved
 * and nothing a run can rewrite. The build itself is untrusted work (a package's install scripts, a
 * resolver fetching a wheel), so it runs WALLED like everything else here: a fresh root, one read-write
 * build folder and one read-write cache, and an egress relay whose allowed hosts are exactly the three
 * package registries and nothing else (`WARMUP_HOSTS`; the same set `scripts/addon-sandbox/warmup.mjs`
 * uses, not widened).
 *
 * Three rules:
 *  - Python goes through `uv` and ONLY through `uv`: `uv venv --python /usr/bin/python3` then
 *    `uv pip install --no-build`. `UV_PYTHON_DOWNLOADS=never` is in the wall's env, so uv never tries to
 *    fetch a managed interpreter from a host the warm-up refuses. No `uv` on this computer is an honest
 *    `uv_missing`, never a fallback to pip.
 *  - Node goes through `npm ci --ignore-scripts`: a third-party package's install script never runs.
 *  - Build artifacts are never run unwalled: `runWarmup` refuses to start anything without the wall.
 *
 * Node built-ins only; the spawn, the clock and the relay are `deps` seams.
 */
import { spawn as spawnChild } from "node:child_process";
import { closeSync, existsSync, mkdtempSync, openSync, realpathSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { assembleBindArgs, rootArgs } from "../pi-bots/pi_contain.mjs";
import { ENTRY_MARK } from "../pi-bots/pi_netns_entry.mjs";
import { buildSeccompProgram, seccompSupported } from "../pi-bots/pi_seccomp.mjs";
import { createEgressRelay } from "../pi-bots/pi_egress.mjs";
import { probeWall, NO_WALL_TEXT } from "./runner.mjs";
import { nodeBinaryFor, STEP_LANG, STEP_PATH, SYSTEM_PYTHON } from "./plan.mjs";

/** The in-namespace entry the warm-up runs under (the relay's forwarder). */
const NETNS_ENTRY = fileURLToPath(new URL("../pi-bots/" + ENTRY_MARK, import.meta.url));

/**
 * The only hosts a dependency install may reach. The same three the add-on warm-up uses; a fourth
 * would be a widening nobody approved, so there is no way to add one at run time.
 */
export const WARMUP_HOSTS = Object.freeze(["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]);

/** Where the build's two mounts appear inside the warm-up's root. */
export const WARMUP_BUILD_MOUNT = "/build";
export const WARMUP_CACHE_MOUNT = "/cache";
/** The proxy port inside the warm-up's own network namespace. */
const WARMUP_PROXY_PORT = 39081;
/** How long one install step may run. */
export const WARMUP_TIMEOUT_MS = 600_000;
/** The fds the entry hands the install command. */
const CHILD_FDS = "0,1,2";
/** bwrap reads the seccomp program here. */
const SECCOMP_CHILD_FD = 3;

/** `p` is `root` or inside it: a SEGMENT-aware test, so `/usr/local` is neither `/usr` nor under it. */
const under = (p, root) => p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);

/** A uv/uvx-style refusal, as the code the caller reports. */
const UV_MISSING = "uv_missing";
/** Anything else that stopped the build. */
const ENV_FAILED = "env_failed";

/** One `bwrap --help`-free seccomp fd: the program goes to an already-unlinked file. */
function openSeccompProgram(build, tmpdirFn) {
  const dir = mkdtempSync(join(tmpdirFn(), "crow-report-env-seccomp-" + process.pid + "-"));
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
 * The install steps one language needs, in order, each of which must exit 0, and the fixed settings
 * their wall carries. `null` when this language has no step this module will build.
 *
 * @param {{language: "python"|"node", buildDir: string, nodeBin?: string, uvBin?: string, npmBin?: string}} o
 * @returns {{steps: {cmd: string, args: string[]}[], env: object}|{refused: string}|null}
 */
export function warmupStepsFor({ language, buildDir, nodeBin = process.execPath, uvBin = null, npmBin = null } = {}) {
  if (typeof buildDir !== "string" || !isAbsolute(buildDir)) return { refused: ENV_FAILED };
  if (language === "python") {
    // A missing uv is honest, and it is never answered with pip: a pip install here would be a
    // different resolver reaching a different set of hosts than the wall allows.
    if (typeof uvBin !== "string" || !uvBin) return { refused: UV_MISSING };
    const venvPython = join(WARMUP_BUILD_MOUNT, "bin", "python");
    return {
      steps: [
        { cmd: uvBin, args: ["venv", "--quiet", "--python", SYSTEM_PYTHON, WARMUP_BUILD_MOUNT] },
        {
          cmd: uvBin,
          args: ["pip", "install", "--quiet", "--no-build", "--python", venvPython, "-r", WARMUP_BUILD_MOUNT + "/requirements.txt"],
        },
      ],
      env: {
        UV_PYTHON_DOWNLOADS: "never",
        PYTHONDONTWRITEBYTECODE: "1",
        UV_CACHE_DIR: join(WARMUP_CACHE_MOUNT, "uv"),
      },
    };
  }
  if (language === "node") {
    if (typeof npmBin !== "string" || !npmBin) return { refused: ENV_FAILED };
    return {
      steps: [{
        cmd: npmBin,
        args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
      }],
      env: {
        npm_config_cache: join(WARMUP_CACHE_MOUNT, "npm"),
        npm_config_ignore_scripts: "true",
        npm_config_audit: "false",
        npm_config_fund: "false",
        PYTHONDONTWRITEBYTECODE: "1",
      },
    };
  }
  return null;
}

/**
 * The wall around one install step: an empty root with the system dirs read-only, the build folder and
 * the cache writable, the relay socket read-only, the seccomp filter, and the in-namespace entry.
 *
 * `cmd` is the bwrap binary the plan's argv is run with (the probed one), never the node the argv
 * carries: a plan with no wall command is not built at all.
 *
 * @returns {{args: string[], env: object, cmd: string}}
 */
export function buildWarmupPlan({
  buildDir, cacheDir, relaySock, nodeBin = process.execPath, bwrap, seccompFd = null,
  home = homedir(), proxyPort = WARMUP_PROXY_PORT, command, commandArgs = [], fixedEnv = {}, exists = existsSync,
}) {
  if (typeof bwrap !== "string" || !bwrap) throw new Error("a warm-up plan needs the bwrap binary it is run with");
  const realBuild = realpathSync(buildDir);
  const realCache = realpathSync(cacheDir);
  const realRelay = realpathSync(dirname(relaySock));
  const resolvedHome = resolve(home);
  const args = rootArgs({ exists, home: resolvedHome });
  const extraEntries = [
    ["--bind", realBuild, WARMUP_BUILD_MOUNT],
    ["--bind", realCache, WARMUP_CACHE_MOUNT],
    ["--ro-bind", realRelay, "/run/crow-net"],
  ];
  // The in-namespace entry is one self-contained node program from this checkout; the warm-up's root
  // holds none of the checkout, so that file is bound read-only at its own path.
  let entryReal = null;
  try { entryReal = realpathSync(NETNS_ENTRY); } catch { entryReal = null; }
  if (!entryReal) throw new Error("the in-namespace entry cannot be resolved");
  extraEntries.push(["--ro-bind", entryReal, NETNS_ENTRY]);
  // The engine the install steps run under, and (when it is not already in the root's read-only /usr
  // or /opt) its install prefix, because npm lives in that prefix. `nodeBinaryFor` refuses a binary or
  // a prefix that is under, or above, the Crow home, a co-hosted instance's home or another user's
  // home; `/usr` and `/opt` are matched by SEGMENT, so `/usrlocal` is not a system directory.
  const node = nodeBinaryFor(nodeBin, { home: resolvedHome, withPrefix: true });
  if (!node.inSystemDirs && node.prefix) extraEntries.push(["--ro-bind", node.prefix, node.prefix]);
  args.push(...assembleBindArgs({ ro: new Map(), rw: new Map(), masks: [], extraEntries }));
  args.push(
    "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
    "--unshare-net", "--cap-drop", "ALL", "--die-with-parent", "--new-session",
    "--chdir", WARMUP_BUILD_MOUNT,
  );
  if (Number.isInteger(seccompFd)) args.push("--seccomp", String(SECCOMP_CHILD_FD));
  args.push(
    "--",
    node.real,
    NETNS_ENTRY,
    "--sock", "/run/crow-net/" + relaySock.split("/").pop(),
    "--proxy-port", String(proxyPort),
    "--fds", CHILD_FDS,
    "--",
    command,
    ...commandArgs,
  );
  const proxy = "http://127.0.0.1:" + proxyPort;
  const env = {
    PATH: dirname(node.real) + ":" + STEP_PATH,
    LANG: STEP_LANG,
    TMPDIR: "/tmp",
    HOME: resolvedHome,
    HTTP_PROXY: proxy,
    HTTPS_PROXY: proxy,
    http_proxy: proxy,
    https_proxy: proxy,
    NO_PROXY: "127.0.0.1,localhost,::1",
    no_proxy: "127.0.0.1,localhost,::1",
    NODE_USE_ENV_PROXY: "1",
    ...fixedEnv,
  };
  return { args, env, cmd: bwrap };
}

/** One walled step: spawn it, keep its stderr tail, and answer a fixed code. */
function runOneStep({ wall, spawnFn, timeoutMs }) {
  return new Promise((resolveRun) => {
    let child = null;
    let timedOut = false;
    let settled = false;
    const stderr = [];
    let stderrBytes = 0;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolveRun(result);
    };
    let timer = null;
    try {
      child = spawnFn(wall.cmd, wall.args, {
        env: wall.env,
        cwd: "/",
        stdio: ["ignore", "ignore", "pipe", ...(wall.seccompFd === null ? [] : [wall.seccompFd])],
        detached: true,
        shell: false,
      });
    } catch {
      finish({ ok: false, code: ENV_FAILED });
      return;
    }
    child.on("error", () => finish({ ok: false, code: ENV_FAILED }));
    child.stderr?.on("data", (chunk) => {
      if (stderrBytes >= 8192) return;
      const keep = Buffer.from(chunk).subarray(0, 8192 - stderrBytes);
      stderrBytes += keep.length;
      stderr.push(keep);
    });
    child.on("close", (code) => {
      if (timedOut) return finish({ ok: false, code: ENV_FAILED });
      if (code !== 0) return finish({ ok: false, code: ENV_FAILED });
      return finish({ ok: true });
    });
    timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
    }, Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? Number(timeoutMs) : WARMUP_TIMEOUT_MS);
    timer.unref?.();
  });
}

/**
 * Run a language's install steps inside the wall, once. Answers `{ok: true}` or `{ok: false, code}`,
 * with `no_wall` when this computer has no sandbox (nothing is started unwalled) and `uv_missing` when
 * Python dependencies were asked for and there is no usable uv.
 *
 * @param {object} o
 * @param {string} o.reportId
 * @param {string} o.language
 * @param {string} o.buildDir  the fresh folder the env is built in (the caller swaps it into place)
 * @param {string} o.cacheDir  the resolver cache, writable inside the wall
 * @param {string} [o.uvBin]
 * @param {string} [o.npmBin]
 * @param {string} [o.nodeBin]
 * @param {object} [o.deps] seams: probe, spawn, createRelay, seccompSupported, buildSeccompProgram, tmpdir, home
 * @returns {Promise<{ok: boolean, code?: string}>}
 */
export async function runWarmup(o = {}) {
  const deps = o.deps && typeof o.deps === "object" ? o.deps : {};
  const wallProbe = probeWall(deps);
  if (wallProbe.ok !== true) return { ok: false, code: "no_wall", error: NO_WALL_TEXT };
  const plan = warmupStepsFor({
    language: o.language,
    buildDir: o.buildDir,
    nodeBin: o.nodeBin,
    uvBin: o.uvBin,
    npmBin: o.npmBin,
  });
  if (!plan) return { ok: false, code: ENV_FAILED };
  if (typeof plan.refused === "string") return { ok: false, code: plan.refused };

  const spawnFn = typeof deps.spawn === "function" ? deps.spawn : spawnChild;
  const createRelay = typeof deps.createRelay === "function" ? deps.createRelay : createEgressRelay;
  const supportsSeccomp = typeof deps.seccompSupported === "function" ? deps.seccompSupported : seccompSupported;
  const buildProgram = typeof deps.buildSeccompProgram === "function" ? deps.buildSeccompProgram : buildSeccompProgram;
  const tmpdirFn = typeof deps.tmpdir === "function" ? deps.tmpdir : osTmpdir;
  const home = typeof deps.home === "string" && deps.home ? deps.home : homedir();
  const nodeBin = typeof o.nodeBin === "string" && o.nodeBin ? o.nodeBin : process.execPath;
  const timeoutMs = Number.isFinite(Number(o.timeoutMs)) && Number(o.timeoutMs) > 0 ? Number(o.timeoutMs) : WARMUP_TIMEOUT_MS;

  const relayDir = mkdtempSync(join(tmpdirFn(), "crow-report-env-net-" + process.pid + "-"));
  let relay = null;
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    if (relay) { try { const done = relay.close?.(); if (done && typeof done.then === "function") done.catch(() => {}); } catch { /* already down */ } }
    try { rmSync(relayDir, { recursive: true, force: true }); } catch { /* already gone */ }
  };

  try {
    relay = createRelay({
      dir: relayDir,
      botId: "report-env:" + String(o.reportId || "?"),
      gatewayPort: 0,
      egressPorts: [443],
      egressAllow: [...WARMUP_HOSTS],
    });
    if (!relay || typeof relay.close !== "function") return { ok: false, code: ENV_FAILED };
    try { await relay.ready; } catch { return { ok: false, code: ENV_FAILED }; }
    // No seccomp table for this architecture: the wall is the bind set and the namespace, exactly as the
    // add-on wall's "no seccomp" tier has it. The build still never runs outside a wall.
    const withSeccomp = supportsSeccomp() === true;
    const program = withSeccomp ? buildProgram() : null;

    for (const step of plan.steps) {
      // One program per step: the fd bwrap reads is consumed by that read, so a second step needs a
      // fresh one (and it is closed as soon as the step is over).
      let stepFd = null;
      let wall = null;
      try {
        if (withSeccomp) {
          stepFd = openSeccompProgram(() => program, tmpdirFn);
          if (!Number.isInteger(stepFd)) return { ok: false, code: ENV_FAILED };
        }
        // The spawned command is the wall binary the probe named; `args` is the wall's own argv.
        wall = buildWarmupPlan({
          buildDir: o.buildDir,
          cacheDir: o.cacheDir,
          relaySock: relay.socketPath,
          nodeBin,
          bwrap: wallProbe.bwrap,
          seccompFd: stepFd,
          home,
          command: step.cmd,
          commandArgs: step.args,
          fixedEnv: plan.env,
        });
      } catch {
        if (Number.isInteger(stepFd)) { try { closeSync(stepFd); } catch { /* closed */ } }
        return { ok: false, code: ENV_FAILED };
      }
      const outcome = await runOneStep({ wall: { ...wall, seccompFd: stepFd }, spawnFn, timeoutMs });
      if (Number.isInteger(stepFd)) { try { closeSync(stepFd); } catch { /* closed */ } }
      if (!outcome.ok) return outcome;
    }
    return { ok: true };
  } finally {
    cleanup();
  }
}