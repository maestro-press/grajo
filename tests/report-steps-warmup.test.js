// PR 3c: the warm-up's own run. Its install steps are untrusted work (`npm ci` runs a resolver,
// `uv pip install` fetches wheels), so every one of them is spawned as the PROBED bwrap binary with the
// wall's argv: the build never starts unwalled, and nothing here ever spawns node by mistake.
//
// Always runs: the wall probe, the relay, the seccomp program, the spawn and the clock are stubs, so
// this file needs no bubblewrap, no uv, no npm and no network.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildWarmupPlan, runWarmup } from "../scripts/report-steps/warmup.mjs";

const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-report-env-warmup-")));
after(() => rmSync(T, { recursive: true, force: true }));

const BWRAP = "/usr/bin/bwrap";
const REPORT_ID = "rpt-0123456789abcdef";
const UV = "/usr/bin/uv";
const NPM = "/usr/bin/npm";

let seq = 0;

/** One run's four folders: the build, the cache, this instance's home and its node engine. */
function fixture() {
  const base = join(T, "run-" + (++seq));
  const buildDir = join(base, "build");
  const cacheDir = join(base, "cache");
  const home = join(base, "home");
  const nodeDir = join(base, "engine", "bin");
  for (const dir of [buildDir, cacheDir, home, nodeDir]) mkdirSync(dir, { recursive: true });
  const nodeBin = join(nodeDir, "node");
  writeFileSync(nodeBin, "");
  return { buildDir, cacheDir, home, nodeBin };
}

/** A child that starts, then closes with `code`, and records nothing of its own. */
function stubSpawn(calls, { code = 0 } = {}) {
  return (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    const child = new EventEmitter();
    child.pid = 4000 + calls.length;
    child.stderr = new EventEmitter();
    child.kill = () => {};
    setImmediate(() => child.emit("close", code));
    return child;
  };
}

/** The relay seam: a socket path inside the dir the warm-up made, and nothing else. */
const stubRelay = ({ dir }) => ({
  socketPath: join(dir, "relay.sock"),
  ready: Promise.resolve(),
  close: () => {},
  denials: () => [],
});

/** The seams every run here uses: a wall that exists, a seccomp program that builds, a stubbed spawn. */
function deps(over = {}) {
  return {
    probe: () => ({ ok: true, pidns: true, bwrap: BWRAP }),
    seccompSupported: () => true,
    buildSeccompProgram: () => Buffer.from([0x20, 0x00, 0x00, 0x00]),
    createRelay: stubRelay,
    ...over,
  };
}

/** The argv after the wall's last `--`: the install command and its own arguments. */
const stepCommand = (args) => args.slice(args.lastIndexOf("--") + 1);

/* ------------------------------------------------------------- the spawn is the wall */

test("a python warm-up spawns the probed bwrap, never node, and the argv ends with the uv command", async () => {
  const f = fixture();
  const calls = [];
  const outcome = await runWarmup({
    reportId: REPORT_ID,
    language: "python",
    buildDir: f.buildDir,
    cacheDir: f.cacheDir,
    nodeBin: f.nodeBin,
    uvBin: UV,
    deps: deps({ spawn: stubSpawn(calls), home: f.home }),
  });
  assert.deepEqual(outcome, { ok: true });
  assert.equal(calls.length, 2, "one spawn per install step");
  for (const call of calls) {
    assert.equal(call.cmd, BWRAP, "the wall binary is the spawned command: " + call.cmd);
    assert.notEqual(call.cmd, f.nodeBin, "node is never the spawned command");
    assert.deepEqual(call.args.slice(0, 2), ["--tmpfs", "/"], "the argv starts with the wall's root");
    assert.equal(call.args.includes("--unshare-net"), true, "and carries the wall's namespaces");
    assert.equal(call.args.includes("--die-with-parent"), true);
    // The env-building rule: uv is told never to fetch an interpreter, and the wall's env is the only
    // env the install gets.
    assert.equal(call.opts.env.UV_PYTHON_DOWNLOADS, "never");
    assert.equal(call.opts.env.HOME, f.home);
    assert.equal(String(call.opts.env.HTTPS_PROXY).startsWith("http://127.0.0.1:"), true);
  }
  assert.deepEqual(stepCommand(calls[0].args), [UV, "venv", "--quiet", "--python", "/usr/bin/python3", "/build"]);
  assert.deepEqual(stepCommand(calls[1].args).slice(0, 5), [UV, "pip", "install", "--quiet", "--no-build"]);
  assert.equal(stepCommand(calls[1].args).includes("-r"), true, "the requirements file is what is installed");
});

test("a node warm-up is spawned the same way: bwrap, then npm ci with its scripts off", async () => {
  const f = fixture();
  const calls = [];
  const outcome = await runWarmup({
    reportId: REPORT_ID,
    language: "node",
    buildDir: f.buildDir,
    cacheDir: f.cacheDir,
    nodeBin: f.nodeBin,
    npmBin: NPM,
    deps: deps({ spawn: stubSpawn(calls), home: f.home }),
  });
  assert.deepEqual(outcome, { ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, BWRAP);
  assert.deepEqual(calls[0].args.slice(0, 2), ["--tmpfs", "/"]);
  assert.equal(calls[0].opts.env.npm_config_ignore_scripts, "true");
  assert.deepEqual(stepCommand(calls[0].args), [NPM, "ci", "--ignore-scripts", "--no-audit", "--no-fund"]);
});

/* --------------------------------------------------------------- every refusal spawns nothing */

test("with no wall the warm-up refuses and spawns nothing", async () => {
  const f = fixture();
  let spawns = 0;
  let relays = 0;
  const outcome = await runWarmup({
    reportId: REPORT_ID,
    language: "python",
    buildDir: f.buildDir,
    cacheDir: f.cacheDir,
    nodeBin: f.nodeBin,
    uvBin: UV,
    deps: deps({
      probe: () => ({ ok: false, reason: "bubblewrap (bwrap) is not installed" }),
      spawn: () => { spawns += 1; throw new Error("a build was spawned without a wall"); },
      createRelay: () => { relays += 1; throw new Error("a relay was opened without a wall"); },
      home: f.home,
    }),
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.code, "no_wall");
  assert.equal(spawns, 0, "no install step ran");
  assert.equal(relays, 0, "no relay was opened");
});

test("no uv is an honest uv_missing, and no fallback is spawned", async () => {
  const f = fixture();
  let spawns = 0;
  const outcome = await runWarmup({
    reportId: REPORT_ID,
    language: "python",
    buildDir: f.buildDir,
    cacheDir: f.cacheDir,
    nodeBin: f.nodeBin,
    uvBin: null,
    deps: deps({ spawn: () => { spawns += 1; throw new Error("a pip fallback was spawned"); }, home: f.home }),
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.code, "uv_missing");
  assert.equal(spawns, 0);
});

/* ------------------------------------------------------------------- the plan's command */

test("a warm-up plan without the bwrap binary it runs in is not built", () => {
  const f = fixture();
  mkdirSync(join(T, "relay-" + seq), { recursive: true });
  assert.throws(() => buildWarmupPlan({
    buildDir: f.buildDir,
    cacheDir: f.cacheDir,
    relaySock: join(T, "relay-" + seq, "relay.sock"),
    nodeBin: f.nodeBin,
    home: f.home,
    command: UV,
    commandArgs: ["venv"],
  }));
});