// PR 3c: the gateway entry point a recipe's `custom` block will call (PR 4a). Everything that stands
// between an approved step and the walled runner, in the order it happens: the newest revision must be
// approved, a non-scheduled run counts one extra step run against the day's cap, the assets and hosts
// the approval covers are re-checked, the bundle dir is written fresh and removed whatever happens.
//
// The runner is stubbed here, so this file needs no bubblewrap: it is about the refusals and the
// bookkeeping, not about the sandbox (tests/report-steps-runner.test.js is that).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-custom-step-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;

const { createDbClient } = await import("../servers/db.js");
const { createReport } = await import("../servers/gateway/reports/store.js");
const { approveStep, proposeStep, saveAsset } = await import("../servers/gateway/reports/steps.js");
const { getUsage } = await import("../servers/gateway/reports/caps.js");
const { CLAIMED_BY_EXECUTOR } = await import("../servers/gateway/reports/claim-token.js");
const { runCustomStepForReport, writeBundleDir } = await import("../servers/gateway/reports/custom-step.js");
const { runCustomStep } = await import("../scripts/report-steps/runner.mjs");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 29);
const T0 = 1_700_000_000_000;
const DAY = "2026-01-02";
const WAITING = (key) => `Step ${key} is waiting for your OK`;

const FILES = Object.freeze({
  "run.py": "print('{}')\n",
  "templates/report.html": "<h1>{{ title }}</h1>\n",
});

const open = [];
after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

let n = 0;

async function freshDb() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

function deps(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    crowHome: HOME,
    day: DAY,
    ...over,
  };
}

async function makeReport(db) {
  const { id } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title: "Weekly listings" });
  return id;
}

async function proposed(db, reportId, over = {}) {
  return proposeStep(db, deps(), {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: FILES,
    requirements: "jinja2==3.1.4\n",
    proposedBy: "owner",
    ...over,
  });
}

/** An approved step, plus the env dir the runner would be handed, plus a recording runner stub. */
async function approvedFixture(db, over = {}) {
  const reportId = await makeReport(db);
  const step = await proposed(db, reportId, over);
  await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: step.rev, bundleHash: step.bundleHash, actor: OWNER,
  });
  const envDir = join(HOME, "reports", reportId, "env", "python");
  mkdirSync(envDir, { recursive: true });
  const runs = [];
  const runDeps = deps({
    ensureEnv: async () => ({ ok: true, dir: envDir, hash: "c".repeat(64), cacheDir: join(HOME, "cache"), built: false }),
    runStep: async (args) => {
      runs.push(args);
      return { ok: true, output: { items: [{ title: "One new listing" }] } };
    },
  });
  return { reportId, runDeps, runs };
}

/* ------------------------------------------------------ the newest revision must be approved */

test("an unapproved newest revision is not run, and the answer is the waiting sentence", async () => {
  const db = await freshDb();
  const { reportId, runDeps, runs } = await approvedFixture(db);

  // A newer revision, proposed and not approved: it is the one that would run, so nothing runs.
  const newer = await proposed(db, reportId, { files: { "run.py": "print('v2')\n" } });
  assert.equal(newer.rev, 2);
  const waiting = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(waiting, { ok: false, code: "step_waiting", error: WAITING("fetch") });
  assert.equal(runs.length, 0, "the runner was never called");

  // And a key that was never proposed is the same answer.
  const unknown = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "other", trigger: "manual" });
  assert.deepEqual(unknown, { ok: false, code: "step_waiting", error: "Step other is waiting for your OK" });

  // A step key that is not one is refused before any of this.
  const bad = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "../fetch", trigger: "manual" });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "bad_input");
});

test("a bundle file changed by a direct UPDATE after approval is not run", async () => {
  const db = await freshDb();
  const { reportId, runDeps, runs } = await approvedFixture(db);
  const { rows } = await db.execute({
    sql: "SELECT files_json FROM report_custom_steps WHERE report_id = ? AND step_key = 'fetch' AND rev = 1",
    args: [reportId],
  });
  const envelope = JSON.parse(rows[0].files_json);
  envelope.files["run.py"] = "import os\nos.system('echo taken over')\n";
  await db.execute({
    sql: "UPDATE report_custom_steps SET files_json = ? WHERE report_id = ? AND step_key = 'fetch' AND rev = 1",
    args: [JSON.stringify(envelope), reportId],
  });
  const result = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(result, { ok: false, code: "step_waiting", error: WAITING("fetch") });
  assert.equal(runs.length, 0);
});

test("an asset swapped on disk after approval is not run", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const saved = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: '[{"id":1}]' });
  const step = await proposed(db, reportId, { assets: ["ways.json"] });
  await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: step.rev, bundleHash: step.bundleHash, actor: OWNER,
  });
  const envDir = join(HOME, "reports", reportId, "env", "python");
  mkdirSync(envDir, { recursive: true });
  const runs = [];
  const runDeps = deps({
    ensureEnv: async () => ({ ok: true, dir: envDir, hash: "d".repeat(64), cacheDir: join(HOME, "cache"), built: false }),
    runStep: async (args) => { runs.push(args); return { ok: true, output: { items: [] } }; },
  });
  // The file behind the row is replaced: the row and the seal are untouched, the bytes are not.
  writeFileSync(join(HOME, "reports", reportId, "assets", saved.sha256), '[{"id":2}]');
  const result = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.equal(result.ok, false);
  // The runnable check reads the asset on disk first, so this is the waiting sentence rather than
  // `asset_changed`; either way the step does not run.
  assert.equal(result.code, "step_waiting");
  assert.equal(runs.length, 0, "an asset the owner did not approve never reaches a run");
});

/* ------------------------------------------------------------------------- the cap */

test("the 11th extra step run of the day is refused, and the first ten are not", async () => {
  const db = await freshDb();
  const { reportId, runDeps, runs } = await approvedFixture(db);
  for (let i = 1; i <= 10; i += 1) {
    const result = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
    assert.equal(result.ok, true, "run " + i + ": " + JSON.stringify(result));
    assert.deepEqual(result.output, { items: [{ title: "One new listing" }] });
  }
  const eleventh = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(eleventh, { ok: false, code: "cap_reached", error: "cap_reached" });
  assert.equal(runs.length, 10, "the eleventh never reached the runner");
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 10);
});

test("a bare token or a bare claim function does not skip the claim: only the executor's pair does", async () => {
  const db = await freshDb();
  const { reportId, runDeps } = await approvedFixture(db);
  const run = (over = {}) => runCustomStepForReport(db, runDeps, {
    report: { id: reportId }, stepKey: "fetch", trigger: "manual", ...over,
  });

  const publicFlag = await run({ claimToken: true, claimExtraStep: true });
  assert.equal(publicFlag.ok, true, JSON.stringify(publicFlag));
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 1,
    "a public boolean is not the executor's claim");

  // The token WITHOUT the run's claim function is not the pair either: the step takes its own claim.
  const tokenOnly = await run({ claimToken: CLAIMED_BY_EXECUTOR });
  assert.equal(tokenOnly.ok, true, JSON.stringify(tokenOnly));
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 2, "the token alone skips nothing");

  // A claim function WITHOUT the token is no pass either.
  const functionOnly = await run({ claimExtraStep: async () => true });
  assert.equal(functionOnly.ok, true, JSON.stringify(functionOnly));
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 3, "a function alone skips nothing");

  // The executor's own pair is the one that claims on the run's behalf, and it is used instead of a
  // second database claim.
  let claimed = 0;
  const paired = await run({
    claimToken: CLAIMED_BY_EXECUTOR,
    claimExtraStep: async () => { claimed += 1; return true; },
  });
  assert.equal(paired.ok, true, JSON.stringify(paired));
  assert.equal(claimed, 1, "the step claimed through the executor's own function");
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 3, "and took no claim of its own");
});

test("the claim token module is imported by the reports internals only", () => {
  const importers = [];
  for (const entry of readdirSync(join(REPO, "servers"), { recursive: true })) {
    const name = String(entry);
    if (!name.endsWith(".js") && !name.endsWith(".mjs")) continue;
    const file = join(REPO, "servers", name);
    let source;
    try {
      if (!statSync(file).isFile()) continue;
      source = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (/from\s+["'][^"']*claim-token\.js["']/.test(source)) importers.push(name.split(sep).join("/"));
  }
  assert.deepEqual(importers.sort(), [
    "gateway/reports/blocks/run-recipe.js",
    "gateway/reports/custom-step.js",
  ], "no caller outside the reports executor can hand a claim away");
});

test("a scheduled trigger does not count toward extra step runs", async () => {
  const db = await freshDb();
  const { reportId, runDeps, runs } = await approvedFixture(db);
  for (let i = 0; i < 3; i += 1) {
    const result = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "schedule" });
    assert.equal(result.ok, true);
  }
  assert.equal(runs.length, 3);
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 0, "the schedule is not an extra run");
  // A bot-requested preview is, exactly like a manual run.
  await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "preview" });
  assert.equal((await getUsage(db, reportId, DAY)).extraStepRuns, 1);
});

/* ------------------------------------------------------------------ the bundle dir */

test("the bundle dir is written fresh, holds the approved files, and is removed on success", async () => {
  const db = await freshDb();
  const { reportId, runDeps } = await approvedFixture(db);
  let seen = null;
  runDeps.runStep = async (args) => {
    seen = {
      dir: args.deps.bundleDir,
      run: readFileSync(join(args.deps.bundleDir, "run.py"), "utf8"),
      template: readFileSync(join(args.deps.bundleDir, "templates", "report.html"), "utf8"),
      language: args.deps.language,
      entry: args.deps.entry,
      envDir: args.deps.envDir,
      assetsDir: args.deps.assetsDir,
      egressAllow: args.deps.egressAllow,
      injectRules: args.deps.injectRules,
      stdin: { input: args.input, state: args.state, params: args.params },
    };
    return { ok: true, output: { items: [] } };
  };
  const result = await runCustomStepForReport(db, runDeps, {
    report: { id: reportId }, stepKey: "fetch", trigger: "manual", input: { week: 1 }, params: { limit: 5 },
  });
  assert.equal(result.ok, true);
  assert.equal(seen.run, FILES["run.py"]);
  assert.equal(seen.template, FILES["templates/report.html"]);
  assert.equal(seen.language, "python");
  assert.equal(seen.entry, "run.py");
  assert.equal(seen.envDir, join(HOME, "reports", reportId, "env", "python"));
  assert.equal(seen.assetsDir, join(HOME, "reports", reportId, "assets"));
  assert.deepEqual(seen.egressAllow, [], "no approved host, nothing to reach");
  assert.deepEqual(seen.injectRules, []);
  assert.deepEqual(seen.stdin, { input: { week: 1 }, state: null, params: { limit: 5 } });
  assert.equal(existsSync(seen.dir), false, "the bundle dir is gone after the run");
});

test("the bundle dir is removed when the run fails too", async () => {
  const db = await freshDb();
  const { reportId, runDeps } = await approvedFixture(db);
  let dir = null;
  runDeps.runStep = async (args) => {
    dir = args.deps.bundleDir;
    return { ok: false, code: "exit_nonzero", error: "exit_nonzero" };
  };
  const result = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(result, { ok: false, code: "exit_nonzero", error: "exit_nonzero" });
  assert.equal(existsSync(dir), false, "a failed run leaves no bundle behind");
});

/* ------------------------------------------------------------- a path that escapes */
test("a bundle path that escapes the dir is refused, and nothing is written outside it", () => {
  const dir = mkdtempSync(join(root, "bundle-"));
  const outside = join(root, "escape.py");
  const bad = [
    { "../escape.py": "x" },
    { "/etc/passwd": "x" },
    { "a/../../escape.py": "x" },
    { "sub\\run.py": "y" },
    { "run.py": 42 },
    { "": "x" },
    {},
  ];
  for (const files of bad) {
    assert.throws(() => writeBundleDir(files, dir), (err) => err && err.code === "bad_input", JSON.stringify(files));
  }
  assert.equal(existsSync(outside), false, "nothing was written outside the bundle dir");
  assert.equal(existsSync(join(dir, "run.py")), false);

  const written = writeBundleDir({ "run.py": "x", "templates/a.html": "y" }, dir);
  assert.equal(written, 2);
  assert.equal(readFileSync(join(dir, "templates", "a.html"), "utf8"), "y");
});

test("a files_json row carrying an escaping path is not run", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  // A row written straight into the table, as a crafted proposal would: proposed, never approved.
  const envelope = JSON.stringify({ files: { "../escape.py": "print(1)\n" }, assets: [] });
  await db.execute({
    sql: `INSERT INTO report_custom_steps
            (report_id, step_key, rev, language, entry, files_json, requirements, bundle_hash, proposed_by, state, created_at)
          VALUES (?, 'fetch', 1, 'python', '../escape.py', ?, '', NULL, 'owner', 'proposed', ?)`,
    args: [reportId, envelope, T0],
  });
  const runs = [];
  const result = await runCustomStepForReport(db, deps({
    runStep: async (args) => { runs.push(args); return { ok: true, output: {} }; },
  }), { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(result, { ok: false, code: "step_waiting", error: WAITING("fetch") });
  assert.equal(runs.length, 0);
  assert.equal(existsSync(join(root, "escape.py")), false);
});

/* -------------------------------------------------- what a caller may hand the runner */

let fakePids = 9000;

/** The child a stubbed spawn answers with: one JSON object on stdout, then a clean exit. */
function fakeChild(output) {
  const child = new EventEmitter();
  child.pid = ++fakePids;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = { on: () => {}, end: () => {} };
  child.kill = () => {};
  setImmediate(() => {
    child.stdout.emit("data", Buffer.from(JSON.stringify(output)));
    child.emit("close", 0, null);
  });
  return child;
}

/** The wall, the seccomp program, the plan and the child, stubbed: only the option bag is under test. */
function runnerSeam(over = {}) {
  return {
    probe: () => ({ ok: true, pidns: true, bwrap: "/usr/bin/bwrap" }),
    seccompSupported: () => true,
    buildSeccompProgram: () => Buffer.from([0x20, 0x00, 0x00, 0x00]),
    buildPlan: () => ({ args: [], env: {} }),
    spawn: () => fakeChild({ items: [] }),
    prlimit: "/usr/bin/prlimit",
    ...over,
  };
}

/** A relay stub that records the option bag it was built with. */
function recordingRelay(seen) {
  return (opts) => {
    seen.push(opts);
    return { socketPath: join(opts.dir, "relay.sock"), ready: Promise.resolve(), close: () => {} };
  };
}

test("a caller's relayOptions and testSeams never reach the runner through runCustomStepForReport", async () => {
  const db = await freshDb();
  const { reportId } = await approvedFixture(db);
  const seen = [];
  let relayOptionsSeen = null;
  const seam = deps({
    ensureEnv: async ({ crowHome }) => ({ ok: true, dir: join(crowHome, "env"), hash: "e".repeat(64), cacheDir: join(crowHome, "cache"), built: false }),
    runStep: runCustomStep,
    relayOptions: {
      _connectOverride: () => ({ host: "127.0.0.1", port: 1 }),
      lookup: async () => [{ address: "93.184.216.34", family: 4 }],
      egressAllow: ["evil.example.com"],
      inject: [{ host: "evil.example.com", header: "Authorization", pathPrefixes: ["/v1"], secret: () => "x" }],
    },
    testSeams: true,
    ...runnerSeam({ createRelay: recordingRelay(seen) }),
  });
  // A run that reached the relay at all proves the stub seam was not forwarded to the runner either.
  const result = await runCustomStepForReport(db, seam, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(seen.length, 1, "the relay was built once");
  relayOptionsSeen = seen[0];
  for (const name of ["_connectOverride", "relayOptions", "testSeams", "addon", "doorFilter", "lookup", "local"]) {
    assert.equal(relayOptionsSeen[name], undefined, name + " from the caller never reaches the relay");
  }
  assert.deepEqual(relayOptionsSeen.egressAllow, [], "the run's own egress list is the only one");
  assert.deepEqual(relayOptionsSeen.inject, [], "and its own credential rules");
});

test("the runner itself reads only lookup and local unless a test harness sets testSeams", async () => {
  const bundleDir = mkdtempSync(join(root, "opt-bundle-"));
  writeFileSync(join(bundleDir, "run.py"), "print('{}')\n");
  const owned = async () => [{ address: "93.184.216.34", family: 4 }];
  const seen = [];
  const result = await runCustomStep({
    reportId: "rpt-0123456789abcdef",
    stepKey: "fetch",
    input: {},
    state: null,
    params: {},
    deps: runnerSeam({
      language: "python",
      entry: "run.py",
      envDir: join(HOME, "env"),
      assetsDir: join(HOME, "assets"),
      bundleDir,
      createRelay: recordingRelay(seen),
      relayOptions: {
        lookup: owned,
        local: { v4: [], v6: [] },
        _connectOverride: () => ({ host: "127.0.0.1", port: 1 }),
        _injectUpstreamTls: { ca: "x" },
        addon: { id: "x" },
        doorFilter: false,
        egressAllow: ["evil.example.com"],
        inject: [],
      },
    }),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].lookup, owned, "lookup is carried");
  assert.deepEqual(seen[0].local, { v4: [], v6: [] }, "local is carried");
  for (const name of ["_connectOverride", "_injectUpstreamTls", "addon", "doorFilter"]) {
    assert.equal(seen[0][name], undefined, name + " is dropped");
  }
  assert.deepEqual(seen[0].egressAllow, [], "a caller's egress list is never the relay's");
  assert.deepEqual(seen[0].inject, [], "nor its credential rules");

  // The same bag WITH testSeams is a harness's, and reaches the relay as it was given.
  const harness = [];
  const second = await runCustomStep({
    reportId: "rpt-0123456789abcdef",
    stepKey: "fetch",
    input: {},
    state: null,
    params: {},
    deps: runnerSeam({
      language: "python",
      entry: "run.py",
      envDir: join(HOME, "env"),
      assetsDir: join(HOME, "assets"),
      bundleDir,
      testSeams: true,
      createRelay: recordingRelay(harness),
      relayOptions: { _connectOverride: () => ({ host: "127.0.0.1", port: 1 }) },
    }),
  });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(typeof harness[0]._connectOverride, "function", "a test harness keeps its seam");
});