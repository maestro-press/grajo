// PR 3c: no wall, no step. On a computer without the sandbox (bubblewrap, an unprivileged user
// namespace, a PID namespace, a seccomp filter) a custom step is REFUSED: nothing is spawned, no relay
// is opened, and the answer is the one sentence. There is no unwalled tier here to fall back to.
//
// The owner hears about it once a day and not once a run: the notice is deduped by a `report_state` row
// keyed by the day.
//
// Always runs: the wall probe is stubbed, so this file needs no bubblewrap. The DB part is a scratch
// crow.db (init-db'd, copied per test) with real report rows and a real approval.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "report-steps-no-wall-"));
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
const { approveStep, proposeStep } = await import("../servers/gateway/reports/steps.js");
const { runCustomStepForReport } = await import("../servers/gateway/reports/custom-step.js");
const { ensureEnv } = await import("../scripts/report-steps/env.mjs");
const { NO_WALL_TEXT, NO_WALL_CODE, probeWall, runCustomStep } = await import("../scripts/report-steps/runner.mjs");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 31);
const T0 = 1_700_000_000_000;
const DAY = "2026-01-02";

const dirs = [];
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
  return { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME, ...over };
}

/* ---------------------------------------------------------------- the wall probe */

test("probeWall answers no for no bwrap, for no PID namespace, and for no seccomp filter", () => {
  assert.deepEqual(probeWall({ probe: () => ({ ok: false, reason: "bubblewrap (bwrap) is not installed" }) }), {
    ok: false, reason: "bubblewrap (bwrap) is not installed",
  });
  assert.equal(probeWall({ probe: () => ({ ok: true, pidns: false, pidnsReason: "no pid ns", bwrap: "/usr/bin/bwrap" }) }).ok, false,
    "a host that cannot make a PID namespace cannot hold a step");
  assert.equal(probeWall({
    probe: () => ({ ok: true, pidns: true, bwrap: "/usr/bin/bwrap" }),
    seccompSupported: () => false,
  }).ok, false, "no filter for this architecture is no wall");
  assert.equal(probeWall({ probe: () => { throw new Error("probe exploded"); } }).ok, false, "a throwing probe is a no");
  assert.deepEqual(probeWall({
    probe: () => ({ ok: true, pidns: true, bwrap: "/usr/bin/bwrap" }),
    seccompSupported: () => true,
  }), { ok: true, bwrap: "/usr/bin/bwrap" });
});

/* ------------------------------------------------------ the runner refuses, and spawns nothing */

test("no prlimit means no memory cap, so the runner refuses with the no-wall line and spawns nothing", async () => {
  // The address-space cap is part of the wall: without the binary there is no cap at all.
  let spawns = 0;
  let relays = 0;
  const result = await runCustomStep({
    reportId: "rpt-0123456789abcdef",
    stepKey: "fetch",
    input: {},
    state: null,
    params: {},
    deps: {
      probe: () => ({ ok: true, pidns: true, bwrap: "/usr/bin/bwrap" }),
      seccompSupported: () => true,
      buildSeccompProgram: () => Buffer.from([0x20, 0x00, 0x00, 0x00]),
      bwrap: "/usr/bin/bwrap",
      prlimit: null,
      spawn: () => { spawns += 1; throw new Error("a step was spawned without a memory cap"); },
      createRelay: () => { relays += 1; throw new Error("a relay was opened for a refused step"); },
      language: "python",
      entry: "run.py",
      envDir: join(HOME, "reports", "rpt-0123456789abcdef", "env", "python"),
      assetsDir: join(HOME, "reports", "rpt-0123456789abcdef", "assets"),
    },
  });
  assert.deepEqual(result, { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT });
  assert.equal(spawns, 0, "nothing was spawned");
  assert.equal(relays, 0, "no relay was opened");
});

test("runner fails closed without bwrap: no spawn, no relay, and the honest line", async () => {
  let spawns = 0;
  let relays = 0;
  const result = await runCustomStep({
    reportId: "rpt-0123456789abcdef",
    stepKey: "fetch",
    input: {},
    state: null,
    params: {},
    deps: {
      probe: () => ({ ok: false, reason: "bubblewrap (bwrap) is not installed" }),
      spawn: () => { spawns += 1; throw new Error("a spawn happened"); },
      createRelay: () => { relays += 1; throw new Error("a relay happened"); },
      language: "python",
      entry: "run.py",
      envDir: join(HOME, "reports", "rpt-0123456789abcdef", "env", "python"),
      assetsDir: join(HOME, "reports", "rpt-0123456789abcdef", "assets"),
    },
  });
  assert.deepEqual(result, { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT });
  assert.equal(spawns, 0, "nothing was spawned");
  assert.equal(relays, 0, "no relay was opened");
});

test("a build is refused too: no sandbox means nothing is installed unwalled", async () => {
  const outcome = await ensureEnv({
    reportId: "rpt-0123456789abcdef",
    language: "python",
    requirements: "jinja2==3.1.4\n",
    crowHome: HOME,
    deps: {
      // A uv that resolves, so the refusal is the wall's and not uv's absence.
      resolveUv: () => "/usr/bin/uv",
      probe: () => ({ ok: false, reason: "bubblewrap (bwrap) is not installed" }),
      spawn: () => { throw new Error("a build was spawned without a wall"); },
    },
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.code, "no_wall");
});

/* --------------------------------------------------- the owner's notice, once per report per day */

test("a no-wall step notifies the owner once for the report's day, not once per run", async () => {
  const db = await freshDb();
  const { id: reportId } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title: "Weekly listings" });
  const proposed = await proposeStep(db, deps(), {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: { "run.py": "print('{}')\n" },
    requirements: "jinja2==3.1.4\n",
    proposedBy: "owner",
  });
  await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: proposed.bundleHash, actor: OWNER,
  });
  const envDir = join(HOME, "reports", reportId, "env", "python");
  mkdirSync(envDir, { recursive: true });

  const notices = [];
  let runs = 0;
  const runDeps = deps({
    day: DAY,
    notifyOwner: (note) => { notices.push(note); },
    ensureEnv: async () => ({ ok: true, dir: envDir, hash: "a".repeat(64), cacheDir: join(HOME, "cache"), built: false }),
    runStep: async () => { runs += 1; return { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT }; },
  });

  const first = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.deepEqual(first, { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT });
  const second = await runCustomStepForReport(db, runDeps, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.equal(second.code, NO_WALL_CODE);
  assert.equal(runs, 2, "both runs reached the runner");
  assert.equal(notices.length, 1, "one notice for the day: " + JSON.stringify(notices));
  assert.equal(notices[0].title, NO_WALL_TEXT, "the notice is the plan's exact sentence");
  assert.equal(notices[0].body, null);
  assert.equal(notices[0].reportId, reportId);

  const { rows } = await db.execute({
    sql: "SELECT key FROM report_state WHERE report_id = ? ORDER BY key",
    args: [reportId],
  });
  assert.deepEqual(rows.map((row) => row.key), ["step_no_wall:" + DAY], "the dedupe is a state row keyed by the day");

  // The next day is a new notice; the same day stays quiet.
  const nextDay = { ...runDeps, day: "2026-01-03" };
  await runCustomStepForReport(db, nextDay, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.equal(notices.length, 2, "a new day is a new notice");
});

test("with no notifier nothing is recorded, so a wired notice later can still be sent", async () => {
  const db = await freshDb();
  const { id: reportId } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title: "Weekly listings" });
  const proposed = await proposeStep(db, deps(), {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: { "run.py": "print('{}')\n" },
    proposedBy: "owner",
  });
  await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: proposed.bundleHash, actor: OWNER,
  });
  const envDir = join(HOME, "reports", reportId, "env", "python");
  mkdirSync(envDir, { recursive: true });
  const bare = deps({
    day: DAY,
    ensureEnv: async () => ({ ok: true, dir: envDir, hash: "b".repeat(64), cacheDir: join(HOME, "cache"), built: false }),
    runStep: async () => ({ ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT }),
  });
  await runCustomStepForReport(db, bare, { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_state WHERE report_id = ?",
    args: [reportId],
  });
  assert.equal(Number(rows[0].n), 0, "a run with nowhere to notify claims nothing");

  const notices = [];
  await runCustomStepForReport(db, { ...bare, notifyOwner: (note) => notices.push(note) },
    { report: { id: reportId }, stepKey: "fetch", trigger: "manual" });
  assert.equal(notices.length, 1);
});

test("the no-wall sentence is the plan's, word for word", () => {
  assert.equal(NO_WALL_TEXT, "Custom steps can't run on this Crow (no sandbox available)");
  assert.equal(NO_WALL_CODE, "no_wall");
});