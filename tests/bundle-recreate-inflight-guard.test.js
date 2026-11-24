/**
 * Recreates share the per-add-on in-flight guard — tests/bundle-recreate-inflight-guard.test.js
 *
 * `startBundleLocal` has always held a per-bundle in-flight entry, but
 * `recreateBundleGuarded` (`up -d --force-recreate`, the shared-storage re-apply and the
 * first-admin "after" step) ran OUTSIDE it. A recreate could therefore overlap a start of
 * the same add-on: two `up`s against one compose project, which is how a recreate tears
 * down what a start is still creating.
 *
 * What this file pins down:
 *
 *   - the guard is the SAME one: a start is refused while a recreate is in flight and a
 *     recreate is refused while a start is in flight, both naming the run in flight;
 *   - the recreate's default `onBusy` is "refuse"
 *     (`{ ok:false, code:"already_running", reason:"already_running", jobId }`, no compose);
 *   - `onBusy:"wait"` (the background callers) waits for the in-flight run's release, then
 *     re-runs the pre-claim checks once it owns the guard (a bundle can be uninstalled while
 *     it queues), then runs its own compose once — and gives up at `waitMs` with
 *     `{ ok:false, code:"already_running_timeout" }` and one warning naming the bundle;
 *   - a caller that passes `installStamp` (the boot first-admin catch-up) is bound to ONE
 *     install: an uninstall + reinstall during its wait answers `{ ok:false,
 *     code:"reinstalled" }` with no compose, and the guard is still released;
 *   - the guard is HELD while a run is in flight (a concurrent start/recreate is refused)
 *     and released on success, on a rejected compose run and on a throw;
 *   - different bundle ids stay independent;
 *   - each caller asks for the policy it needs, driven behaviourally rather than read out of
 *     the source: the shared-storage Apply route and the first-admin card REFUSE (owner
 *     clicks), the install job's after-step and the boot first-admin catch-up WAIT
 *     (background, no owner to press Restart).
 *
 * Nothing here reaches docker: `docker` is a stub that owns nothing, `docker compose
 * config` is stubbed to the model the shared safety check reads, and `docker compose up`
 * is a DEFERRED the test settles itself, so "in flight" is a state the test controls
 * rather than a race. The whole file runs against a scratch CROW_HOME.
 */
import { test, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import express from "express";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

let home;
let bundlesDir;
let appBundlesDir;
let A; // servers/gateway/routes/bundles.js
let catchup; // servers/gateway/bundle-first-admin-catchup.js

/** The compose control created by the current test (settled in afterEach, whatever happens). */
let openCompose = null;

/** How long a "this must NOT block" expectation may wait before the test calls it a failure. */
const PATIENCE_MS = 3000;

function writeBundle(id, { compose = `name: ${id}\nservices:\n  app:\n    image: busybox\n` } = {}) {
  const dir = join(bundlesDir, id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({
    id, name: id, version: "1.0.0", type: "bundle", docker: { composefile: "docker-compose.yml" },
  }));
  writeFileSync(join(dir, "docker-compose.yml"), compose);
  return dir;
}

before(async () => {
  home = mkdtempSync(join(tmpdir(), "crowhome-recreate-guard-"));
  // BEFORE any import: bundles-config resolves CROW_HOME/BUNDLES_DIR at load, and the
  // router built below opens crow.db under this instance's data dir.
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = join(home, "data");
  mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
  bundlesDir = join(home, "bundles");
  appBundlesDir = join(home, "app-bundles");
  mkdirSync(appBundlesDir, { recursive: true });

  writeBundle("alpha");
  writeBundle("beta");

  writeFileSync(join(home, "installed.json"), JSON.stringify([
    { id: "alpha", type: "bundle", version: "1.0.0" },
    { id: "beta", type: "bundle", version: "1.0.0" },
  ]));

  // The scratch dashboard DB: the card route's failed after-step rings the existing bell
  // (reportFirstAdminNotice), which wants its tables rather than a caught "no such table".
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: process.env.CROW_DATA_DIR },
    stdio: "pipe",
    cwd: REPO,
  });

  A = await import("../servers/gateway/routes/bundles.js");
  catchup = await import("../servers/gateway/bundle-first-admin-catchup.js");
  // The REVIEWED tree the card route and the install job read manifests/scripts from (the
  // repo's own `bundles/` in production). A fixture dir keeps these tests off the repo's.
  A._setAppBundlesForTest(appBundlesDir);
  A._setAppEnvPathForTest(join(home, "app.env"));
});

after(() => {
  delete process.env.CROW_HOME;
  delete process.env.CROW_DATA_DIR;
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

afterEach(async () => {
  // Whatever a failing assertion left behind: let every pending compose "exit", drop the
  // seams. A half-finished run then cannot leak into the next test.
  try { openCompose?.settleAll(); } catch { /* best effort */ }
  openCompose = null;
  A._setComposeRunnerForTest(null);
  A._setComposeConfigRunnerForTest(null);
  A._setDockerRunnerForTest(null);
  A._setBindDriftRecheckForTest(null);
  A._setFirstAdminSetupDepsForTest(null);
  A._setOwnerCheckForTest(null);
  // ...and let each settled run's continuation reach its own release.
  await new Promise((resolve) => setImmediate(resolve));
});

/**
 * The three stand-ins a recreate/start needs so no docker exists, plus a `docker compose up`
 * the test drives. Copied from tests/bundle-start-inflight-guard.test.js.
 */
function makeCompose() {
  const calls = [];
  const waiters = [];
  let claimed = 0;

  const runner = (args, opts) => {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
    const call = {
      args: [...(args || [])],
      cwd: opts?.cwd,
      settled: false,
      /** Settles when the runner's promise does (before the run's own continuation). */
      done: promise.then(() => {}, () => {}),
      settle(value = { stdout: "", stderr: "" }) {
        if (call.settled) return;
        call.settled = true;
        resolve(value);
      },
      fail(err = Object.assign(new Error("compose up failed"), { stderr: "port is already allocated" })) {
        if (call.settled) return;
        call.settled = true;
        reject(err);
      },
    };
    calls.push(call);
    const waiter = waiters.shift();
    if (waiter) waiter(call);
    return promise;
  };

  const nextCall = () => {
    if (claimed < calls.length) {
      const call = calls[claimed];
      claimed += 1;
      return Promise.resolve(call);
    }
    return new Promise((resolve) => {
      waiters.push((call) => { claimed += 1; resolve(call); });
    });
  };

  const settleAll = () => { for (const call of calls) call.settle(); };

  return { runner, calls, nextCall, settleAll };
}

/** Install the stand-ins (and the detector-recheck no-op) around one test. */
function installStubs(compose = makeCompose()) {
  openCompose = compose;
  A._setDockerRunnerForTest(async () => ({ stdout: "", stderr: "" }));
  A._setComposeConfigRunnerForTest(async (_args, { cwd }) => ({
    stdout: JSON.stringify({ name: basename(cwd), services: { app: { image: "busybox:1.36" } } }),
    stderr: "",
  }));
  A._setComposeRunnerForTest(compose.runner);
  A._setBindDriftRecheckForTest(() => {});
  return compose;
}

/** Await `promise`, failing with a readable assertion if it does not settle in `ms`. */
async function within(promise, ms, what) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new assert.AssertionError({ message: `waited ${ms}ms for ${what} — it did not happen` })),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Let queued continuations (claims, waits, `finally` releases) run. */
const tick = () => new Promise((resolve) => setImmediate(resolve));

/** Let the run's continuation (and its `finally`, which releases the guard) run. */
async function settleTick(call) {
  call.settle();
  await call.done;
  await tick();
}

function assertStartRefused(out, { what }) {
  assert.equal(out.ok, false, `${what}: refused`);
  assert.equal(out.status, 409, `${what}: refused with the route's conflict status`);
  assert.equal(out.code, "already_running", `${what}: refused with the already_running code`);
  assert.equal(out.error, "already_running", `${what}: and the already_running message`);
  assert.equal(typeof out.jobId, "string", `${what}: names the in-flight run's jobId`);
  assert.ok(out.jobId.length > 0, `${what}: the jobId is a real id`);
}

function assertRecreateRefused(out, { what }) {
  assert.equal(out.ok, false, `${what}: a recreate while a run is in flight is refused`);
  assert.equal(out.code, "already_running", `${what}: refused with the already_running code`);
  assert.equal(out.reason, "already_running", `${what}: and the already_running reason`);
  assert.equal(typeof out.jobId, "string", `${what}: names the in-flight run's jobId`);
  assert.ok(out.jobId.length > 0, `${what}: the jobId is a real id`);
}

/**
 * The compose call at index `n`, waiting for it to be recorded (the install job has several:
 * pull, first up, then the after-step's recreate).
 */
async function waitForCall(compose, n, what) {
  const deadline = Date.now() + PATIENCE_MS;
  while (compose.calls.length <= n) {
    if (Date.now() > deadline) {
      throw new assert.AssertionError({ message: `waited ${PATIENCE_MS}ms for ${what} — it did not happen (${compose.calls.length} compose calls)` });
    }
    await tick();
  }
  return compose.calls[n];
}

/** Poll `check` (real time) until it is true, failing after PATIENCE_MS. */
async function waitFor(check, what) {
  const deadline = Date.now() + PATIENCE_MS;
  while (!check()) {
    if (Date.now() > deadline) {
      throw new assert.AssertionError({ message: `waited ${PATIENCE_MS}ms for ${what} — it did not happen` });
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

// ── first-admin fixtures (the card route and the install job) ──────────────

const FIRST_ADMIN_SWITCH = "FX_ENABLE_REGISTRATION";
const FIRST_ADMIN_PASSPHRASE = "generated-Secret_1";

/** A crow/setup bundle whose after-step closes its own registration, then recreates once. */
function firstAdminManifest(id) {
  return {
    id,
    name: `${id} app`,
    version: "1.0.0",
    type: "bundle",
    origin: "official",
    docker: { composefile: "docker-compose.yml" },
    firstAdmin: {
      mode: "crow",
      via: "setup",
      setup: {
        script: "scripts/first-admin.sh",
        timeout_s: 30,
        after: { env: { [FIRST_ADMIN_SWITCH]: "false" }, recreate: true },
      },
      user: "admin",
      secretEnv: "FX_ADMIN_PASSWORD",
    },
    env_vars: [{ name: FIRST_ADMIN_SWITCH, default: "true" }],
  };
}

/** Seed the REVIEWED copy (app bundles), the installed copy, and the install record. */
function seedFirstAdminBundle(id) {
  const manifest = firstAdminManifest(id);
  const dir = join(appBundlesDir, id);
  mkdirSync(join(dir, "scripts"), { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  writeFileSync(join(dir, "docker-compose.yml"), `name: ${id}\nservices:\n  app:\n    image: busybox\n`);
  writeFileSync(join(dir, "scripts", "first-admin.sh"), "#!/usr/bin/env bash\nexit 0\n");
  writeBundle(id);
  const path = join(home, "installed.json");
  const current = JSON.parse(readFileSync(path, "utf8"));
  if (!current.find((e) => e && e.id === id)) {
    current.push({ id, type: "bundle", version: "1.0.0", installedAt: "2026-11-10T09:00:00.000Z" });
    writeFileSync(path, JSON.stringify(current, null, 2));
  }
  return manifest;
}

/** runFirstAdminSetup's seams: the script succeeds, the password is "saved", nothing else. */
function firstAdminSetupSeams() {
  return {
    runScript: async () => ({ stdout: "registered the account\n", stderr: "" }),
    openDb: () => ({ close() {} }),
    hasSaved: async () => false,
    ensureWriteKey: async () => ({ id: "k1" }),
    newSecret: () => FIRST_ADMIN_PASSPHRASE,
    save: async () => ({ id: 1 }),
    writeMarker: async () => true,
    applyMcpEnv: async () => false,
    requestReload: async () => {},
    readEnv: () => ({}),
    warn: () => {},
  };
}

/** The installed .env's values (null when the bundle has no .env yet). */
function installedEnv(id) {
  try {
    const text = readFileSync(join(bundlesDir, id, ".env"), "utf8");
    const values = {};
    for (const line of text.split("\n")) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
      if (m) values[m[1]] = m[2];
    }
    return values;
  } catch {
    return null;
  }
}

// ── 1. the default is to refuse ────────────────────────────────────────────

test("a recreate during a start is refused by default: no second compose, code already_running, the start's jobId", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const call = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");
    assert.deepEqual(call.args, ["up", "-d"]);

    const rec = A._recreateBundleGuardedForTest("alpha");
    pending.push(rec);
    const out = await within(rec, PATIENCE_MS, "the recreate to answer already_running instead of running compose");
    assertRecreateRefused(out, { what: "the recreate" });
    assert.equal(compose.calls.length, 1, "only the start ran compose");

    call.settle();
    const startOut = await start;
    assert.equal(startOut.ok, true);
    assert.equal(startOut.jobId, out.jobId, "the refusal named the run it collided with");
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 2. onBusy:"wait" waits for the in-flight run ───────────────────────────

test('onBusy:"wait": the recreate runs no compose until the start settles, then re-creates once', async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    const rec = A._recreateBundleGuardedForTest("alpha", { onBusy: "wait", waitMs: 5000 });
    pending.push(rec);
    await tick();
    await tick();
    assert.equal(compose.calls.length, 1, "the waiting recreate ran no compose while the start was in flight");

    // The start finishes: only now may the recreate's own compose run.
    await settleTick(startCall);
    assert.equal((await start).ok, true);

    const recCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "the waiting recreate's `compose up` after the start settled",
    );
    assert.deepEqual(recCall.args, ["up", "-d", "--force-recreate"]);
    assert.equal(recCall.cwd, join(bundlesDir, "alpha"));
    assert.equal(compose.calls.length, 2);

    recCall.settle();
    const out = await rec;
    assert.equal(out.ok, true);
    assert.equal(out.recreated, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 2b. a waiter re-checks the install once it owns the guard ───────────────

test("a bundle uninstalled while a waiting recreate queued: not_installed after the start settles, no compose", async () => {
  const compose = installStubs();
  const pending = [];
  const installedPath = join(home, "installed.json");
  // Restored whatever happens: every later test reads this file.
  const original = readFileSync(installedPath, "utf8");
  try {
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    const rec = A._recreateBundleGuardedForTest("alpha", { onBusy: "wait", waitMs: 5000 });
    pending.push(rec);
    await tick();
    await tick();
    assert.equal(compose.calls.length, 1, "the waiter ran no compose while the start was in flight");

    // The owner uninstalls alpha while the background recreate queues behind the start.
    const entries = JSON.parse(original).filter((e) => e && e.id !== "alpha");
    writeFileSync(installedPath, JSON.stringify(entries, null, 2));

    await settleTick(startCall);
    assert.equal((await start).ok, true, "the start in front of the waiter is untouched");

    const out = await within(rec, PATIENCE_MS, "the waiter to answer once its turn came");
    assert.equal(out.ok, false);
    assert.equal(out.code, "not_installed", "the stale request does not recreate what is no longer installed");
    assert.match(out.reason, /not installed/);
    assert.equal(compose.calls.length, 1, "the stale recreate ran no compose at all");
  } finally {
    writeFileSync(installedPath, original);
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 2c. a caller bound to ONE install refuses a reinstall during its wait ──

/** Rewrite alpha's installed entry with `stamp` (the caller restores the file itself). */
function writeAlphaStamp(original, stamp) {
  const installedPath = join(home, "installed.json");
  const entries = JSON.parse(original).map((e) => (e && e.id === "alpha" ? { ...e, installedAt: stamp } : e));
  writeFileSync(installedPath, JSON.stringify(entries, null, 2));
}

test("an add-on REINSTALLED while a waiting recreate queued: code reinstalled, no compose, the guard is free afterwards", async () => {
  const compose = installStubs();
  const pending = [];
  const installedPath = join(home, "installed.json");
  const original = readFileSync(installedPath, "utf8");
  const STAMP = "2026-11-10T09:00:00.000Z";
  const REINSTALLED = "2026-11-12T09:00:00.000Z";
  try {
    writeAlphaStamp(original, STAMP);

    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    const rec = A._recreateBundleGuardedForTest("alpha", { onBusy: "wait", waitMs: 5000, installStamp: STAMP });
    pending.push(rec);
    await tick();
    await tick();
    assert.equal(compose.calls.length, 1, "the waiter ran no compose while the start was in flight");

    // The owner uninstalls and reinstalls alpha while the background recreate queues: the same
    // bundle id, a NEW install stamp. The queued run belongs to the install that is gone.
    writeAlphaStamp(original, REINSTALLED);

    await settleTick(startCall);
    assert.equal((await start).ok, true, "the start in front of the waiter is untouched");

    const out = await within(rec, PATIENCE_MS, "the waiter to answer once its turn came");
    assert.equal(out.ok, false, "a run bound to the old install does not recreate the new one");
    assert.equal(out.code, "reinstalled");
    assert.match(out.reason, /reinstalled/);
    assert.equal(compose.calls.length, 1, "the refused recreate ran no compose at all");

    // The claim was released: an unbound recreate of the same (new) install runs compose.
    const again = A._recreateBundleGuardedForTest("alpha");
    pending.push(again);
    const againCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a recreate after the refusal (the guard must be free)",
    );
    assert.deepEqual(againCall.args, ["up", "-d", "--force-recreate"]);
    againCall.settle();
    assert.equal((await again).ok, true);
  } finally {
    writeFileSync(installedPath, original);
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("the same wait with the stamp UNCHANGED still recreates (the check is the install, not the waiting)", async () => {
  const compose = installStubs();
  const pending = [];
  const installedPath = join(home, "installed.json");
  const original = readFileSync(installedPath, "utf8");
  const STAMP = "2026-11-10T09:00:00.000Z";
  try {
    writeAlphaStamp(original, STAMP);

    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    const rec = A._recreateBundleGuardedForTest("alpha", { onBusy: "wait", waitMs: 5000, installStamp: STAMP });
    pending.push(rec);
    await tick();
    await tick();
    assert.equal(compose.calls.length, 1, "the waiter ran no compose while the start was in flight");

    await settleTick(startCall);
    assert.equal((await start).ok, true);

    const recCall = await within(compose.nextCall(), PATIENCE_MS, "the waiting recreate's own `compose up`");
    assert.deepEqual(recCall.args, ["up", "-d", "--force-recreate"]);
    recCall.settle();
    const out = await rec;
    assert.equal(out.ok, true, "the same install is still there: the recreate goes ahead");
    assert.equal(out.recreated, true);
  } finally {
    writeFileSync(installedPath, original);
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 3. the wait is bounded ────────────────────────────────────────────────

test("onBusy:\"wait\" gives up at waitMs: already_running_timeout, no compose, one warning naming the bundle", async () => {
  const compose = installStubs();
  const pending = [];
  const warns = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warns.push(args.map(String).join(" ")); };
  try {
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    const out = await within(
      A._recreateBundleGuardedForTest("alpha", { onBusy: "wait", waitMs: 30 }),
      PATIENCE_MS,
      "the waiting recreate to give up at its own waitMs",
    );
    assert.equal(out.ok, false);
    assert.equal(out.code, "already_running_timeout");
    assert.match(out.reason, /still running after/);
    assert.equal(compose.calls.length, 1, "a timed-out recreate never ran compose");
    assert.equal(warns.length, 1, "exactly one clear warning");
    assert.match(warns[0], /alpha/, "the warning names the bundle");
    assert.match(warns[0], /still running after/, "and says what it was waiting for");

    // The start is untouched by the give-up, and the guard is still the start's.
    const blocked = await within(
      A._recreateBundleGuardedForTest("alpha"),
      PATIENCE_MS,
      "a later recreate to still see the start in flight",
    );
    assertRecreateRefused(blocked, { what: "a recreate after the give-up" });

    startCall.settle();
    assert.equal((await start).ok, true);
  } finally {
    console.warn = originalWarn;
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 4. a start is refused while a recreate is in flight ────────────────────

test("a start during a recreate answers 409 already_running with the recreate's jobId, through the HTTP route", async () => {
  const compose = installStubs();
  const pending = [];
  let request = null;
  try {
    const rec = A._recreateBundleGuardedForTest("alpha");
    pending.push(rec);
    const call = await within(compose.nextCall(), PATIENCE_MS, "the recreate's `compose up`");
    assert.deepEqual(call.args, ["up", "-d", "--force-recreate"]);

    // In process first: the refusal names the recreate.
    const blocked = await within(
      A.startBundleLocal("alpha"),
      PATIENCE_MS,
      "a start to answer 409 already_running while the recreate is in flight",
    );
    assertStartRefused(blocked, { what: "the in-process start" });

    await withStartRoute(async ({ post }) => {
      request = post("alpha");
      const res = await within(
        request,
        PATIENCE_MS,
        "the HTTP start route to answer while the recreate is in flight",
      );
      const body = await res.json();
      assert.equal(res.status, 409, JSON.stringify(body));
      assert.equal(body.error, "already_running");
      assert.equal(body.code, "already_running");
      assert.equal(body.job_id, blocked.jobId, "the route and the in-process start name the same run");
      assert.equal(compose.calls.length, 1, "neither start ran compose");
    });

    call.settle();
    assert.equal((await rec).ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled([...pending, ...(request ? [request] : [])]);
  }
});

// ── 5. the guard is released on success, rejection and throw ───────────────

test("a successful recreate HOLDS the guard while it is in flight and releases it after: a following start runs compose", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const rec = A._recreateBundleGuardedForTest("alpha");
    pending.push(rec);
    const recCall = await within(compose.nextCall(), PATIENCE_MS, "the recreate's `compose up`");

    // While it is in flight the guard is genuinely held: both a recreate and a start of the
    // same add-on are refused, and neither runs compose. (Without the guard both would run,
    // so this is what the test would fail on.)
    const blockedRecreate = await within(
      A._recreateBundleGuardedForTest("alpha"),
      PATIENCE_MS,
      "a concurrent recreate to answer already_running",
    );
    assertRecreateRefused(blockedRecreate, { what: "a recreate during the successful recreate" });
    const blockedStart = await within(
      A.startBundleLocal("alpha"),
      PATIENCE_MS,
      "a concurrent start to answer already_running",
    );
    assertStartRefused(blockedStart, { what: "a start during the recreate" });
    assert.equal(blockedStart.jobId, blockedRecreate.jobId, "both refusals name the one run in flight");
    assert.equal(compose.calls.length, 1, "neither concurrent run reached compose");

    recCall.settle();
    assert.equal((await rec).ok, true);

    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after the recreate finished (the guard must be released on success)",
    );
    assert.deepEqual(startCall.args, ["up", "-d"]);
    assert.equal(compose.calls.length, 2, "the released start is a new compose run, not the recreate's");
    startCall.settle();
    assert.equal((await start).ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("after a failed recreate (compose up rejects) the guard is released: a following start runs compose", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const failed = A._recreateBundleGuardedForTest("alpha");
    pending.push(failed);
    const failedCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's failing recreate `compose up`");

    const blocked = await within(
      A._recreateBundleGuardedForTest("alpha"),
      PATIENCE_MS,
      "a recreate during the failing run to answer already_running",
    );
    assertRecreateRefused(blocked, { what: "a recreate during the failing run" });

    failedCall.fail();
    const failedOut = await failed;
    assert.equal(failedOut.ok, false);
    assert.equal(failedOut.code, "compose_failed");

    // The release is explicit: a start right after the rejection runs its OWN compose.
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after the rejected recreate (the guard must be released on failure)",
    );
    assert.deepEqual(startCall.args, ["up", "-d"]);
    assert.equal(compose.calls.length, 2, "the released start ran a compose of its own");
    startCall.settle();
    assert.equal((await start).ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("a recreate that THROWS holds the guard while it is in flight, reports compose_failed and releases", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    // Defer ONE `compose config` call (the safety check the recreate runs before its `up`), so
    // the run is observably IN FLIGHT when the compose runner later throws synchronously. Every
    // later run (the start below) gets the ordinary stubs.
    let releaseConfig;
    const configGate = new Promise((resolve) => { releaseConfig = resolve; });
    let configCalls = 0;
    A._setComposeConfigRunnerForTest(async (_args, { cwd }) => {
      configCalls += 1;
      if (configCalls === 1) await configGate;
      return { stdout: JSON.stringify({ name: basename(cwd), services: { app: { image: "busybox:1.36" } } }), stderr: "" };
    });
    // A runner that throws synchronously once: the throw happens INSIDE the guarded region,
    // so the recreate's own catch turns it into compose_failed and its `finally` must release
    // the guard.
    let calls = 0;
    A._setComposeRunnerForTest((args, opts) => {
      calls += 1;
      if (calls === 1) throw new Error("docker went away");
      return compose.runner(args, opts);
    });

    const thrown = A._recreateBundleGuardedForTest("alpha");
    pending.push(thrown);
    await waitFor(() => configCalls === 1, "the throwing recreate to reach its compose safety check");

    // In flight: the guard is held, so a concurrent start is refused and runs nothing.
    const blocked = await within(
      A.startBundleLocal("alpha"),
      PATIENCE_MS,
      "a start during the throwing recreate to answer already_running",
    );
    assertStartRefused(blocked, { what: "a start during the throwing recreate" });
    assert.equal(compose.calls.length, 0, "the throwing recreate never got as far as a recorded compose call");

    releaseConfig();
    const out = await within(thrown, PATIENCE_MS, "the throwing recreate to answer");
    assert.equal(out.ok, false);
    assert.equal(out.code, "compose_failed");
    assert.match(out.reason, /docker went away/);

    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after the throw to run its own compose (the guard must be released)",
    );
    assert.deepEqual(startCall.args, ["up", "-d"]);
    assert.equal(compose.calls.length, 1, "the released start ran a compose of its own");
    startCall.settle();
    assert.equal((await start).ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 6. different bundle ids are independent ────────────────────────────────

test("a recreate of one bundle does not block a start of another: both run compose together", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const rec = A._recreateBundleGuardedForTest("alpha");
    const start = A.startBundleLocal("beta");
    pending.push(rec, start);

    const recCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's recreate `compose up`");
    const startCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "beta's start `compose up` (different ids are not serialized by one guard)",
    );
    assert.deepEqual(
      [recCall.cwd, startCall.cwd].sort(),
      [join(bundlesDir, "alpha"), join(bundlesDir, "beta")].sort(),
    );
    assert.equal(compose.calls.length, 2);

    recCall.settle();
    startCall.settle();
    assert.equal((await rec).ok, true);
    assert.equal((await start).ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 7. the shared-storage Apply route refuses, like the Start route ────────

/**
 * The route is driven the way the router's own tests drive it: mounted in a bare express app
 * (the gateway adds auth/CSRF above it, not inside it) on a scratch home.
 */
async function withRouter(fn) {
  const app = express();
  app.use(express.json());
  app.use(A.default());
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, body) => fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  try {
    return await fn({ post, base });
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function withStartRoute(fn) {
  return withRouter(({ post }) => fn({
    post: (bundleId) => post("/bundles/api/start", { bundle_id: bundleId }),
    url: "/bundles/api/start",
  }));
}

test("shared-storage Apply during a start answers 409 {error, code: already_running, job_id} exactly like Start", async () => {
  const compose = installStubs();
  const pending = [];
  let request = null;
  try {
    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const call = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    await withRouter(async ({ post }) => {
      request = post("/bundles/api/shared-storage/apply/alpha");
      const res = await within(
        request,
        PATIENCE_MS,
        "the Apply route to answer 409 already_running while a start is in flight",
      );
      const body = await res.json();
      assert.equal(res.status, 409, JSON.stringify(body));
      assert.equal(body.error, "already_running");
      assert.equal(body.code, "already_running");
      assert.equal(typeof body.job_id, "string");
      assert.ok(body.job_id.length > 0);
      assert.equal(compose.calls.length, 1, "Apply ran no compose and never touched the .env");
    });

    // The refused route did not write the managed block: the bundle still has no .env.
    assert.throws(() => readFileSync(join(bundlesDir, "alpha", ".env")), /ENOENT/);

    call.settle();
    const startOut = await start;
    assert.equal(startOut.ok, true);
    assert.equal(typeof startOut.jobId, "string");
  } finally {
    compose.settleAll();
    await Promise.allSettled([...pending, ...(request ? [request] : [])]);
  }
});

// ── 8. each caller asks for the policy it needs ────────────────────────────

test('the boot first-admin catch-up seam passes onBusy:"wait": it waits for an in-flight start instead of skipping the after-step', async () => {
  const compose = installStubs();
  const pending = [];
  let real = null;
  try {
    real = await catchup.firstAdminCatchUpDeps();
    const recreate = real.recreate;
    assert.equal(typeof recreate, "function", "the catch-up has a real recreate seam");

    const start = A.startBundleLocal("alpha");
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's start `compose up`");

    let settled = false;
    const after = recreate("alpha").then((out) => { settled = true; return out; });
    pending.push(after);
    await tick();
    await tick();
    assert.equal(settled, false, 'the catch-up seam WAITS: it did not skip the after-step while a start ran');
    assert.equal(compose.calls.length, 1, "no compose while the start is in flight");

    await settleTick(startCall);
    const recCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "the catch-up's own recreate after the start settled",
    );
    assert.deepEqual(recCall.args, ["up", "-d", "--force-recreate"]);
    recCall.settle();
    const out = await after;
    assert.equal(out.ok, true);
    assert.equal(out.recreated, true);
  } finally {
    await real?.close?.();
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("the first-admin card route REFUSES while a start is in flight: it reports the refusal and runs no compose", async () => {
  const id = "fx-card";
  const compose = installStubs();
  seedFirstAdminBundle(id);
  A._setFirstAdminSetupDepsForTest(firstAdminSetupSeams());
  A._setOwnerCheckForTest(() => true);
  const pending = [];
  try {
    const start = A.startBundleLocal(id);
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, `${id}'s start \`compose up\``);

    let body = null;
    await withRouter(async ({ post }) => {
      const response = await within(
        post("/bundles/api/first-admin-auto", { bundle_id: id }),
        PATIENCE_MS,
        "the first-admin card route to answer while the start is in flight",
      );
      body = await response.json();
      assert.equal(response.status, 200, JSON.stringify(body));
    });

    assert.equal(body.result, "ok", "the setup itself succeeded");
    assert.equal(body.after, "recreate-failed: already_running", "the card's recreate was REFUSED, not queued");
    assert.match(body.afterFailure ?? "", /press Restart/, "and the card says to press Restart");
    assert.equal(installedEnv(id)?.[FIRST_ADMIN_SWITCH], "false", "the value is on disk, so Restart applies it");
    assert.equal(compose.calls.length, 1, "the card's recreate ran no compose");

    startCall.settle();
    assert.equal((await start).ok, true, "the start was never disturbed");
  } finally {
    A._setFirstAdminSetupDepsForTest(null);
    A._setOwnerCheckForTest(null);
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("the install job's after-step WAITS for an in-flight start: it recreates once the start settles", async () => {
  const id = "fx-install";
  const compose = installStubs();
  const manifest = seedFirstAdminBundle(id);
  A._setFirstAdminSetupDepsForTest(firstAdminSetupSeams());
  const pending = [];
  let job = null;
  try {
    const start = A.startBundleLocal(id);
    pending.push(start);
    const startCall = await within(compose.nextCall(), PATIENCE_MS, `${id}'s start \`compose up\``);
    assert.deepEqual(startCall.args, ["up", "-d"]);

    job = A._createJobForTest(id, "install");
    const installing = A.runInstallJob(id, {}, { job, installedSnapshot: [], consentVerified: false, manifest });
    pending.push(installing);

    // The install's own compose calls, which are NOT guarded (they precede any start): pull,
    // then the first `up`. Settling them lets the install reach its after-step.
    const pullCall = await waitForCall(compose, 1, "the install's `compose pull`");
    assert.deepEqual(pullCall.args, ["pull"]);
    pullCall.settle();
    const installUp = await waitForCall(compose, 2, "the install's first `compose up`");
    assert.deepEqual(installUp.args, ["up", "-d"]);
    installUp.settle();

    // The after-step's value is written BEFORE its recreate: once it is on disk, the recreate
    // is queued behind the start. WAIT means no compose of its own until the start settles.
    await waitFor(() => installedEnv(id)?.[FIRST_ADMIN_SWITCH] === "false", "the install's after-step to write the .env value");
    await tick();
    await tick();
    assert.equal(compose.calls.length, 3, "the waiting after-step ran no compose while the start was in flight");
    assert.equal(/^after:/m.test(job.log.join("\n")), false, "the step has not finished yet");

    // The start finishes: only now may the install's after-step recreate.
    await settleTick(startCall);
    assert.equal((await start).ok, true);

    const recCall = await waitForCall(compose, 3, "the after-step's recreate after the start settled");
    assert.deepEqual(recCall.args, ["up", "-d", "--force-recreate"]);
    recCall.settle();

    const out = await within(installing, PATIENCE_MS, "the install to finish");
    assert.equal(out.ok, true, out.reason);
    const log = job.log.join("\n");
    assert.match(log, /^after: "applied"$/m, "the after-step finished instead of being dropped");
    assert.equal(/recreate-failed/.test(log), false, "nothing was refused (that is the REFUSE policy)");
    assert.equal(compose.calls.filter((c) => c.args.includes("--force-recreate")).length, 1, "exactly one recreate");
  } finally {
    A._setFirstAdminSetupDepsForTest(null);
    if (job) { try { A._finishJobForTest(job, "complete"); } catch { /* never started */ } }
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 9. the Apply button shows the existing sentence, not a new one ─────────

// Kept as a source assertion: the sentence is built in the dashboard's browser-side section,
// and this suite has no browser/jsdom harness to click through. It still pins the two things
// that regress: the branch is on the CODE, and the sentence is the existing i18n key.

test("the Shared Storage Apply button turns 409 already_running into the existing already-restarting sentence", () => {
  const section = readFileSync(
    join(REPO, "servers/gateway/dashboard/settings/sections/shared-storage.js"),
    "utf8",
  );
  // It branches on the CODE (not the free-text error) and reuses the approved key, so
  // "Apply (failed)" never appears for a run that is simply still going.
  assert.match(section, /d\.code === 'already_running'/);
  assert.match(section, /tJs\("fixit\.flash\.alreadyRestarting", lang\)/);
  assert.match(section, /async render\(\{ db, lang \}\)/, "the sentence needs the viewer's language");
  assert.ok(
    !section.includes("already restarting. Give it"),
    "no hardcoded copy in this file: the string lives in i18n",
  );
});