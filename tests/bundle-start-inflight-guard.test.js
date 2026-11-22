/**
 * One start per bundle at a time — tests/bundle-start-inflight-guard.test.js
 *
 * Starting a bundle runs `docker compose up`, and that child only settles when the
 * process exits — a slow (or hung) build can be in flight for minutes. Two starts of the
 * SAME bundle that overlap run two `up`s against one compose project, which is how a
 * "restart" during a first start can tear down what the first one is still creating.
 *
 * The behaviour specified here (NOT implemented yet — every test in this file fails
 * until it is): `startBundleLocal` holds a module-level in-flight map keyed by bundle id.
 * While a start/restart for that id is in flight:
 *
 *   - a second `startBundleLocal` / `restartBundleInProcess` for the same id runs NO
 *     compose, and answers
 *     `{ ok:false, status:409, code:"already_running", error:"already_running",
 *        jobId:<the id of the in-flight run> }`;
 *   - the in-flight run's own success result carries that same `jobId`;
 *   - the HTTP route answers 409 with `{ error:"already_running",
 *     code:"already_running", job_id:<id> }`;
 *   - different ids still start in parallel;
 *   - the guard is released in a `finally` when the compose runner's promise settles —
 *     success, rejection or a throw — but NOT by a caller-side timeout (the browser
 *     add-on card bounds its wait at 15 minutes; the container is still being built).
 *
 * Nothing here reaches docker: `docker` is a stub that owns nothing, `docker compose
 * config` is stubbed to the model the shared safety check reads, and `docker compose up`
 * is a DEFERRED the test settles itself, so "in flight" is a state the test controls
 * rather than a race. The whole file runs against a scratch CROW_HOME.
 */
import { test, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import express from "express";

let home;
let bundlesDir;
let A; // servers/gateway/routes/bundles.js
let remedy; // servers/gateway/fix-it/remedies/restart-browser-addon.js
let setDeps;

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
  home = mkdtempSync(join(tmpdir(), "crowhome-inflight-"));
  // BEFORE any import: bundles-config resolves CROW_HOME/BUNDLES_DIR at load, and the
  // router built below opens crow.db under this instance's data dir.
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = join(home, "data");
  mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
  bundlesDir = join(home, "bundles");

  writeBundle("alpha");
  writeBundle("beta");
  writeBundle("browser");
  // A start that THROWS after the guard is taken: the compose path exists, but reading it
  // fails (EISDIR) — the only failure this path cannot express as a rejected compose run.
  mkdirSync(join(bundlesDir, "boom"), { recursive: true });
  writeFileSync(join(bundlesDir, "boom", "manifest.json"), JSON.stringify({
    id: "boom", name: "boom", version: "1.0.0", type: "bundle",
  }));
  mkdirSync(join(bundlesDir, "boom", "docker-compose.yml"), { recursive: true });

  writeFileSync(join(home, "installed.json"), JSON.stringify([
    { id: "alpha", type: "bundle", version: "1.0.0" },
    { id: "beta", type: "bundle", version: "1.0.0" },
    { id: "browser", type: "bundle", version: "1.0.0" },
    { id: "boom", type: "bundle", version: "1.0.0" },
  ]));

  A = await import("../servers/gateway/routes/bundles.js");
  remedy = await import("../servers/gateway/fix-it/remedies/restart-browser-addon.js");
  setDeps = remedy._setRestartDepsForTest;
});

after(() => {
  delete process.env.CROW_HOME;
  delete process.env.CROW_DATA_DIR;
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

afterEach(() => {
  // Whatever a failing assertion left behind: let every pending compose "exit", drop the
  // seams, and restore the remedy. A half-finished start then cannot leak into the next test.
  try { openCompose?.settleAll(); } catch { /* best effort */ }
  openCompose = null;
  setDeps?.(null);
  A._setComposeRunnerForTest(null);
  A._setComposeConfigRunnerForTest(null);
  A._setDockerRunnerForTest(null);
  A._setBindDriftRecheckForTest(null);
});

/**
 * The three stand-ins a start needs so no docker exists, plus a `docker compose up` the
 * test drives:
 *   - `docker` (ownership check + `compose config` project name): answers nothing, so
 *     nobody else owns the project;
 *   - `compose config` (the shared safety check's model): a busybox app;
 *   - `compose up`: records `{ args, cwd }` and returns a promise this test settles by hand.
 *
 * `nextCall()` resolves with the next recorded call (immediately if one is already
 * waiting), so a test can say "the run is now in flight" without sleeping.
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
      /** Settles when the runner's promise does (before the start's own continuation). */
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
  // No boot detectors in a unit test: the post-start recheck is a no-op, not a DB read.
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

/** Let the start's continuation (and its `finally`, which releases the guard) run. */
async function settleTick(call) {
  call.settle();
  await call.done;
  await new Promise((resolve) => setImmediate(resolve));
}

function assertAlreadyRunning(out, { what }) {
  assert.equal(out.ok, false, `${what}: a start while another start is in flight is refused`);
  assert.equal(out.status, 409, `${what}: refused with the route's conflict status`);
  assert.equal(out.code, "already_running", `${what}: refused with the already_running code`);
  assert.equal(out.error, "already_running", `${what}: and the already_running message`);
  assert.equal(typeof out.jobId, "string", `${what}: names the in-flight run's jobId`);
  assert.ok(out.jobId.length > 0, `${what}: the jobId is a real id, not an empty string`);
}

// ── 1. one start per bundle ────────────────────────────────────────────────

test("two concurrent starts of ONE bundle: compose runs once, the second answers 409 already_running with the first run's jobId", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const first = A.startBundleLocal("alpha");
    pending.push(first);
    const call = await within(compose.nextCall(), PATIENCE_MS, "alpha's first `compose up`");

    const second = await within(
      A.startBundleLocal("alpha"),
      PATIENCE_MS,
      "a second start of alpha to answer 409 already_running instead of running compose again",
    );
    assertAlreadyRunning(second, { what: "the second start" });
    assert.equal(compose.calls.length, 1, "only the first start ran compose");

    call.settle();
    const firstOut = await first;
    assert.equal(firstOut.ok, true);
    assert.equal(typeof firstOut.jobId, "string", "the run that did start reports its own jobId");
    assert.ok(firstOut.jobId.length > 0);
    assert.equal(firstOut.jobId, second.jobId, "the refusal named the run it collided with");
    assert.equal(compose.calls.length, 1);
    assert.deepEqual(call.args, ["up", "-d"]);
    assert.equal(call.cwd, join(bundlesDir, "alpha"));
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 2. different ids are independent ───────────────────────────────────────

test("two different bundles start in parallel: both run compose", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const alpha = A.startBundleLocal("alpha");
    const beta = A.startBundleLocal("beta");
    pending.push(alpha, beta);

    const alphaCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's `compose up`");
    const betaCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "beta's `compose up` (different ids are not serialized by one guard)",
    );
    assert.equal(compose.calls.length, 2, "one up per bundle, in flight together");
    assert.deepEqual(
      [alphaCall.cwd, betaCall.cwd].sort(),
      [join(bundlesDir, "alpha"), join(bundlesDir, "beta")].sort(),
    );

    alphaCall.settle();
    betaCall.settle();
    const [alphaOut, betaOut] = await Promise.all([alpha, beta]);
    assert.equal(alphaOut.ok, true);
    assert.equal(betaOut.ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 3. the guard is released when the compose runner settles ───────────────

test("after a successful start the guard is released: the next start runs compose again", async () => {
  const compose = installStubs();
  try {
    const first = A.startBundleLocal("alpha");
    const firstCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's first `compose up`");
    firstCall.settle();
    const firstOut = await first;
    assert.equal(firstOut.ok, true);

    const second = A.startBundleLocal("alpha");
    const secondCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after the first finished to run compose again (the guard must be released on success)",
    );
    assert.equal(compose.calls.length, 2);
    secondCall.settle();
    const secondOut = await second;
    assert.equal(secondOut.ok, true);
  } finally {
    compose.settleAll();
  }
});

test("after a failed start (compose up rejects) the guard is released: the next start runs compose again", async () => {
  const compose = installStubs();
  const pending = [];
  try {
    const failed = A.startBundleLocal("alpha");
    pending.push(failed);
    const failedCall = await within(compose.nextCall(), PATIENCE_MS, "alpha's failing `compose up`");

    // Held while the run is in flight, so the release below is a real release and not
    // the absence of a guard.
    const blocked = await within(
      A.startBundleLocal("alpha"),
      PATIENCE_MS,
      "a start during the failing run to answer 409 already_running",
    );
    assertAlreadyRunning(blocked, { what: "a start during the failing run" });
    assert.equal(compose.calls.length, 1);

    failedCall.fail();
    const failedOut = await failed;
    assert.equal(failedOut.ok, false);
    assert.equal(failedOut.status, 500);
    assert.equal(failedOut.code, "compose_failed");

    const retry = A.startBundleLocal("alpha");
    pending.push(retry);
    const retryCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after a rejected compose run to run compose again (the guard must be released on failure)",
    );
    assert.equal(compose.calls.length, 2);
    retryCall.settle();
    const retryOut = await retry;
    assert.equal(retryOut.ok, true);
  } finally {
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

test("after a start that THROWS the guard is released: the same bundle starts again instead of answering already_running", async () => {
  const compose = installStubs();
  const pending = [];
  // Declared here so `finally` can always open the gate, whatever assertion failed.
  let releaseConfig = () => {};
  try {
    // "boom" throws inside startBundleLocal's own try (reading the compose file fails),
    // which is the other exit the `finally` must cover: never a rejected compose promise.
    // The safety check is held open, so the throw happens INSIDE the guarded region and
    // the second call below cannot race the first to the guard.
    let signalConfig;
    const configGate = new Promise((resolve) => { releaseConfig = resolve; });
    const configCalled = new Promise((resolve) => { signalConfig = resolve; });
    A._setComposeConfigRunnerForTest(async (_args, { cwd }) => {
      signalConfig();
      await configGate;
      return { stdout: JSON.stringify({ name: basename(cwd), services: { app: { image: "busybox:1.36" } } }), stderr: "" };
    });

    const thrown = A.startBundleLocal("boom");
    pending.push(thrown);
    await within(configCalled, PATIENCE_MS, "boom's compose safety check (the start is now in flight)");

    const blocked = await within(
      A.startBundleLocal("boom"),
      PATIENCE_MS,
      "a start during the throwing run to answer 409 already_running",
    );
    assertAlreadyRunning(blocked, { what: "a start during the throwing run" });

    releaseConfig();
    const thrownOut = await thrown;
    assert.equal(thrownOut.ok, false);
    assert.equal(thrownOut.status, 500);
    assert.equal(thrownOut.code, "compose_failed");

    const again = await within(
      A.startBundleLocal("boom"),
      PATIENCE_MS,
      "a start after the throw to run its own checks again (the guard must be released)",
    );
    assert.equal(again.ok, false);
    assert.equal(again.status, 500, "the same failure, not a stale already_running");
    assert.notEqual(again.code, "already_running", "the throw released the guard");
    assert.equal(compose.calls.length, 0, "this path never reached compose at all");
  } finally {
    releaseConfig();
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 4. a caller-side timeout does NOT release the guard ───────────────────

test("the browser add-on card times out, but the run is still in flight: a start answers 409, and only the compose exit releases it", async () => {
  const compose = installStubs();
  const pending = [];
  const warns = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warns.push(args.map(String).join(" ")); };
  try {
    // The REAL restart path (no `startBundle` seam): the card calls
    // restartBundleInProcess("browser"); only the owner rule, the Chromium guard and the
    // wait bound are injected.
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }), timeoutMs: 20 });

    const card = await remedy.default({}, { db: null, item: null, req: {} });
    assert.deepEqual(card, { resolved: false }, "the card reports it did not wait any longer");
    assert.equal(warns.length, 1);
    assert.match(warns[0], /^\[fix-it\] browser add-on: the restart did not run \(timeout\)$/);

    // The card gave up, but its restart is still running `up`: the compose call is here
    // (whether it arrived just before or just after the bound) and it has NOT settled.
    const call = await within(compose.nextCall(), PATIENCE_MS, "the timed-out restart's `compose up`");
    assert.deepEqual(call.args, ["up", "-d", "--force-recreate"], "the card's restart, in the product's own flags");
    assert.equal(call.cwd, join(bundlesDir, "browser"));
    assert.equal(call.settled, false, "the compose child has not exited");

    const blocked = await within(
      A.startBundleLocal("browser"),
      PATIENCE_MS,
      "a start while the timed-out restart is still in flight to answer 409 already_running",
    );
    assertAlreadyRunning(blocked, { what: "a start during the timed-out restart" });
    assert.equal(compose.calls.length, 1, "a caller-side timeout must not release the guard");

    // The container build finally exits: now — and only now — the guard is released.
    await settleTick(call);

    const afterExit = A.startBundleLocal("browser");
    pending.push(afterExit);
    const afterExitCall = await within(
      compose.nextCall(),
      PATIENCE_MS,
      "a start after the timed-out restart's compose exited to run compose again",
    );
    assert.equal(compose.calls.length, 2);
    afterExitCall.settle();
    assert.equal((await afterExit).ok, true);
  } finally {
    console.warn = originalWarn;
    compose.settleAll();
    await Promise.allSettled(pending);
  }
});

// ── 5. the card path and the HTTP route share one guard ───────────────────

/**
 * The route is driven the way the router's own tests drive it: mounted in a bare express
 * app (the gateway adds auth/CSRF above it, not inside it) on a scratch home.
 */
async function withStartRoute(fn) {
  const app = express();
  app.use(express.json());
  app.use(A.default());
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const url = `http://127.0.0.1:${server.address().port}/bundles/api/start`;
  const post = (bundleId) => fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bundle_id: bundleId }),
  });
  try {
    return await fn({ post, url });
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("an in-process restart in flight makes the HTTP start route answer 409 already_running with the same job_id", async () => {
  const compose = installStubs();
  const pending = [];
  let request = null;
  try {
    const restart = A.restartBundleInProcess("alpha");
    pending.push(restart);
    const call = await within(compose.nextCall(), PATIENCE_MS, "the in-process restart's `compose up`");
    assert.deepEqual(call.args, ["up", "-d", "--force-recreate"]);

    await withStartRoute(async ({ post }) => {
      request = post("alpha");
      const res = await within(
        request,
        PATIENCE_MS,
        "the HTTP start route to answer 409 already_running while the card's restart is in flight",
      );
      const body = await res.json();

      assert.equal(res.status, 409, "the route's conflict status");
      assert.equal(body.error, "already_running");
      assert.equal(body.code, "already_running");
      assert.equal(typeof body.job_id, "string", "the body names the in-flight run");
      assert.ok(body.job_id.length > 0);
      assert.equal(compose.calls.length, 1, "the route ran no compose: it saw the card's run");

      call.settle();
      const restartOut = await restart;
      assert.equal(restartOut.ok, true);
      assert.equal(restartOut.jobId, body.job_id, "the route named the restart that held the guard");
    });
  } finally {
    compose.settleAll();
    await Promise.allSettled([...pending, ...(request ? [request] : [])]);
  }
});

test("a start in flight through the HTTP route makes an in-process restart answer 409, and only its compose exit frees the bundle", async () => {
  const compose = installStubs();
  const pending = [];
  let request = null;
  try {
    await withStartRoute(async ({ post }) => {
      request = post("alpha");
      pending.push(request);
      const call = await within(compose.nextCall(), PATIENCE_MS, "the route's `compose up`");
      assert.deepEqual(call.args, ["up", "-d"]);

      // Same bundle, same guard, no request: the Fix-it card's path must see the route's run.
      const restart = await within(
        A.restartBundleInProcess("alpha"),
        PATIENCE_MS,
        "an in-process restart to answer 409 already_running while the route's start is in flight",
      );
      assert.equal(restart.ok, false);
      assert.equal(restart.status, 409);
      assert.equal(restart.code, "already_running");
      assert.equal(restart.error, "already_running");
      assert.equal(typeof restart.jobId, "string");
      assert.ok(restart.jobId.length > 0);
      assert.equal(compose.calls.length, 1, "the restart ran no compose");

      call.settle();
      const res = await request;
      const body = await res.json();
      assert.equal(res.status, 200, JSON.stringify(body));
      assert.equal(body.ok, true);
    });
  } finally {
    compose.settleAll();
    await Promise.allSettled([...pending, ...(request ? [request] : [])]);
  }
});