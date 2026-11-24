/**
 * The boot CATCH-UP PIPELINES (servers/gateway/bundle-boot-catchups.js).
 *
 * Two passes run once per gateway boot after the add-ons settle: first-admin setup
 * (bundle-first-admin-catchup.js) and then the app's API token (bundle-api-token.js). A
 * token needs that add-on's admin, so within ONE add-on the order is fixed — but across
 * add-ons nothing depends on anything. Before the pipelines, both passes walked the whole
 * installed list one add-on at a time: the first-admin pass' recreate seam WAITS when that
 * add-on has a start/recreate in flight (up to 10 minutes), so ONE busy add-on held up every
 * other add-on's first-admin catch-up and then ALL token catch-ups.
 *
 * This file pins the per-add-on pipeline:
 *   - B's first-admin AND token catch-up both finish while A is still parked in its recreate
 *     seam (A's wait holds only A);
 *   - within one add-on the token step still runs after the first-admin step, after-step
 *     included (the order a token's sign-in depends on);
 *   - `onlyId` processes exactly the named entry in each runner, and nothing else;
 *   - the pipelines never open more than the concurrency cap at once.
 *
 * Every seam is injected: no database, no docker, no app, no gateway.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { runBootCatchUps, BOOT_CATCHUP_CONCURRENCY } = await import("../servers/gateway/bundle-boot-catchups.js");
const { runFirstAdminCatchUp } = await import("../servers/gateway/bundle-first-admin-catchup.js");
const { runApiTokenCatchUp } = await import("../servers/gateway/bundle-api-token.js");
const { FIRST_ADMIN_AUTO_PREFIX } = await import("../servers/gateway/bundle-first-admin.js");

const INSTALL = "2026-11-20T09:00:00.000Z";
const AT = "2026-11-20T10:00:00.000Z";

/** A manifest with a setup script, an API-token step, and (optionally) a recreating after-step. */
function manifestFor(id, { after = false } = {}) {
  const upper = id.toUpperCase();
  const secretEnv = `${upper}_ADMIN_PASSWORD`;
  const tokenEnv = `${upper}_API_TOKEN`;
  return {
    id,
    name: id,
    origin: "official",
    env_vars: [
      { name: "APP_URL", default: "http://127.0.0.1:8000" },
      { name: secretEnv, description: "the admin password", secret: true },
      // paperless-shaped: the app's own grammar, so the plan is usable as-is.
      { name: tokenEnv, description: "API token", secret: true, pattern: "^[a-f0-9]{40}$" },
      ...(after ? [{ name: `${upper}_SIGNUPS`, default: "true" }] : []),
    ],
    firstAdmin: {
      mode: "crow",
      via: "setup",
      setup: {
        script: "scripts/first-admin.sh",
        timeout_s: 30,
        ...(after ? { after: { env: { [`${upper}_SIGNUPS`]: "false" }, recreate: true } } : {}),
        token: { script: "scripts/api-token.sh", env: tokenEnv },
      },
      user: "admin",
      secretEnv,
    },
  };
}

/**
 * One add-on's seams, for BOTH runners. `order` is the sequence of steps this add-on went
 * through; `hold` (when given) is awaited INSIDE the recreate seam, exactly where a recreate
 * waiting on a start in flight waits in production.
 */
function addon(id, { after = false, hold = null } = {}) {
  const manifest = manifestFor(id, { after });
  const state = {
    installed: [{ id, installedAt: INSTALL }],
    settings: { [`${FIRST_ADMIN_AUTO_PREFIX}${id}`]: JSON.stringify({ install: INSTALL, result: "ok" }) },
    order: [],
    runs: { admin: 0, token: 0 },
    began: [],
    ended: [],
  };
  const common = {
    appBundles: () => "/reviewed",
    bundlesDir: () => "/installed",
    crowHome: () => "/home/crow",
    listInstalled: () => state.installed,
    getManifest: (bundleId) => (bundleId === id ? manifest : null),
    readSetting: (key) => (key in state.settings ? state.settings[key] : null),
    writeSetting: (key, value) => { state.settings[key] = value; },
    mcpTransport: () => "stdio",
    tryBegin: (bundleId) => { state.began.push(bundleId); return true; },
    end: (bundleId) => { state.ended.push(bundleId); },
  };
  const adminDeps = {
    ...common,
    // This install has no first-admin marker yet: the run under test is the one that makes
    // it (the token pass' own gate reads the seeded "ok" through tokenDeps).
    readSetting: (key) => (key.startsWith(FIRST_ADMIN_AUTO_PREFIX) ? null : (key in state.settings ? state.settings[key] : null)),
    setupDeps: () => ({}),
    hasAdminSaved: () => false,
    appRunning: () => true,
    runSetup: async (o) => {
      state.runs.admin += 1;
      state.order.push(`${id}:admin`);
      assert.equal(o.bundleId, id, "a run is always for this add-on");
      return { result: "ok", log: [] };
    },
    applyAfter: async (o) => {
      state.order.push(`${id}:after`);
      const recreated = await o.recreate(o.bundleId);
      return { ok: recreated.ok !== false, applied: true, outcome: "applied", line: 'after: "applied"', reason: null };
    },
    recreate: async (bundleId) => {
      state.order.push(`${bundleId}:recreate`);
      if (hold) { hold.arrive(); await hold.promise; }
      return { ok: true, recreated: true };
    },
    reconnect: async () => ({ ok: true }),
    reportAfterFailure: async () => null,
    reportChanged: async () => null,
    warn: () => {},
  };
  const tokenDeps = {
    ...common,
    tokenDeps: () => ({}),
    mcpValue: () => "",
    hasKeychainRow: () => false,
    runApiToken: async (o) => {
      state.runs.token += 1;
      state.order.push(`${id}:token`);
      assert.equal(o.bundleId, id, "a token run is always for this add-on");
      return { result: "ok", log: [] };
    },
    reconnect: async () => ({ ok: true }),
    notify: async () => null,
    now: () => Date.parse(AT),
  };
  return { id, state, adminDeps, tokenDeps };
}

/** A gate a test holds open: the recreate seam parks on it until the test releases it. */
function gate() {
  let release;
  const promise = new Promise((r) => { release = r; });
  let arrived;
  const started = new Promise((r) => { arrived = r; });
  return { promise, release, started, arrive: arrived };
}

function deferredSignal() {
  let fire;
  const promise = new Promise((r) => { fire = r; });
  return { promise, fire };
}

/** A timed guard so a stuck pipeline fails the test instead of hanging it. */
function within(promise, ms = 4000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`timed out after ${ms} ms`)), ms).unref()),
  ]);
}

const byId = (addons) => Object.fromEntries(addons.map((a) => [a.id, a]));

/** The pipeline wiring post-listen uses, with each add-on's own injected seams. */
function wiring(addons, extra = {}) {
  const map = byId(addons);
  return {
    listIds: () => addons.map((a) => a.id),
    firstAdmin: ({ onlyId }) => runFirstAdminCatchUp({ deps: map[onlyId].adminDeps, onlyId }),
    apiToken: ({ onlyId }) => runApiTokenCatchUp({ deps: map[onlyId].tokenDeps, onlyId }),
    log: () => {},
    warn: () => {},
    ...extra,
  };
}

// ── the wait holds only its own add-on ───────────────────────────────────────────

test("one add-on parked in its recreate seam does not hold any other add-on's catch-up", async () => {
  const held = gate();
  const alpha = addon("alpha", { after: true, hold: held });
  const bravo = addon("bravo");
  const bravoDone = deferredSignal();
  const bravoTokenDeps = bravo.tokenDeps;
  bravo.tokenDeps = {
    ...bravoTokenDeps,
    runApiToken: async (o) => {
      const answer = await bravoTokenDeps.runApiToken(o);
      bravoDone.fire();
      return answer;
    },
  };

  const run = runBootCatchUps({ ...wiring([alpha, bravo]), concurrency: 4 });

  // A is really parked where a busy add-on parks: inside its own recreate seam.
  await within(held.started);
  assert.deepEqual(alpha.state.order, ["alpha:admin", "alpha:after", "alpha:recreate"]);

  // B's whole pipeline — first-admin AND the token that depends on it — finished anyway.
  await within(bravoDone.promise);
  assert.deepEqual(bravo.state.order, ["bravo:admin", "bravo:token"], "B's admin, then B's token");
  assert.equal(bravo.state.runs.admin, 1);
  assert.equal(bravo.state.runs.token, 1);
  assert.deepEqual(alpha.state.order, ["alpha:admin", "alpha:after", "alpha:recreate"], "A is still waiting");
  assert.equal(alpha.state.runs.token, 0, "A's token has not run yet: its first-admin step is not done");

  // Releasing A lets only A finish; its token runs after its own after-step.
  held.release();
  const summary = await within(run);

  assert.deepEqual(alpha.state.order, ["alpha:admin", "alpha:after", "alpha:recreate", "alpha:token"]);
  assert.ok(
    alpha.state.order.indexOf("alpha:after") < alpha.state.order.indexOf("alpha:token"),
    "within one add-on the token step still runs after the first-admin step",
  );
  assert.deepEqual(summary.firstAdmin.map((r) => r.id).sort(), ["alpha", "bravo"]);
  assert.deepEqual(summary.apiToken.map((r) => r.id).sort(), ["alpha", "bravo"]);
});

test("a first-admin failure for one add-on never costs that add-on's token step or another add-on", async () => {
  const alpha = addon("alpha");
  const bravo = addon("bravo");
  const lines = { log: [], warn: [] };
  const wiring0 = wiring([alpha, bravo]);
  const summary = await runBootCatchUps({
    ...wiring0,
    // The pass itself blowing up (not just one bundle's catch): still only alpha's pipeline.
    firstAdmin: async ({ onlyId }) => {
      if (onlyId === "alpha") throw new Error("compose is on fire");
      return wiring0.firstAdmin({ onlyId });
    },
    log: (m) => lines.log.push(String(m)),
    warn: (m) => lines.warn.push(String(m)),
  });

  // alpha's first-admin step threw: that add-on's token step is still attempted (it has its
  // marker), and bravo is untouched.
  assert.deepEqual(alpha.state.order, ["alpha:token"]);
  assert.deepEqual(bravo.state.order, ["bravo:admin", "bravo:token"]);
  assert.ok(lines.warn.some((l) => l.startsWith("[first-admin] catch-up skipped:")), "the existing skipped warning, in its own format");
  assert.ok(lines.log.some((l) => l.startsWith("[api-token] catch-up:")), "the existing log line, in its own format");
  assert.equal(summary.firstAdmin.some((r) => r.id === "alpha"), false);
});

test("the settle gate is awaited before any pipeline, and a settled failure skips without throwing", async () => {
  const alpha = addon("alpha");
  let settledRan = false;
  const summary = await runBootCatchUps({
    ...wiring([alpha]),
    settled: async () => { settledRan = true; throw new Error("add-ons never settled"); },
  });
  assert.equal(settledRan, true);
  assert.deepEqual(alpha.state.order, [], "nothing ran");
  assert.deepEqual(summary, { firstAdmin: [], apiToken: [] });

  const ok = addon("charlie");
  await runBootCatchUps({ ...wiring([ok]), settled: async () => {} });
  assert.deepEqual(ok.state.order, ["charlie:admin", "charlie:token"]);
});

// ── onlyId: exactly the named entry ──────────────────────────────────────────────

test("onlyId processes exactly the named add-on in each runner, and nothing else", async () => {
  const alpha = addon("alpha", { after: true });
  const bravo = addon("bravo");

  // The runners see BOTH installed entries through these seams: onlyId is what narrows it.
  for (const a of [alpha, bravo]) {
    a.adminDeps.listInstalled = () => [alpha.state.installed[0], bravo.state.installed[0]];
    a.tokenDeps.listInstalled = () => [alpha.state.installed[0], bravo.state.installed[0]];
  }

  const admin = await runFirstAdminCatchUp({ deps: { ...alpha.adminDeps, getManifest: (id) => manifestFor(id) }, onlyId: "alpha" });
  assert.deepEqual(admin.ran, [{ id: "alpha", result: "ok" }], "one entry processed, its own answer");
  assert.equal(admin.checked, 1, "only the named entry was checked");
  assert.deepEqual(alpha.state.order.filter((s) => s === "alpha:admin"), ["alpha:admin"]);
  assert.deepEqual(bravo.state.order.filter((s) => s === "bravo:admin"), [], "bravo untouched");

  const token = await runApiTokenCatchUp({ deps: { ...bravo.tokenDeps, getManifest: (id) => manifestFor(id) }, onlyId: "bravo" });
  assert.deepEqual(token.ran, [{ id: "bravo", result: "ok" }]);
  assert.equal(token.checked, 1);
  assert.deepEqual(bravo.state.order.filter((s) => s === "bravo:token"), ["bravo:token"]);
  assert.deepEqual(alpha.state.order.filter((s) => s === "alpha:token"), [], "alpha untouched by a bravo-only run");

  // An id that is not installed processes nothing at all (and still answers the same shape).
  const none = await runApiTokenCatchUp({ deps: { ...bravo.tokenDeps, getManifest: (id) => manifestFor(id) }, onlyId: "charlie" });
  assert.deepEqual(none, { checked: 0, ran: [] });
});

// ── concurrency cap ─────────────────────────────────────────────────────────────

test("the pipelines never open more than the cap at once, and every add-on still gets its turn", async () => {
  const ids = ["a1", "a2", "a3", "a4", "a5", "a6", "a7"];
  let active = 0;
  let maxActive = 0;
  const finished = [];
  const step = async (id) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active -= 1;
    finished.push(id);
  };
  const summary = await runBootCatchUps({
    listIds: () => ids,
    firstAdmin: async ({ onlyId }) => { await step(onlyId); return { checked: 1, ran: [] }; },
    apiToken: async ({ onlyId }) => { await step(onlyId); return { checked: 1, ran: [] }; },
    concurrency: 3,
    log: () => {},
    warn: () => {},
  });
  assert.equal(maxActive, 3, "the cap is what runs at once, no more");
  assert.deepEqual(finished.sort(), [...ids, ...ids].sort(), "every add-on ran both steps");
  assert.deepEqual(summary.firstAdmin, []);
  assert.equal(BOOT_CATCHUP_CONCURRENCY >= 1 && BOOT_CATCHUP_CONCURRENCY <= 8, true, "a modest default cap");
});

// ── the boot wiring (static source match) ───────────────────────────────────────

// The pipelines are only useful if the listen path actually calls them, once, behind the
// settle gate, and only when auth is on. The old wiring walked the whole list twice there;
// these source assertions keep a refactor from quietly restoring it — or from dropping the
// `settled` seam so the catch-ups race the add-ons they are catching up.
test("boot wires the per-add-on catch-ups behind the settle gate", () => {
  const post = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "servers/gateway/boot/post-listen.js"),
    "utf8",
  );

  assert.match(
    post,
    /import\("\.\.\/bundle-boot-catchups\.js"\)[\s\S]{0,200}runBootCatchUps\(/,
    "post-listen imports bundle-boot-catchups.js and calls runBootCatchUps",
  );
  assert.equal((post.match(/runBootCatchUps\(/g) || []).length, 1, "runBootCatchUps is called exactly once on the listen path");
  assert.match(
    post,
    /runBootCatchUps\(\{[\s\S]{0,300}settled:[\s\S]{0,300}addonsSettled\(\)/,
    "the call passes a settled seam that awaits proxy.addonsSettled()",
  );
  assert.match(
    post,
    /if \(!noAuth\) \{\s*import\("\.\.\/bundle-boot-catchups\.js"\)/,
    "the catch-ups sit inside if (!noAuth) — a --no-auth gateway is nobody's dashboard",
  );
  assert.doesNotMatch(post, /runFirstAdminCatchUp\(/, "the old sequential first-admin wiring is gone");
  assert.doesNotMatch(post, /runApiTokenCatchUp\(/, "the old sequential token wiring is gone");
  assert.match(
    post,
    /runBootCatchUps\([\s\S]{0,600}\)\)\s*(\/\/[^\n]*\n\s*)*\.catch\(/,
    "fire-and-forget: the import chain ends in a .catch",
  );
});