/**
 * The browser add-on restart remedy runs the route's local start IN PROCESS —
 * tests/fix-it-restart-browser-addon.test.js
 *
 * The card's action must run the SAME path the Extensions Restart button runs, and it
 * now calls it as code: `restartBundleInProcess("browser")` in routes/bundles.js, which
 * refuses a bundle hosted elsewhere and otherwise runs `startBundleLocal` with
 * `recreate: true` (ownership → consent + compose safety check → `up -d --build
 * --force-recreate` → the detectors' re-check).
 *
 * It must never make an HTTP request. The old implementation re-POSTed the owner's own
 * dashboard request to this gateway's own loopback listener with the forwarded Cookie and
 * CSRF token; since the session cookie became `__Host-crow_session` (HTTPS-only), that
 * plain-HTTP self-call carried the wrong cookie and the route answered 403/302 — it could
 * never restart anything. So every test here fails if `fetch` is called at all.
 *
 * The owner rule, the Chromium-downgrade guard and the restart itself are injected
 * (`_setRestartDepsForTest`); none of them reaches docker or the network. The last block
 * goes further and injects NO restart at all: the REAL `restartBundleInProcess` runs
 * against a temp CROW_HOME holding an installed browser bundle whose compose cannot be
 * read, with docker and `docker compose` replaced by stubs that throw — so the compose
 * safety check is what refuses, and `up` is never reached.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let remedy;
let BUNDLE_ID;
let RESTART_TIMEOUT_MS;
let setDeps;
let setDockerRunner;
let setComposeConfigRunner;
let setComposeRunner;
let OWNER_ONLY_FLASH;
let OWNER_ONLY_MESSAGE;
let home;

const OWNER = async () => true;
/** The Chromium-downgrade guard, allowed: these tests are about the restart path, not
 *  about which Chromium the rebuild installs (tests/fix-it-browser-chromium-guard.test.js
 *  is that). */
const GUARD_ALLOWED = async () => ({ blocked: false });

/** The dashboard request that clicked the button: an OWNER session over HTTPS, the only
 *  kind that carries a `__Host-` cookie. */
const ownerRequest = (cookie = "__Host-crow_session=abc123") => ({ headers: { cookie }, secure: true });

/**
 * An installed browser bundle in `crowHome`: the manifest and compose the real path
 * resolves, and a lock whose playwright-core 1.58.2 pins the Chromium a rebuild of this
 * image installs (145 — see browser-chromium-guard.js).
 */
function writeBrowserBundle(crowHome, { compose = "name: browser\nservices:\n  browser:\n    image: crow-browser:test\n" } = {}) {
  const dir = join(crowHome, "bundles", "browser");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id: "browser", version: "1.8.0", docker: { composefile: "docker-compose.yml" } }));
  writeFileSync(join(dir, "docker-compose.yml"), compose);
  writeFileSync(join(dir, "package-lock.json"), `${JSON.stringify({
    name: "crow-browser",
    lockfileVersion: 3,
    packages: {
      "": { name: "crow-browser", dependencies: { playwright: "^1.49.0" } },
      "node_modules/playwright": { version: "1.58.2", dependencies: { "playwright-core": "1.58.2" } },
      "node_modules/playwright-core": { version: "1.58.2" },
    },
  }, null, 2)}\n`);
  writeFileSync(join(crowHome, "installed.json"), JSON.stringify([{ id: "browser", type: "bundle", version: "1.8.0" }]));
}

before(async () => {
  home = mkdtempSync(join(tmpdir(), "crowhome-browserrestart-"));
  process.env.CROW_HOME = home;
  // The bundle must be on disk BEFORE the import: bundles-config reads CROW_HOME at load
  // time, and every path below (including routes/bundles.js's BUNDLES_DIR) comes from it.
  writeBrowserBundle(home);
  remedy = await import("../servers/gateway/fix-it/remedies/restart-browser-addon.js");
  const core = await import("../servers/gateway/bundle-core.js");
  // bundle-core's runner seams: `dockerRunner()` / `docker compose` are resolved per call,
  // so a stub set here is what the REAL guard and the REAL start path ask.
  setDockerRunner = core._setDockerRunnerForTest;
  setComposeConfigRunner = null; // resolved in the real-path test (routes/bundles.js)
  setComposeRunner = core._setComposeRunnerForTest;
  BUNDLE_ID = remedy.BUNDLE_ID;
  RESTART_TIMEOUT_MS = remedy.RESTART_TIMEOUT_MS;
  setDeps = remedy._setRestartDepsForTest;
  const restore = await import("../servers/gateway/fix-it/remedies/restore-bundle-compose.js");
  OWNER_ONLY_FLASH = restore.OWNER_ONLY_FLASH;
  OWNER_ONLY_MESSAGE = restore.OWNER_ONLY_MESSAGE;
});

after(() => {
  delete process.env.CROW_HOME;
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

beforeEach(() => setDeps(null));

/**
 * Run `fn` with `globalThis.fetch` replaced by a stub that records and refuses, so any HTTP
 * request the remedy makes is visible AND cannot reach a server. Restored in a finally.
 */
async function withoutFetch(fn) {
  const prevFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = (...args) => {
    calls.push(args);
    throw new Error("the remedy must not make an HTTP request");
  };
  try {
    const value = await fn();
    return { value, calls };
  } finally {
    globalThis.fetch = prevFetch;
  }
}

/** Collect console.warn for the duration of `fn`, and return both its result and the lines. */
async function captureWarn(fn) {
  const lines = [];
  const original = console.warn;
  console.warn = (...args) => { lines.push(args.map(String).join(" ")); };
  let value;
  try { value = await fn(); } finally { console.warn = original; }
  return { value, lines };
}

/** Run the remedy with the given seams (always restored), returning its result. */
async function run({ deps = {}, req = ownerRequest(), args = {} } = {}) {
  setDeps({ owner: OWNER, guard: GUARD_ALLOWED, ...deps });
  try {
    return await remedy.default(args, { db: null, item: null, req });
  } finally {
    setDeps(null);
  }
}

// ── the happy path: in process, no HTTP ─────────────────────────────────────

test("(a) an owner on a __Host- HTTPS session restarts in process: startBundle once, and NO HTTP request", async () => {
  const starts = [];
  const { value, calls } = await withoutFetch(() => run({ deps: { startBundle: async (id) => { starts.push(id); return { ok: true }; } } }));

  assert.equal(value.resolved, true);
  assert.deepEqual(starts, [BUNDLE_ID], "the route's start ran once, for the browser bundle");
  assert.deepEqual(calls, [], "no fetch at all: the restart is a function call, not a self-call");
});

test("(b) a stale plain crow_session cookie beside the __Host- one changes nothing", async () => {
  const starts = [];
  const req = ownerRequest("__Host-crow_session=abc123; crow_session=old");
  const { value, calls } = await withoutFetch(() => run({ req, deps: { startBundle: async (id) => { starts.push(id); return { ok: true }; } } }));

  assert.equal(value.resolved, true);
  assert.deepEqual(starts, [BUNDLE_ID]);
  assert.deepEqual(calls, [], "no request carries a cookie anywhere");
});

test("the restart path is bounded by the 15-minute constant", () => {
  assert.equal(RESTART_TIMEOUT_MS, 15 * 60 * 1000);
});

// ── the owner rule ────────────────────────────────────────────────────────

test("(c) not the owner → the owner-only flash, nothing restarted, one (owner_only) warn", async () => {
  let starts = 0;
  const { value, lines } = await captureWarn(() => run({
    deps: { owner: async () => false, startBundle: async () => { starts += 1; return { ok: true }; } },
  }));

  assert.equal(value.resolved, false);
  assert.equal(value.flash, OWNER_ONLY_FLASH);
  assert.equal(value.message, OWNER_ONLY_MESSAGE);
  assert.equal(starts, 0, "the restart never ran");
  assert.equal(lines.length, 1, "exactly one line");
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(owner_only\)$/);
});

// ── the Chromium-downgrade guard (fail closed) ─────────────────────────────

for (const [name, guard] of [
  ["blocked", async () => ({ blocked: true })],
  ["throwing", async () => { throw new Error("docker is not reachable"); }],
  ["answering nothing usable", async () => undefined],
]) {
  test(`(d) a ${name} guard → resolved false, nothing restarted, one (downgrade_guard) warn`, async () => {
    let starts = 0;
    const { value, lines } = await captureWarn(() => run({
      deps: { guard, startBundle: async () => { starts += 1; return { ok: true }; } },
    }));

    assert.equal(value.resolved, false, "the card stays open, the owner can try later");
    assert.equal(value.flash, undefined, "the Nest's generic line: the guard adds no user-facing copy");
    assert.equal(starts, 0, "no restart is run when the guard refuses");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(downgrade_guard\)$/);
  });
}

// ── a restart that did not run ────────────────────────────────────────────

test("(e) the start refuses on the compose safety check → one warn naming its code", async () => {
  const { value, lines } = await captureWarn(() => run({
    deps: { startBundle: async () => ({ ok: false, status: 403, code: "compose_security_check", error: "Security check failed: x" }) },
  }));

  assert.equal(value.resolved, false);
  assert.equal(value.flash, undefined, "the Nest's generic failure line, not a made-up sentence");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(start_failed:compose_security_check\)$/);
});

test("(f) the start refuses with only a message → the warn names the message", async () => {
  const { value, lines } = await captureWarn(() => run({
    deps: { startBundle: async () => ({ ok: false, status: 500, error: "Failed to start: docker compose up refused" }) },
  }));

  assert.equal(value.resolved, false);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(start_failed:/);
  assert.ok(lines[0].includes("start_failed:Failed to start: docker compose up refused"), lines[0]);
});

test("(f) a long message is trimmed to 200 characters, and never carries more", async () => {
  const long = "x".repeat(500);
  const { lines } = await captureWarn(() => run({ deps: { startBundle: async () => ({ ok: false, error: long }) } }));

  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(start_failed:x{200}\)$/);
});

test("(f) a message with newlines and tabs is one single-line warn, collapsed to spaces", async () => {
  const { value, lines } = await captureWarn(() => run({
    deps: { startBundle: async () => ({ ok: false, status: 500, error: "Failed to start:\n\tcompose up\trefused\n\n" }) },
  }));

  assert.equal(value.resolved, false);
  assert.equal(lines.length, 1, "exactly one warn line");
  assert.ok(!lines[0].includes("\n"), `no newline in the line: ${JSON.stringify(lines[0])}`);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(start_failed:Failed to start: compose up refused\)$/);
});

test("(g) a restart that hangs is bounded by the seam's timeout → one (timeout) warn", async () => {
  let settled = false;
  const { value, lines } = await captureWarn(() => run({
    deps: {
      timeoutMs: 25,
      startBundle: () => new Promise((resolve) => { setTimeout(() => { settled = true; resolve({ ok: true }); }, 5000).unref?.(); }),
    },
  }));

  assert.equal(value.resolved, false, "a hung build never holds the click open");
  assert.equal(settled, false, "the bound resolved first, not the restart");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(timeout\)$/);
});

test("(h) a restart that throws → one (start_failed:…) warn, never a throw into the Nest", async () => {
  const { value, lines } = await captureWarn(() => run({
    deps: { startBundle: async () => { throw new Error("the route blew up"); } },
  }));

  assert.equal(value.resolved, false);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[fix-it\] browser add-on: the restart did not run \(start_failed:/);
  assert.ok(lines[0].includes("the route blew up"), lines[0]);
});

// ── the REAL guard, wired as the product wires it ─────────────────────────
// The tests above replace the guard. These do NOT: only `owner` and the start are
// injected, so the remedy really calls downgradeGuard() → runningBrowserContainerIds()
// (docker ps by the bundle's compose project) → restartWouldDowngrade() (the lock's
// Chromium vs the profile's `Last Version`). The only stand-in is docker itself, through
// bundle-core's `_setDockerRunnerForTest` seam, and the CROW_HOME the module resolved at
// import (the temp home `before` fills with an installed browser bundle).

const PROFILE_PATH = "/root/.config/chromium-crow/Last Version";
const BROWSER_CONTAINER_ID = "b0b0b0b0b0b0";

/** A fake `docker` CLI: one running container, whose profile was last written by `profileVersion`. */
function fakeDocker(profileVersion) {
  const calls = [];
  const run = async (cmd, args, opts) => {
    calls.push({ cmd, args: [...args], opts });
    if (args[0] === "ps") return { stdout: `${BROWSER_CONTAINER_ID}\n`, stderr: "" };
    if (args[0] === "exec") return { stdout: `${profileVersion}\n`, stderr: "" };
    throw new Error(`unexpected docker call: ${cmd} ${args.join(" ")}`);
  };
  run.calls = calls;
  return run;
}

/**
 * Run the remedy with the real guard and a start spy. Nothing touches docker or the
 * network: docker is the stub, the start is recorded, and both are cleared in `finally`.
 */
async function runWithRealGuard(profileVersion) {
  const docker = fakeDocker(profileVersion);
  const started = [];
  setDockerRunner(docker);
  // NO `guard` seam on purpose: the remedy must build the real one.
  setDeps({ owner: OWNER, startBundle: async (id) => { started.push(id); return { ok: true }; } });
  try {
    const { value, lines } = await captureWarn(() => remedy.default({}, { db: null, item: null, req: ownerRequest() }));
    return { out: value, lines, docker, started };
  } finally {
    setDeps(null);
    setDockerRunner(null);
  }
}

test("the REAL guard: bundled 145 vs a profile at 159 → blocked, so the restart never runs", async () => {
  const { out, lines, docker, started } = await runWithRealGuard("159.0.8154.6");

  assert.equal(out.resolved, false, "the card stays pending: a rebuild would install an older Chromium than the profile holds");
  assert.equal(out.flash, undefined, "no new copy — the Nest's generic line");
  assert.deepEqual(started, [], "the restart was NOT run");

  // It really asked docker, in the product's own order: which containers run, then what
  // wrote this one's profile.
  assert.deepEqual(docker.calls.map((c) => c.args[0]), ["ps", "exec"]);
  assert.ok(docker.calls[0].args.includes("label=com.docker.compose.project=browser"), docker.calls[0].args.join(" "));
  assert.deepEqual(docker.calls[1].args, ["exec", BROWSER_CONTAINER_ID, "cat", PROFILE_PATH]);

  assert.equal(lines.length, 1);
  assert.match(lines[0], /\(downgrade_guard\)$/);
});

test("the REAL guard: bundled 145 vs a profile at 145 → allowed, so the restart runs with no request", async () => {
  const { out, started } = await runWithRealGuard("145.0.7632.6");

  assert.equal(out.resolved, true, "the same Chromium: the rebuild cannot move the profile backwards");
  assert.deepEqual(started, [BUNDLE_ID], "the restart ran exactly once, for the bundle it holds");
});

// ── the REAL route code: no seam between the remedy and the start path ────

/**
 * The last block injects NO restart: `startBundle` and `restart` are both left out, so the
 * remedy dynamically imports routes/bundles.js and runs the REAL
 * `restartBundleInProcess("browser")` against the temp CROW_HOME. That path asks docker
 * about the compose project (a stub that throws: `composeOwnership` treats an unreachable
 * docker as "nobody else owns it") and then the compose safety check, which cannot read the
 * model (the `compose config` seam throws) and therefore REFUSES. `up` must never be
 * reached: the compose runner records every call and fails the test.
 */
test("(i) the REAL start path: a compose the safety check cannot read refuses, and `up` never runs", async () => {
  const composeCalls = [];
  setDockerRunner(async () => { throw new Error("docker is not available in this test"); });
  setComposeRunner(async (args) => {
    composeCalls.push([...args]);
    throw new Error("docker compose up must not run for a refused start");
  });
  setComposeConfigRunner = (await import("../servers/gateway/routes/bundles.js"))._setComposeConfigRunnerForTest;
  setComposeConfigRunner(async () => { throw new Error("docker compose config is unavailable"); });
  try {
    const { value, lines } = await captureWarn(() => run({ deps: {} }));

    assert.equal(value.resolved, false, "the owner is told the fix did not run");
    assert.equal(value.flash, undefined, "the Nest's generic line");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /\(start_failed:compose_security_check\)$/, lines[0]);
    assert.deepEqual(composeCalls, [], "no compose command ran: the refusal came before `up`");
  } finally {
    setComposeConfigRunner(null);
    setComposeRunner(null);
    setDockerRunner(null);
  }
});