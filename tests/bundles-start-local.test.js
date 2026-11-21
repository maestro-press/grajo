/**
 * restartBundleInProcess — the in-process restart the Fix-it card calls
 * (tests/bundles-start-local.test.js)
 *
 * The Extensions Start route's local path is `startBundleLocal` (routes/bundles.js), and
 * `restartBundleInProcess` is the no-request entry point the "Restart the browser add-on"
 * card uses: it refuses a bundle whose manifest names ANOTHER instance's host (its
 * containers run there, so a local `up` would start the wrong copy) and otherwise runs the
 * same `up -d --build --force-recreate` through the same guards.
 *
 * Nothing here touches docker or compose: the refusal is decided from the installed
 * manifest, before any such call, and both runner seams are stubs that record and throw —
 * so a regression that asks docker is visible instead of spawning one.
 *
 * CROW_HOME is a scratch dir set BEFORE the dynamic import: BUNDLES_DIR resolves at load.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home;
let restartBundleInProcess;
let startBundleLocal;
let setDockerRunner;
let setComposeRunner;
let setComposeConfigRunner;

before(async () => {
  home = mkdtempSync(join(tmpdir(), "crowhome-startlocal-"));
  process.env.CROW_HOME = home;

  // A bundle that runs on another instance: its manifest says so, and that alone decides.
  const peerDir = join(home, "bundles", "peer-thing");
  mkdirSync(peerDir, { recursive: true });
  writeFileSync(join(peerDir, "manifest.json"), JSON.stringify({
    id: "peer-thing", name: "Peer thing", version: "1.0.0",
    host: "other-instance", docker: { composefile: "docker-compose.yml" },
  }));
  writeFileSync(join(peerDir, "docker-compose.yml"), "name: peer-thing\nservices:\n  app:\n    image: busybox\n");

  // A bundle with no containers at all (an MCP-server / skill-only add-on).
  const bareDir = join(home, "bundles", "no-containers");
  mkdirSync(bareDir, { recursive: true });
  writeFileSync(join(bareDir, "manifest.json"), JSON.stringify({ id: "no-containers", name: "Bare", version: "1.0.0", type: "skill" }));

  writeFileSync(join(home, "installed.json"), JSON.stringify([
    { id: "peer-thing", type: "bundle", version: "1.0.0" },
    { id: "no-containers", type: "skill", version: "1.0.0" },
  ]));

  const routes = await import("../servers/gateway/routes/bundles.js");
  restartBundleInProcess = routes.restartBundleInProcess;
  startBundleLocal = routes.startBundleLocal;
  setComposeConfigRunner = routes._setComposeConfigRunnerForTest;
  const core = await import("../servers/gateway/bundle-core.js");
  setDockerRunner = core._setDockerRunnerForTest;
  setComposeRunner = core._setComposeRunnerForTest;
});

after(() => {
  delete process.env.CROW_HOME;
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
});

/** Both runner seams, as stubs that record and refuse. Cleared by the caller in a finally. */
function stubRunners() {
  const dockerCalls = [];
  const composeCalls = [];
  setDockerRunner(async (cmd, args) => {
    dockerCalls.push([cmd, ...(args || [])]);
    throw new Error("docker must not be asked for this decision");
  });
  setComposeRunner(async (args) => {
    composeCalls.push([...(args || [])]);
    throw new Error("docker compose must not run for this decision");
  });
  setComposeConfigRunner(async () => { throw new Error("docker compose config must not run either"); });
  return { dockerCalls, composeCalls };
}

function clearRunners() {
  setDockerRunner(null);
  setComposeRunner(null);
  setComposeConfigRunner(null);
}

test("restartBundleInProcess refuses a bundle whose manifest names another instance's host", async () => {
  const { dockerCalls, composeCalls } = stubRunners();
  try {
    const out = await restartBundleInProcess("peer-thing");

    assert.equal(out.ok, false, "a bundle that runs elsewhere is never restarted here");
    assert.equal(out.status, 409);
    assert.equal(out.code, "remote_host");
    assert.match(out.error, /another Crow instance/);
    assert.deepEqual(dockerCalls, [], "the refusal came from the manifest, before any docker call");
    assert.deepEqual(composeCalls, [], "and before any compose call");
  } finally {
    clearRunners();
  }
});

test("startBundleLocal: a bundle with no compose file answers the route's own 404", async () => {
  const { dockerCalls, composeCalls } = stubRunners();
  try {
    const out = await startBundleLocal("no-containers");

    assert.equal(out.ok, false);
    assert.equal(out.status, 404);
    assert.equal(out.error, "Bundle 'no-containers' has no Docker containers");
    assert.deepEqual(dockerCalls, []);
    assert.deepEqual(composeCalls, []);
  } finally {
    clearRunners();
  }
});

test("restartBundleInProcess never throws, whatever it is handed", async () => {
  const { dockerCalls } = stubRunners();
  try {
    for (const id of [undefined, null, "", "../../etc", "does-not-exist"]) {
      const out = await restartBundleInProcess(id);
      assert.equal(out.ok, false, `refused for ${JSON.stringify(id)}`);
      assert.equal(typeof out.status, "number");
    }
    assert.deepEqual(dockerCalls, []);
  } finally {
    clearRunners();
  }
});