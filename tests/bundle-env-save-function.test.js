/**
 * Configure's env save: the route's behaviour, pinned over HTTP, plus the shape of the
 * `saveBundleEnv()` extraction it is being factored into.
 *
 * Contract: `export async function saveBundleEnv(bundleId, envVars, { owner = false, keychain } = {})`
 * in servers/gateway/routes/bundles.js returns `{ status, body }`, body being exactly the
 * JSON POST /bundles/api/env sends, with every validation (invalid id 400, not installed
 * 404, env_vars not an object 400, invalid_env 400, folder_needs_owner 403,
 * keychain/env_write 500) inside the function. The route handler only calls it with
 * `owner: await isLocalOwner(req)` and `keychain: req.body?.keychain`.
 *
 * Scratch CROW_HOME / CROW_DATA_DIR before the import: bundles.js resolves those at import.
 * No compose runner, no docker, no gateway .env: the fixtures are plain installed dirs and
 * the app env path points at a file that is never created, so propagation is a no-op.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const TMP_HOME = mkdtempSync(join(tmpdir(), "crow-envsave-home-"));
const TMP_DATA = mkdtempSync(join(tmpdir(), "crow-envsave-data-"));
process.env.CROW_HOME = TMP_HOME;
process.env.CROW_DATA_DIR = TMP_DATA;
process.env.CROW_AUTO_UPDATE = "0";
process.env.CROW_DISABLE_HEALTH_MONITOR = "1";
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_DISABLE_NOSTR = "1";
const CROW_HOME = process.env.CROW_HOME;

const FIXTURES = mkdtempSync(join(tmpdir(), "crow-envsave-app-"));
const GW = mkdtempSync(join(tmpdir(), "crow-envsave-gw-"));

const B = await import("../servers/gateway/routes/bundles.js");
B._setAppBundlesForTest(FIXTURES);
// Never created: propagateEnvToGateway sees no file and writes nothing.
B._setAppEnvPathForTest(join(GW, ".env"));
// The owner question is answered by the file's own seam, so a bare request is a
// non-owner save deterministically (the folder refusal below depends on it).
if (typeof B._setOwnerCheckForTest === "function") B._setOwnerCheckForTest(() => false);

after(() => {
  if (typeof B._setOwnerCheckForTest === "function") B._setOwnerCheckForTest(null);
  B._setAppEnvPathForTest(null);
  for (const d of [TMP_HOME, TMP_DATA, FIXTURES, GW]) rmScratch(d);
});

// ── fixtures ──

/** Declared key, a clearable key, and a generated secret the save may never write. */
const ENV_VARS = [
  { name: "FIXTURE_GREETING", description: "a greeting" },
  { name: "FIXTURE_PROJECT_ID", description: "a project id" },
  { name: "FIXTURE_DB_PASSWORD", generate: "secret" },
];
// A comment and three untouched-looking lines: the save must keep all of them in place.
const ENV_TEXT = "# kept comment\nFIXTURE_GREETING=hello\nFIXTURE_PROJECT_ID=p-1\nFIXTURE_DB_PASSWORD=generated-original\n";
const CLEARED_ENV_TEXT = "# kept comment\nFIXTURE_GREETING=bonjour\nFIXTURE_PROJECT_ID=p-1\nFIXTURE_DB_PASSWORD=generated-original\n";

const ROUTE_ID = "fixture-env-route";
const CLEAR_ID = "fixture-env-clear";
const FOLDER_ID = "fixture-env-folder";
const ABSENT_ID = "fixture-env-absent";

const FOLDER_COMPOSE = 'services:\n  app:\n    image: busybox:1.36\n    volumes:\n      - "${FIXTURE_MEDIA_DIR:-./media}:/media"\n';

/** An installed bundle: its dir has a manifest (the manifest lookup reads it first) and an .env. */
function seedInstalled(id, envVars, envText, composeText = null) {
  const dir = join(CROW_HOME, "bundles", id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id, name: id, description: "d", type: "bundle", version: "0.1.0", env_vars: envVars }));
  if (composeText) writeFileSync(join(dir, "docker-compose.yml"), composeText);
  writeFileSync(join(dir, ".env"), envText);
  return dir;
}
const envPath = (id) => join(CROW_HOME, "bundles", id, ".env");
const readEnvText = (id) => readFileSync(envPath(id), "utf8");

seedInstalled(ROUTE_ID, ENV_VARS, ENV_TEXT);
seedInstalled(CLEAR_ID, [{ name: "FIXTURE_PROJECT_ID", description: "a project id" }], "FIXTURE_PROJECT_ID=p-1\nOTHER_NOTE=keep\n");
seedInstalled(FOLDER_ID, [{ name: "FIXTURE_MEDIA_DIR", description: "a folder" }], "FIXTURE_MEDIA_DIR=./media\n", FOLDER_COMPOSE);

// ── HTTP harness ──

async function withServer(fn) {
  const app = express();
  app.use(express.json());
  app.use(B.default());
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
}

const postEnv = (base, body) => fetch(`${base}/bundles/api/env`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json() }));

const FOLDER_REFUSAL = {
  code: "folder_needs_owner",
  key: "FIXTURE_MEDIA_DIR",
  error: "Folder settings (FIXTURE_MEDIA_DIR) are set from this machine's own dashboard, signed in with its password.",
};

// ── 1. the route, unchanged ──

test("test_env_route_unchanged_over_http", async () => {
  // Each refusal, then a real save. Nothing is written before the last two calls.
  writeFileSync(envPath(ROUTE_ID), ENV_TEXT);
  await withServer(async (base) => {
    const badId = await postEnv(base, { bundle_id: "../fixture-env-route", env_vars: {} });
    assert.equal(badId.status, 400);
    assert.deepEqual(badId.body, { error: "Invalid bundle ID" });

    const absent = await postEnv(base, { bundle_id: ABSENT_ID, env_vars: { FIXTURE_GREETING: "x" } });
    assert.equal(absent.status, 404);
    assert.deepEqual(absent.body, { error: `Bundle '${ABSENT_ID}' is not installed` });

    const notObject = await postEnv(base, { bundle_id: ROUTE_ID, env_vars: "FIXTURE_GREETING=hi" });
    assert.equal(notObject.status, 400);
    assert.deepEqual(notObject.body, { error: "env_vars must be an object" });

    const invalid = await postEnv(base, { bundle_id: ROUTE_ID, env_vars: { "bad-key": "x" } });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.code, "invalid_env");
    assert.equal(invalid.body.key, "bad-key");
    assert.match(invalid.body.error, /bad-key/);

    assert.equal(readEnvText(ROUTE_ID), ENV_TEXT, "no refusal wrote the .env");

    const saved = await postEnv(base, { bundle_id: ROUTE_ID, env_vars: { FIXTURE_GREETING: "bonjour" } });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.deepEqual(saved.body, {
      ok: true,
      message: "Environment variables saved",
      needs_restart: false,
      needs_bundle_restart: false,
      applies_on_next_start: false,
      bundle_restart_keys: [],
      needs_config: [],
      keychain: null,
    });
    assert.equal(readEnvText(ROUTE_ID), CLEARED_ENV_TEXT, "line-preserving: only the submitted key changed");

    // A generated secret is never operator input: it is dropped before anything is written.
    const generated = await postEnv(base, { bundle_id: ROUTE_ID, env_vars: { FIXTURE_DB_PASSWORD: "attacker-value" } });
    assert.equal(generated.status, 200, JSON.stringify(generated.body));
    assert.equal(generated.body.ok, true);
    assert.equal(generated.body.needs_restart, false);
    assert.equal(readEnvText(ROUTE_ID), CLEARED_ENV_TEXT);
    assert.ok(!readEnvText(ROUTE_ID).includes("attacker-value"));
  });
});

// ── 2. the extraction answers exactly what the route answers ──

test("test_save_bundle_env_function_matches_route", async () => {
  const saveBundleEnv = B.saveBundleEnv;
  assert.equal(typeof saveBundleEnv, "function", "saveBundleEnv is not exported from servers/gateway/routes/bundles.js");

  const cases = [
    { label: "invalid id", body: { bundle_id: "../fixture-env-route", env_vars: {} } },
    { label: "not installed", body: { bundle_id: ABSENT_ID, env_vars: { FIXTURE_GREETING: "x" } } },
    { label: "env_vars is not an object", body: { bundle_id: ROUTE_ID, env_vars: "FIXTURE_GREETING=hi" } },
    { label: "invalid env name", body: { bundle_id: ROUTE_ID, env_vars: { "bad-key": "x" } } },
    { label: "valid save", body: { bundle_id: ROUTE_ID, env_vars: { FIXTURE_GREETING: "bonjour" } } },
    { label: "generated key stripped", body: { bundle_id: ROUTE_ID, env_vars: { FIXTURE_DB_PASSWORD: "attacker-value" } } },
  ];

  await withServer(async (base) => {
    for (const { label, body } of cases) {
      writeFileSync(envPath(ROUTE_ID), ENV_TEXT);
      const viaRoute = await postEnv(base, body);
      const envAfterRoute = readEnvText(ROUTE_ID);

      writeFileSync(envPath(ROUTE_ID), ENV_TEXT);
      const viaFunction = await saveBundleEnv(body.bundle_id, body.env_vars, { owner: false });
      const envAfterFunction = readEnvText(ROUTE_ID);

      assert.deepEqual(viaFunction, viaRoute, `${label}: the function's {status, body} must match the route's`);
      assert.equal(envAfterFunction, envAfterRoute, `${label}: the function must leave the .env exactly as the route does`);
    }
  });
});

// ── 3. an empty string clears a declared non-required key ──

test("test_save_bundle_env_empty_string_clears_a_key", async () => {
  const saveBundleEnv = B.saveBundleEnv;
  assert.equal(typeof saveBundleEnv, "function", "saveBundleEnv is not exported from servers/gateway/routes/bundles.js");

  const out = await saveBundleEnv(CLEAR_ID, { FIXTURE_PROJECT_ID: "" }, { owner: false });
  assert.equal(out.status, 200, JSON.stringify(out.body));
  assert.equal(out.body.ok, true);
  assert.equal(readEnvText(CLEAR_ID), "FIXTURE_PROJECT_ID=\nOTHER_NOTE=keep\n", "KEY= clears it; the other line stays");
});

// ── 4. owner:false refuses a folder value on a compose-referenced key ──

test("test_save_bundle_env_owner_flag", async () => {
  const saveBundleEnv = B.saveBundleEnv;
  assert.equal(typeof saveBundleEnv, "function", "saveBundleEnv is not exported from servers/gateway/routes/bundles.js");

  const body = { FIXTURE_MEDIA_DIR: "/srv/fixture-media" };
  const viaFunction = await saveBundleEnv(FOLDER_ID, { ...body }, { owner: false });
  assert.equal(viaFunction.status, 403);
  assert.deepEqual(viaFunction.body, FOLDER_REFUSAL);
  assert.equal(readEnvText(FOLDER_ID), "FIXTURE_MEDIA_DIR=./media\n", "the folder was not written");

  // The route, for a request that is not the owner, answers the same 403.
  await withServer(async (base) => {
    const viaRoute = await postEnv(base, { bundle_id: FOLDER_ID, env_vars: { ...body } });
    assert.equal(viaRoute.status, 403);
    assert.deepEqual(viaRoute.body, FOLDER_REFUSAL);
  });
  assert.equal(readEnvText(FOLDER_ID), "FIXTURE_MEDIA_DIR=./media\n");
});