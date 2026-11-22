/**
 * Panel-method project services (Finance Hub P2): a service whose `connect.method` is "panel" is
 * connected in its own bundle panel, never by the generic Connect screen, and never starts a
 * child. A scratch Crow home, a per-test init-db database and the echo MCP fixture as every
 * installed add-on: never ~/.crow or ~/.pi.
 *
 * The panel fixture is the real registry's entries plus one extra manifest (set through the
 * catalog's test seam), so the existing services keep their own connect blocks.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseHTML } from "linkedom";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(REPO, "tests", "fixtures", "echo-mcp-server.mjs");
const HOME = mkdtempSync(join(tmpdir(), "crow-panel-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-panel-data-"));
mkdirSync(join(HOME, "secrets"), { recursive: true });
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = DATA;
process.env.CROW_AUTO_UPDATE = "0";
process.env.CROW_DISABLE_HEALTH_MONITOR = "1";
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_DISABLE_NOSTR = "1";
delete process.env.CROW_SERVICES_UI;

const CAT = await import("../servers/shared/service-catalog.js");
const SC = await import("../servers/shared/service-connections.js");
const SENS = await import("../servers/shared/service-sensitivity.js");
const C = await import("../servers/gateway/services/children.js");
const TC = await import("../servers/gateway/services/tool-cache.js");
const K = await import("../servers/gateway/keychain/store.js");
const { loadKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { createDbClient } = await import("../servers/db.js");
const { servicesApiRouter, loadServicesPage } = await import("../servers/gateway/routes/services-api.js");
const { isOneClickEligible, savedKeyServiceIds } = await import("../servers/gateway/services/saved-key.js");
const { connectedServiceSources } = await import("../servers/gateway/dashboard/panels/bot-builder/data-queries.js");
const { listProjectServiceTools } = await import("../servers/gateway/services/project-tools.js");
const { validateManifest } = await import("../scripts/lib/bundle-contract.mjs");
const { projectServicesHtml } = await import("../servers/gateway/dashboard/panels/project-services/html.js");
const { projectServicesClientJs, projectServicesData, projectServicesDataScript } = await import(
  "../servers/gateway/dashboard/panels/project-services/client.js"
);
const { csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");

const GH = "GITHUB_PERSONAL_ACCESS_TOKEN";
const NOTION_TOKEN = "NOTION_TOKEN";
const PANEL_KEY = "PANELFIX_KEY";
const PANEL_APPROVE = "PANELFIX_APPROVE";
const CANARY_KEY = "test-canary-panelkey-7f3a9";
const CANARY_APPROVE = "test-canary-panelapprove-4b81c";
const CANARIES = [CANARY_KEY, CANARY_APPROVE];
const PANEL_ROUTE = "/dashboard/panelfix";
const SPAWNS = join(HOME, "spawns.log");
const BUNDLES = ["github", "notion", "panelfix"];

// ---- the fixture service, in the real registry ------------------------------------------------

const PANEL = {
  id: "panelfix",
  name: "Panel Fixture",
  description: "fixture",
  icon: "box",
  category: "finance",
  version: "1.0.0",
  type: "mcp-server",
  server: { command: "node", args: [FIXTURE], envKeys: [] },
  connect: {
    method: "panel",
    group: "paste",
    panel_route: PANEL_ROUTE,
    panel_secrets: [PANEL_KEY, PANEL_APPROVE],
  },
};
const REG = JSON.parse(readFileSync(join(REPO, "registry", "add-ons.json"), "utf8"));
CAT._setServiceCatalogForTest({ ...REG, "add-ons": [...REG["add-ons"], PANEL] });

// ---- scratch install --------------------------------------------------------------------------

for (const id of BUNDLES) {
  const dir = join(HOME, "bundles", id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "echo-control.json"), JSON.stringify({ spawnLog: SPAWNS }));
}
writeFileSync(join(HOME, "installed.json"), JSON.stringify(BUNDLES.map((id) => ({ id, type: "mcp-server", version: "1.0.0" }))));
writeFileSync(join(HOME, "mcp-addons.json"), JSON.stringify(
  Object.fromEntries(BUNDLES.map((id) => [id, { command: "node", args: [FIXTURE], env: {} }])),
), { mode: 0o600 });

const spawnCount = () => (existsSync(SPAWNS) ? readFileSync(SPAWNS, "utf8").split("\n").filter(Boolean).length : 0);

// ---- databases, projects, connections ---------------------------------------------------------

const DIRS = [HOME, DATA];
const mkDb = (path) => createDbClient(path);
async function withDbPath(path, fn) {
  const d = mkDb(path);
  try { return await fn(d); } finally { d.close(); }
}

let dbN = 0;
async function freshDb() {
  const dir = mkdtempSync(join(tmpdir(), `crow-panel-db${++dbN}-`));
  DIRS.push(dir);
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe", cwd: REPO });
  const path = join(dir, "crow.db");
  const d = mkDb(path);
  const ids = {};
  for (const slug of ["spring", "home"]) {
    const r = await d.execute({ sql: "INSERT INTO project_spaces (slug, name) VALUES (?, ?) RETURNING id", args: [slug, slug] });
    ids[slug] = Number(r.rows[0].id);
  }
  d.close();
  return { path, dir, ids };
}

/** createPanelConnection, as the panel's own connect path calls it. */
async function panelCreate(ctx, body) {
  return withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createPanelConnection(d, body, { key });
  });
}

/** A panel connection plus the binding and fingerprints the owner's connect path records. */
async function panelConnect(ctx, { projectId, label = "main", secrets, config = {} } = {}) {
  const values = secrets ?? { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE };
  const conn = await panelCreate(ctx, { projectId, serviceId: "panelfix", accountLabel: label, config, secrets: values });
  SENS.recordConnectionBinding(conn, { crowHome: HOME, service: CAT.serviceById("panelfix"), values: { config: conn.config, secrets: values } });
  return conn;
}

/** A real (non-panel) connection, as the owner's connect route makes one. */
async function connectBound(ctx, serviceId, { projectId, label = "work", secrets = {}, config = {} } = {}) {
  return withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    const c = await SC.createConnection(d, { projectId, serviceId, accountLabel: label, config, secrets, testedAt: new Date() }, { key });
    SENS.recordConnectionBinding(c, { crowHome: HOME, service: CAT.serviceById(serviceId), values: { config: c.config, secrets } });
    return c;
  });
}

const keyObj = () => loadKeychainKey({ crowHome: HOME });
const codeOf = async (p) => {
  try { await p; return "ok"; } catch (err) { return err?.code || String(err); }
};

// ---- the services API router harness ----------------------------------------------------------

const COOKIE = "crow_session=s1";
const AUTH = { cookie: COOKIE, "x-crow-csrf": csrfTokenForSession("s1") };
const stubGate = (req, res, next) => {
  if (!String(req.headers.cookie || "").includes("crow_session=s1")) return res.status(401).json({ error: "Not authenticated" });
  req.dashboardSession = "s1";
  next();
};

function fakeTest(result = { ok: true }) {
  const f = async (service, opts) => { f.calls.push({ service: service.id, values: opts.values }); return f.result; };
  f.calls = [];
  f.result = result;
  return f;
}

async function startApp(ctx, opts = {}) {
  const app = express();
  app.use(servicesApiRouter({
    dbFactory: () => mkDb(ctx.path),
    sessionGate: stubGate,
    testConnection: ctx.test,
    installedIds: () => new Set(BUNDLES),
    uiEnabled: () => true,
    crowHome: HOME,
    reservedNames: () => new Set(),
    refreshMasking: () => {},
    recordSecrets: () => {},
    ownerCheck: async (_db, req) => req.dashboardSession === "s1",
    ...opts,
  }));
  return new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
}

function call(server, method, path, { body, headers = {} } = {}) {
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port: server.address().port, path, method,
      headers: { ...(payload != null ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}), ...headers },
    }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () => { let json = null; try { json = JSON.parse(text); } catch {} resolve({ status: res.statusCode, text, json }); });
    });
    req.on("error", reject);
    if (payload != null) req.write(payload);
    req.end();
  });
}

async function withApp(ctx, fn, opts) {
  const s = await startApp(ctx, opts);
  try { return await fn(s); } finally { s.close(); }
}

/** Capture console.log/warn/error while fn runs. */
async function capture(fn) {
  const out = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...a) => { out.push(a.map(String).join(" ")); };
  try { return { result: await fn(), out: out.join("\n") }; } finally { Object.assign(console, orig); }
}

const panelRefusal = { ok: false, error: "PANEL_ONLY", code: "PANEL_ONLY", message: "Connect this in its own panel" };

after(async () => {
  await C.stopAllChildren();
  for (const d of DIRS) rmScratch(d);
});

// ---- 1. no child, sealed secrets --------------------------------------------------------------

test("test_panel_method_no_child_spawned", async () => {
  assert.equal(typeof CAT.isPanelService, "function", "isPanelService is exported");
  assert.equal(typeof SC.createPanelConnection, "function", "createPanelConnection is exported");
  assert.ok(SC.CONNECTION_ERROR_CLASSES.has("panel_only"), "panel_only is a connection error class");

  const svc = CAT.serviceById("panelfix");
  assert.ok(svc, "the panel fixture is in the catalog");
  assert.equal(svc.method, "panel");
  assert.equal(CAT.isPanelService(svc), true);
  assert.equal(CAT.isPanelService(CAT.serviceById("github")), false, "a token service is not a panel service");
  assert.equal(svc.panelRoute, PANEL_ROUTE);
  assert.deepEqual(svc.panelSecrets, [PANEL_KEY, PANEL_APPROVE]);
  assert.deepEqual(svc.fields, [], "a panel service declares no fields");

  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const before = spawnCount();
  const conn = await panelConnect(ctx, { projectId: pid });
  assert.match(conn.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

  const row = await withDbPath(ctx.path, (d) => SC.getConnection(d, conn.uuid));
  assert.equal(row.status, "active");
  assert.equal(row.method, "panel");
  assert.equal(row.serviceId, "panelfix");
  assert.equal(row.lastError, null);

  // The audit row names the service and nothing else.
  const audit = (await withDbPath(ctx.path, (d) => d.execute({
    sql: "SELECT action, target, payload FROM project_audit_log WHERE action = 'service.connect' ORDER BY id",
  }))).rows;
  const mine = audit.filter((a) => a.target === conn.uuid);
  assert.equal(mine.length, 1);
  assert.deepEqual(JSON.parse(mine[0].payload), { service_id: "panelfix" });

  // The secrets are sealed once, for this connection, under their own names.
  assert.deepEqual(
    await withDbPath(ctx.path, (d) => K.serviceSecretsFor(d, keyObj(), conn.uuid, { allowedKeys: [PANEL_KEY, PANEL_APPROVE] })),
    { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
  );

  // No child, ever: ensureChild refuses it by class, before any secret read or spawn.
  await assert.rejects(
    withDbPath(ctx.path, (d) => C.ensureChild(d, conn.uuid, { crowHome: HOME })),
    (err) => err?.name === "ChildError" && err?.code === "panel_only",
  );
  assert.equal(C.childState(conn.uuid), "stopped");
  assert.equal(spawnCount(), before, "a panel connection starts no process");

  // Undeclared key, missing declared key, a config value, and a service that is not panel.
  assert.equal(await codeOf(panelCreate(ctx, {
    projectId: pid, serviceId: "panelfix", accountLabel: "undeclared",
    secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE, PANELFIX_OTHER: "x" },
  })), "bad_value");
  assert.equal(await codeOf(panelCreate(ctx, {
    projectId: pid, serviceId: "panelfix", accountLabel: "missing", secrets: { [PANEL_KEY]: CANARY_KEY },
  })), "missing_field");
  assert.equal(await codeOf(panelCreate(ctx, {
    projectId: pid, serviceId: "panelfix", accountLabel: "configured",
    config: { PANELFIX_SETTING: "1" }, secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
  })), "bad_value");
  assert.equal(await codeOf(panelCreate(ctx, {
    projectId: pid, serviceId: "github", accountLabel: "github", secrets: { [GH]: "test-token-1" },
  })), "unknown_service");
  assert.equal(await codeOf(panelCreate(ctx, {
    projectId: pid, serviceId: "panelfix", accountLabel: "main",
    secrets: { [PANEL_KEY]: "another-key", [PANEL_APPROVE]: "another-approval" },
  })), "label_taken", "the label rule is the same as any other connection");

  // The generic createConnection refuses a panel service with its own class.
  assert.equal(await codeOf(withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createConnection(d, {
      projectId: pid, serviceId: "panelfix", accountLabel: "plain",
      secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
    }, { key });
  })), "panel_only");

  const rows = (await withDbPath(ctx.path, (d) => d.execute("SELECT uuid FROM service_connections"))).rows;
  assert.equal(rows.length, 1, "a refused panel connect stores no row");
  assert.equal(spawnCount(), before);
});

// ---- 2. no panel value in any environment -----------------------------------------------------

test("test_panel_secrets_never_in_any_env", async () => {
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const { result, out } = await capture(async () => {
    const panel = await panelConnect(ctx, { projectId: pid });
    const gh = await connectBound(ctx, "github", { projectId: pid, label: "work", secrets: { [GH]: "test-token-panel-2" } });
    const { client } = await withDbPath(ctx.path, (d) => C.ensureChild(d, gh.uuid, { crowHome: HOME }));
    const who = JSON.parse((await client.callTool({ name: "whoami", arguments: {} })).content[0].text);
    for (const name of [PANEL_KEY, PANEL_APPROVE]) {
      assert.ok(!who.keys.includes(name), name + " is not in a service child's environment");
      const h = JSON.parse((await client.callTool({ name: "envhash", arguments: { name } })).content[0].text);
      assert.equal(h.present, false, name + " has no value in a service child's environment");
    }
    assert.deepEqual(C.childSecretValues(gh.uuid).filter((v) => CANARIES.includes(v)), [], "the child's injected values hold no panel value");
    await C.stopAllChildren();
    const offered = await withDbPath(ctx.path, (d) => C.offerableProjectConnections(d, pid));
    const listed = await withDbPath(ctx.path, (d) => C.listedTools(d, panel.uuid, { crowHome: HOME }));
    const listedGh = await withDbPath(ctx.path, (d) => C.listedTools(d, gh.uuid, { crowHome: HOME }));
    const blobs = {
      "this process's env": JSON.stringify(process.env),
      "the offerable connections": JSON.stringify(offered),
      "the panel connection's listed tools": JSON.stringify(listed),
      "a github connection's listed tools": JSON.stringify(listedGh),
      "the child registry": JSON.stringify(C.listChildren()),
    };
    for (const [where, blob] of Object.entries(blobs)) {
      for (const canary of CANARIES) assert.ok(!blob.includes(canary), where + " carry no panel value");
    }
    return { panel, gh };
  });
  assert.ok(!out.includes(CANARY_KEY), "no log line carries a panel key");
  assert.ok(!out.includes(CANARY_APPROVE), "no log line carries a panel approval value");

  const audits = (await withDbPath(ctx.path, (d) => d.execute("SELECT action, target, payload FROM project_audit_log"))).rows;
  assert.ok(audits.some((a) => a.target === result.panel.uuid && a.action === "service.connect"), "the panel connect is audited");
  for (const canary of CANARIES) assert.ok(!JSON.stringify(audits).includes(canary), "no audit payload carries a panel value");

  const meta = (await withDbPath(ctx.path, (d) => d.execute(
    "SELECT kind, label, bundle_id, env_key, username, url, key_id, origin, status, connection_uuid FROM crow_keychain",
  ))).rows;
  for (const canary of CANARIES) assert.ok(!JSON.stringify(meta).includes(canary), "only the sealed column holds it");

  // A panel row rewritten to another service must never start a child: its recorded binding still
  // names panelfix, so the binding/fingerprint check refuses it before any secret is read.
  const rewritten = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    const c = await SC.createPanelConnection(d, {
      projectId: pid, serviceId: "panelfix", accountLabel: "rewritten",
      secrets: { [PANEL_KEY]: "test-panel-rewrite-key-9", [PANEL_APPROVE]: "test-panel-rewrite-approve-9" },
    }, { key, crowHome: HOME });
    assert.equal(SENS.connectionBindingOk(c, { crowHome: HOME }), true, "the panel connect records its binding");
    // Re-key the key's sealed row to the GitHub env name, then rewrite the row's service.
    const row = (await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [c.uuid, PANEL_KEY] })).rows[0];
    await d.execute({ sql: "UPDATE crow_keychain SET env_key = ? WHERE id = ?", args: [GH, row.id] });
    await d.execute({ sql: "UPDATE service_connections SET service_id = 'github', bundle_id = 'github', method = 'token' WHERE uuid = ?", args: [c.uuid] });
    return c;
  });
  const beforeReject = spawnCount();
  await assert.rejects(
    withDbPath(ctx.path, (d) => C.ensureChild(d, rewritten.uuid, { crowHome: HOME })),
    (err) => err?.name === "ChildError" && (err?.code === "not_active" || err?.code === "panel_only"),
  );
  assert.equal(C.childState(rewritten.uuid), "stopped");
  assert.equal(spawnCount(), beforeReject, "a panel row rewritten to another service starts no process");
});

// ---- 3. the generic Connect refuses it --------------------------------------------------------

test("test_generic_connect_refuses_panel", async () => {
  const ctx = await freshDb();
  ctx.test = fakeTest();
  await withApp(ctx, async (s) => {
    const typed = await call(s, "POST", "/dashboard/services/api/project/spring/connect", {
      body: { serviceId: "panelfix", accountLabel: "main", values: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE } },
      headers: AUTH,
    });
    assert.equal(typed.status, 400, typed.text);
    assert.deepEqual(typed.json, panelRefusal);
    const saved = await call(s, "POST", "/dashboard/services/api/project/spring/connect", {
      body: { serviceId: "panelfix", useSavedKey: true },
      headers: AUTH,
    });
    assert.equal(saved.status, 400, saved.text);
    assert.deepEqual(saved.json, panelRefusal);
    for (const r of [typed, saved]) {
      for (const canary of CANARIES) assert.ok(!r.text.includes(canary), "no answer carries a panel value");
    }
  });
  assert.equal(ctx.test.calls.length, 0, "nothing is tested or sent anywhere");
  assert.equal((await withDbPath(ctx.path, (d) => d.execute("SELECT COUNT(*) AS n FROM service_connections"))).rows[0].n, 0);
  assert.equal((await withDbPath(ctx.path, (d) => d.execute("SELECT COUNT(*) AS n FROM crow_keychain"))).rows[0].n, 0);
});

// ---- 4. no one-click for a panel service ------------------------------------------------------

test("test_saved_key_one_click_refuses_panel", async () => {
  assert.equal(typeof CAT.isPanelService, "function", "isPanelService is exported");
  const ctx = await freshDb();
  const svc = CAT.serviceById("panelfix");
  assert.equal(CAT.isPanelService(svc), true);
  assert.equal(isOneClickEligible(svc), false, "a panel service is never a one-click connect");

  await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    for (const envKey of [PANEL_KEY, PANEL_APPROVE]) {
      await K.saveExtensionSecret(d, key, { bundleId: "panelfix", envKey, label: `Panel Fixture - ${envKey}`, secret: CANARY_KEY, origin: "typed" });
    }
    // A control: rows of the same shape for github do make github one-click (the setup works).
    await K.saveExtensionSecret(d, key, { bundleId: "github", envKey: GH, label: `GitHub - ${GH}`, secret: "test-token-4", origin: "typed" });
  });

  const ids = await withDbPath(ctx.path, (d) => savedKeyServiceIds(d, CAT.serviceCatalog(), new Set(BUNDLES)));
  assert.ok(!ids.has("panelfix"), "an active saved key never makes a panel service one-click");
  assert.ok(ids.has("github"), "the same test setup makes github one-click");
});

// ---- 5. Test again and Restart refuse it ------------------------------------------------------

test("test_test_and_restart_routes_refuse_panel", async () => {
  assert.equal(typeof SC.createPanelConnection, "function", "createPanelConnection is exported");
  const ctx = await freshDb();
  const conn = await panelConnect(ctx, { projectId: ctx.ids.spring });
  ctx.test = fakeTest();
  const before = spawnCount();
  await withApp(ctx, async (s) => {
    for (const action of ["test", "restart"]) {
      const r = await call(s, "POST", `/dashboard/services/api/connection/${conn.uuid}/${action}`, { headers: AUTH, body: {} });
      assert.equal(r.status, 400, action + ": " + r.text);
      assert.deepEqual(r.json, panelRefusal);
      for (const canary of CANARIES) assert.ok(!r.text.includes(canary));
    }
  });
  assert.equal(ctx.test.calls.length, 0, "the live test never runs for a panel service");
  assert.equal(spawnCount(), before, "nothing is spawned");
  assert.equal(C.childState(conn.uuid), "stopped");
});

// ---- 6. every bot-facing listing skips it -----------------------------------------------------

test("test_bot_builder_and_project_tools_skip_panel_secrets", async () => {
  assert.equal(typeof SC.createPanelConnection, "function", "createPanelConnection is exported");
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const panel = await panelConnect(ctx, { projectId: pid });
  const gh = await connectBound(ctx, "github", { projectId: pid, label: "work", secrets: { [GH]: "test-token-6" } });
  TC.writeToolCache(HOME, "github", "1.0.0", [{ name: "whoami", description: "who" }]);
  TC.writeToolCache(HOME, "panelfix", "1.0.0", [{ name: "panel-tool", description: "p" }]);
  const before = spawnCount();

  const offered = await withDbPath(ctx.path, (d) => C.offerableProjectConnections(d, pid));
  assert.deepEqual(offered.map((c) => c.uuid), [gh.uuid], "only the github connection is offered");
  assert.ok(!offered.some((c) => c.uuid === panel.uuid), "the panel connection is never offered");
  for (const canary of CANARIES) assert.ok(!JSON.stringify(offered).includes(canary));

  const sources = await withDbPath(ctx.path, (d) => connectedServiceSources({ db: d, projectId: pid, crowHome: HOME, started: new Set() }));
  assert.ok(sources.some((s) => s.server === "github"), "the github service is still listed for the builder");
  assert.ok(!sources.some((s) => s.server === "panelfix"), "a panel service is never a builder source");
  for (const canary of CANARIES) assert.ok(!JSON.stringify(sources).includes(canary));

  const listed = await withDbPath(ctx.path, (d) => listProjectServiceTools(d, { projectId: pid, crowHome: HOME }));
  assert.ok(listed.tools.some((t) => t.name.startsWith("mcp__github-")), "the chat still lists github's tools");
  assert.ok(!listed.tools.some((t) => t.name.startsWith("mcp__panelfix-")), "no panel tool is advertised");
  assert.ok(![...listed.route.values()].some((v) => v.uuid === panel.uuid), "no route reaches the panel connection");

  assert.equal(spawnCount(), before, "none of the listings starts a process");
  assert.equal(C.childState(panel.uuid), "stopped");
});

// ---- 7. the manifest contract -----------------------------------------------------------------

const CONTRACT_BASE = { id: "panelfix", name: "Panel Fixture", description: "fixture", type: "mcp-server", category: "finance" };
function panelManifest(connect = {}) {
  return {
    ...CONTRACT_BASE,
    connect: { method: "panel", group: "paste", panel_route: PANEL_ROUTE, panel_secrets: [PANEL_KEY], ...connect },
  };
}
const TOKEN_CONNECT = {
  method: "token",
  group: "network",
  fields: [
    { name: "HA_URL", kind: "address", label_key: "k.url" },
    { name: "HA_TOKEN", kind: "secret", label_key: "k.token" },
  ],
  steps: ["s.one"],
};
function tokenManifest(connect = {}) {
  return {
    id: "demo", name: "Demo", description: "d", type: "mcp-server", category: "misc",
    env_vars: [{ name: "HA_URL", description: "u" }, { name: "HA_TOKEN", description: "t", secret: true }],
    connect: { ...TOKEN_CONNECT, ...connect },
  };
}
const checkPanel = (m) => validateManifest(m, "/tmp/panelfix");
const checkToken = (m) => validateManifest(m, "/tmp/demo");

test("test_contract_accepts_panel_secrets_without_env_vars", () => {
  const ok = checkPanel(panelManifest());
  assert.equal(ok.ok, true, ok.errors.join("; "));

  const noRoute = panelManifest();
  delete noRoute.connect.panel_route;
  assert.equal(checkPanel(noRoute).ok, false, "a panel block needs panel_route");

  const noSecrets = panelManifest();
  delete noSecrets.connect.panel_secrets;
  assert.equal(checkPanel(noSecrets).ok, false, "a panel block needs panel_secrets");

  assert.equal(checkPanel(panelManifest({ fields: [{ name: PANEL_KEY, kind: "secret", label_key: "k" }] })).ok, false,
    "a panel block may carry fields, but they must be empty");
  assert.equal(checkPanel(panelManifest({ panel_route: "dashboard/panelfix" })).ok, false, "panel_route starts with /");
  assert.equal(checkPanel(panelManifest({ panel_secrets: ["panelfix_key"] })).ok, false, "a secret name is an env-style name");
  assert.equal(checkPanel(panelManifest({ panel_secrets: [PANEL_KEY, PANEL_KEY] })).ok, false, "secret names are unique");

  assert.equal(checkToken(tokenManifest({ panel_secrets: [PANEL_KEY] })).ok, false, "panel_secrets is only for method panel");
  assert.equal(checkToken(tokenManifest({ panel_route: PANEL_ROUTE })).ok, false, "panel_route is only for method panel");
  assert.equal(checkToken(tokenManifest()).ok, true, "the untouched token block still passes");
});

// ---- 8. the connect sheet links to the panel --------------------------------------------------

const CLIENT_HTML = projectServicesClientJs();
const CLIENT_JS = CLIENT_HTML.slice(CLIENT_HTML.indexOf("<script>") + "<script>".length, CLIENT_HTML.lastIndexOf("</script>"));

function panelPage() {
  return {
    project: { slug: "spring", name: "Spring" },
    connections: [],
    hasMembers: false,
    alsoOnCrow: [],
    groups: {
      network: [],
      signin: [],
      paste: [{
        serviceId: "panelfix", bundleId: "panelfix", name: "Panel Fixture", installed: true, labelFrom: null,
        panelRoute: PANEL_ROUTE, fields: [], steps: [], stepLinks: {},
      }],
      builtin: [],
    },
    botsLive: false,
  };
}

function boot(pageData) {
  const html = projectServicesHtml(pageData, "en") + projectServicesDataScript(pageData, "en");
  const { window, document } = parseHTML(`<html><body class="shell"><main>${html}</main></body></html>`);
  const calls = [];
  const fetchStub = (url, init = {}) => {
    calls.push({ url: String(url), method: init.method, body: init.body ?? null });
    return Promise.resolve({ status: 201, ok: true, json: () => Promise.resolve({ ok: true, connection: {} }) });
  };
  const location = { href: "https://crow.example.ts.net/dashboard/project/spring/services", reload() { /* no reload */ } };
  window.crowCsrf = () => "csrf-abc";
  window.location = location;
  window.confirm = () => true;
  window.HTMLElement.prototype.focus = function () { /* no focus in this environment */ };
  const consoleStub = { log() {}, warn() {}, error() {} };
  const ctx = vm.createContext({ window, document, location, fetch: fetchStub, URL, console: consoleStub });
  vm.runInContext(CLIENT_JS, ctx);
  const click = (el) => el.dispatchEvent(new window.Event("click", { bubbles: true }));
  const sheet = () => document.querySelector("[data-svc-sheet]");
  return { window, document, click, calls, sheet };
}

test("test_connect_screen_links_to_panel", async () => {
  const data = projectServicesData(panelPage(), "en");
  assert.equal(data.groups.paste[0].panelRoute, PANEL_ROUTE, "the page data carries the panel route");

  const s = boot(panelPage());
  s.click(s.document.querySelector(".svc-add"));
  assert.ok(s.sheet(), "the Add view opened");
  const pick = s.sheet().querySelector('[data-svc-connect="panelfix"]');
  assert.ok(pick, "the Add view offers the panel service");
  s.click(pick);

  const links = s.sheet().querySelectorAll("a.svc-panel-link");
  assert.equal(links.length, 1, "exactly one panel link");
  assert.equal(links[0].getAttribute("href"), PANEL_ROUTE);
  assert.equal(links[0].textContent, "Connect in Panel Fixture");
  assert.equal(links[0].getAttribute("target"), null, "the link opens in the same tab");
  assert.equal(s.sheet().querySelectorAll("input").length, 0, "no inputs in a panel connect view");
  assert.equal(s.sheet().querySelector(".svc-submit"), null, "no Connect and test button");
  const buttons = [...s.sheet().querySelectorAll("button")].filter((b) => /connect|test/i.test(b.textContent || ""));
  assert.deepEqual(buttons.map((b) => b.textContent), [], "no button offers a generic connect");
  assert.equal(s.calls.length, 0, "opening a panel connection posts nothing");

  // The page's own card: the route travels to the browser, a value never does.
  const ctx = await freshDb();
  const page = await withDbPath(ctx.path, (d) => loadServicesPage(d, "spring", { installedIds: new Set(["panelfix"]), crowHome: HOME }));
  const cards = Object.values(page.groups).flat();
  const card = cards.find((c) => c.serviceId === "panelfix");
  assert.ok(card, "the panel service is on the page");
  assert.equal(card.panelRoute, PANEL_ROUTE);
  assert.deepEqual(card.fields, []);
  const gh = cards.find((c) => c.serviceId === "github");
  assert.equal(gh.panelRoute, undefined, "only a panel service carries a panel route");
  for (const canary of CANARIES) assert.ok(!JSON.stringify(page).includes(canary), "the page carries no value");
});

// ---- 9. every existing method is unchanged ----------------------------------------------------

test("test_existing_methods_unchanged", async () => {
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  ctx.test = fakeTest();

  // createConnection plus a real child, as today.
  const gh = await connectBound(ctx, "github", { projectId: pid, label: "work", secrets: { [GH]: "test-token-9" } });
  assert.equal(gh.status, "active");
  const before = spawnCount();
  const got = await withDbPath(ctx.path, (d) => C.ensureChild(d, gh.uuid, { crowHome: HOME }));
  assert.equal(spawnCount(), before + 1, "a github connection still starts its child");
  const who = JSON.parse((await got.client.callTool({ name: "whoami", arguments: {} })).content[0].text);
  assert.ok(who.keys.includes(GH));
  await C.stopAllChildren();

  // notion still connects and still gets its derived header.
  const nt = await connectBound(ctx, "notion", { projectId: pid, label: "work", secrets: { [NOTION_TOKEN]: "test-token-11" } });
  assert.equal(nt.status, "active");
  const beforeNotion = spawnCount();
  const notionChild = await withDbPath(ctx.path, (d) => C.ensureChild(d, nt.uuid, { crowHome: HOME }));
  assert.equal(spawnCount(), beforeNotion + 1);
  const headers = JSON.parse((await notionChild.client.callTool({ name: "envhash", arguments: { name: "OPENAPI_MCP_HEADERS" } })).content[0].text);
  assert.equal(headers.present, true);
  await C.stopAllChildren();

  const offered = await withDbPath(ctx.path, (d) => C.offerableProjectConnections(d, pid));
  assert.deepEqual(offered.map((c) => c.serviceId).sort(), ["github", "notion"]);

  // The generic connect route and Test again, unchanged.
  await withApp(ctx, async (s) => {
    const c = await call(s, "POST", "/dashboard/services/api/project/spring/connect", {
      body: { serviceId: "github", accountLabel: "Route", values: { [GH]: "test-token-12" } },
      headers: AUTH,
    });
    assert.equal(c.status, 201, c.text);
    assert.equal(c.json.ok, true);
    assert.equal(c.json.connection.status, "active");
    assert.deepEqual(c.json.connection.fields, { [GH]: "set" });
    assert.deepEqual(c.json.connection.private, { on: false, locked: false });
    const t = await call(s, "POST", `/dashboard/services/api/connection/${c.json.connection.uuid}/test`, { headers: AUTH, body: {} });
    assert.equal(t.status, 200, t.text);
    assert.deepEqual(t.json, { ok: true, status: "active" });
    const page = await call(s, "GET", "/dashboard/services/api/project/spring", { headers: AUTH });
    assert.equal(page.status, 200);
    assert.ok(page.json.connections.some((x) => x.serviceId === "github"));
  });
  assert.equal(ctx.test.calls.length, 2, "the live test ran for the connect and for Test again");

  // The saved key still works for a one-click service.
  assert.equal(isOneClickEligible(CAT.serviceById("github")), true);
  const savedIds = await withDbPath(ctx.path, (d) => savedKeyServiceIds(d, CAT.serviceCatalog(), new Set(BUNDLES)));
  assert.ok(savedIds.has("github"), "the typed connect remembered the key");

  // A non-panel manifest still needs its fields and steps, with the same message as before.
  const noSteps = tokenManifest();
  delete noSteps.connect.steps;
  const r = checkToken(noSteps);
  assert.equal(r.ok, false);
  assert.ok(r.errors.includes("shape /connect must have required property 'steps'"), r.errors.join("; "));
});