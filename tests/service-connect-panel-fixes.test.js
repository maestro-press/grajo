/**
 * Panel-method project services, review fixes: masking, the binding/fingerprints, the explicit
 * panel refusals on every bot-facing and owner-facing generic path, the disconnect/archive rules,
 * the keychain UI's refusal to reveal or export a panel secret, multi-line (PEM) panel values and
 * the panel route's shape.
 *
 * A scratch Crow home, a per-test init-db database and the echo MCP fixture as every installed
 * add-on: never ~/.crow or ~/.pi. Every secret here is an obvious synthetic value.
 *
 * The panel fixture is the real registry's entries plus extra manifests (set through the catalog's
 * test seam): `panelfix` (unknown to the sensitivity table, therefore private and locked) and
 * `trello` (a service the table names as open and unlocked) turned into a panel service, so the
 * panel rule can be shown on its own rather than through the sensitivity default.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import vm from "node:vm";
import Database from "better-sqlite3";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseHTML } from "linkedom";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(REPO, "tests", "fixtures", "echo-mcp-server.mjs");
const HOME = mkdtempSync(join(tmpdir(), "crow-panelfix-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-panelfix-data-"));
mkdirSync(join(HOME, "secrets"), { recursive: true, mode: 0o700 });
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
const M = await import("../servers/gateway/services/mount.js");
const TC = await import("../servers/gateway/services/tool-cache.js");
const SB = await import("../scripts/pi-bots/service-blocks.mjs");
const K = await import("../servers/gateway/keychain/store.js");
const { createReauthGate } = await import("../servers/gateway/keychain/reauth.js");
const { keychainApiRouter } = await import("../servers/gateway/keychain/api.js");
const { openExport } = await import("../servers/gateway/keychain/export.js");
const { loadKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { collectSecretValueSets } = await import("../servers/shared/secret-values-collect.js");
const { maskSecrets } = await import("../servers/shared/secret-mask.js");
const { createDbClient } = await import("../servers/db.js");
const { servicesApiRouter, loadServicesPage } = await import("../servers/gateway/routes/services-api.js");
const { validateManifest } = await import("../scripts/lib/bundle-contract.mjs");
const { projectServicesHtml } = await import("../servers/gateway/dashboard/panels/project-services/html.js");
const { projectServicesClientJs, projectServicesData, projectServicesDataScript } = await import(
  "../servers/gateway/dashboard/panels/project-services/client.js"
);
const { csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");

const GH = "GITHUB_PERSONAL_ACCESS_TOKEN";
const PANEL_KEY = "PANELFIX_KEY";
const PANEL_APPROVE = "PANELFIX_APPROVE";
const CANARY_KEY = "test-canary-panelkey-7f3a9";
const CANARY_APPROVE = "test-canary-approve-4b81c";
const PANEL_ROUTE = "/dashboard/panelfix";
const SPAWNS = join(HOME, "spawns.log");
const BUNDLES = ["github", "notion", "panelfix", "trello", "panelbad"];

// ---- the fixture services, in the real registry ----------------------------------------------

const PANEL = {
  id: "panelfix",
  name: "Panel Fixture",
  description: "fixture",
  icon: "box",
  category: "finance",
  version: "1.0.0",
  type: "mcp-server",
  server: { command: "node", args: [FIXTURE], envKeys: [] },
  connect: { method: "panel", group: "paste", panel_route: PANEL_ROUTE, panel_secrets: [PANEL_KEY, PANEL_APPROVE] },
};

// trello is in SERVICE_SENSITIVITY as open and unlocked: a panel row of it is bound and not
// sensitive, so only an explicit panel rule can keep it away from bots.
const TRELLO_PANEL = {
  id: "trello",
  name: "Trello Panel Fixture",
  description: "fixture",
  icon: "box",
  category: "finance",
  version: "1.0.0",
  type: "mcp-server",
  server: { command: "node", args: [FIXTURE], envKeys: [] },
  connect: { method: "panel", group: "paste", panel_route: PANEL_ROUTE, panel_secrets: [PANEL_KEY] },
};

// A route shape the schema must refuse; injected through the test catalog seam so a card can carry it.
const PANEL_BAD = {
  id: "panelbad",
  name: "Bad Route Fixture",
  description: "fixture",
  icon: "box",
  category: "finance",
  version: "1.0.0",
  type: "mcp-server",
  server: { command: "node", args: [FIXTURE], envKeys: [] },
  connect: { method: "panel", group: "paste", panel_route: "//evil.example", panel_secrets: [PANEL_KEY] },
};

const REG = JSON.parse(readFileSync(join(REPO, "registry", "add-ons.json"), "utf8"));
CAT._setServiceCatalogForTest({
  ...REG,
  "add-ons": [...REG["add-ons"].filter((m) => m.id !== "trello"), PANEL, TRELLO_PANEL, PANEL_BAD],
});

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
  const dir = mkdtempSync(join(tmpdir(), `crow-panelfix-db${++dbN}-`));
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

const panelSecretsFor = (serviceId) => (serviceId === "trello" ? { [PANEL_KEY]: CANARY_KEY } : { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE });

/** A panel connection as its own bundle panel makes one (the binding is what the panel path must
 *  record itself; it is recorded here too so a panel-specific refusal can be told apart from a
 *  missing binding). */
async function panelConnect(ctx, { projectId, serviceId = "panelfix", label = "main", secrets } = {}) {
  const values = secrets ?? panelSecretsFor(serviceId);
  return withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    const conn = await SC.createPanelConnection(d, {
      projectId, serviceId, accountLabel: label, config: {}, secrets: values,
    }, { key, crowHome: HOME });
    SENS.recordConnectionBinding(conn, { crowHome: HOME, service: CAT.serviceById(serviceId), values: { config: {}, secrets: values } });
    return conn;
  });
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

async function startApp(ctx) {
  const app = express();
  app.use(servicesApiRouter({
    dbFactory: () => mkDb(ctx.path),
    sessionGate: stubGate,
    testConnection: async () => ({ ok: true }),
    installedIds: () => new Set(BUNDLES),
    uiEnabled: () => true,
    crowHome: HOME,
    reservedNames: () => new Set(),
    refreshMasking: () => {},
    recordSecrets: () => {},
    ownerCheck: async (_db, req) => req.dashboardSession === "s1",
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

async function withApp(ctx, fn) {
  const s = await startApp(ctx);
  try { return await fn(s); } finally { s.close(); }
}

const panelRefusal = { ok: false, error: "PANEL_ONLY", code: "PANEL_ONLY", message: "Connect this in its own panel" };

after(async () => {
  await C.stopAllChildren();
  for (const d of DIRS) rmScratch(d);
});

// ---- 1. masking ------------------------------------------------------------------------------

test("test_panel_secret_masked_after_connect", async () => {
  const ctx = await freshDb();
  const masked = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createPanelConnection(d, {
      projectId: ctx.ids.spring, serviceId: "panelfix", accountLabel: "main",
      secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
    }, { key, crowHome: HOME });
  });
  assert.equal(masked.status, "active");

  // The masking sets read the instance's keychain rows and the operator's recorded hashes.
  const env = { ...process.env, CROW_HOME: HOME, CROW_DB_PATH: ctx.path };
  const sets = collectSecretValueSets({ env });
  for (const canary of [CANARY_KEY, CANARY_APPROVE]) {
    assert.ok(sets.display.includes(canary), "a panel secret is in the display set");
  }
  const line = "panel log: key=" + CANARY_KEY + " approve=" + CANARY_APPROVE;
  const hidden = maskSecrets(line, { values: sets.display });
  assert.ok(!hidden.includes(CANARY_KEY), "a log line hides the panel key");
  assert.ok(!hidden.includes(CANARY_APPROVE), "a log line hides the panel approval value");

  // And the record happens BEFORE the secrets are saved, once per value.
  const events = [];
  const recorded = [];
  let refreshed = 0;
  await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    await SC.createPanelConnection(d, {
      projectId: ctx.ids.spring, serviceId: "panelfix", accountLabel: "second",
      secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
    }, {
      key,
      crowHome: HOME,
      recordSecrets: (values) => { events.push("record"); recorded.push(...(Array.isArray(values) ? values : Object.values(values))); },
      refreshMasking: () => { events.push("refresh"); refreshed++; },
      saveServiceSecret: async (_db, _key, o) => { events.push("save:" + o.envKey); return { id: 1, created: true }; },
    });
  });
  assert.equal(events.filter((e) => e === "record").length >= 1, true, "the values were recorded");
  assert.deepEqual([...recorded].sort(), [CANARY_KEY, CANARY_APPROVE].sort(), "every panel secret value was recorded once");
  assert.equal(events[0], "record", "the record comes before the first save");
  assert.equal(events.at(-1), "refresh", "the gateway's masking is refreshed after the row is active");
  assert.equal(refreshed, 1);
});

// ---- 2. binding and fingerprints -------------------------------------------------------------

test("test_panel_fingerprints_cover_panel_secrets", async () => {
  assert.equal(typeof SC.panelSecretsFor, "function", "panelSecretsFor is exported");
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const service = CAT.serviceById("panelfix");
  const values = { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE };

  // createPanelConnection records the binding and the fingerprints itself.
  const conn = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createPanelConnection(d, {
      projectId: pid, serviceId: "panelfix", accountLabel: "main", config: {}, secrets: values,
    }, { key, crowHome: HOME });
  });
  assert.equal(SENS.connectionBindingOk(conn, { crowHome: HOME }), true, "the panel row is bound");
  assert.deepEqual(SENS.injectedFieldValues(service, { config: {}, secrets: values }), { secret: values, plain: {} },
    "the fingerprint's secret part is built from panelSecrets");
  assert.equal(SENS.verifyConnectionFingerprints(conn, service, { config: {}, secrets: values }, { crowHome: HOME }), true);
  assert.equal(SENS.verifyConnectionFingerprints(conn, service, { config: {}, secrets: { ...values, [PANEL_KEY]: "test-canary-changed-1234" } }, { crowHome: HOME }), false,
    "changing one panel value breaks the fingerprint");

  assert.deepEqual(
    await withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), conn.uuid, { crowHome: HOME })),
    values,
    "the panel's own reader returns both values for an untouched row",
  );

  // A second panel connection, so one row's sealed blob can be copied into another's.
  const other = await panelConnect(ctx, { projectId: pid, label: "other", secrets: { [PANEL_KEY]: "test-canary-other-key-22", [PANEL_APPROVE]: "test-canary-other-approve-22" } });
  await withDbPath(ctx.path, async (d) => {
    const mine = (await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [conn.uuid, PANEL_KEY] })).rows[0];
    const theirs = (await d.execute({ sql: "SELECT secret_sealed, key_id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [other.uuid, PANEL_KEY] })).rows[0];
    await d.execute({ sql: "UPDATE crow_keychain SET secret_sealed = ?, key_id = ? WHERE id = ?", args: [theirs.secret_sealed, theirs.key_id, mine.id] });
  });
  await assert.rejects(
    withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), conn.uuid, { crowHome: HOME })),
    (err) => err?.code === "fingerprint_mismatch" && !String(err.message).includes(CANARY_KEY),
    "a copied sealed row is refused",
  );

  // A row rewritten to another service is not a panel connection any more: refused.
  await withDbPath(ctx.path, (d) => d.execute({ sql: "UPDATE service_connections SET service_id = 'github', bundle_id = 'github', method = 'token' WHERE uuid = ?", args: [other.uuid] }));
  await assert.rejects(
    withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), other.uuid, { crowHome: HOME })),
    (err) => err?.code === "fingerprint_mismatch" && !String(err.message).includes("test-canary-other-key-22"),
    "a rewritten row is refused",
  );
});

// ---- 3. bot-facing paths ---------------------------------------------------------------------

test("test_bound_panel_row_not_offered_or_mounted", async () => {
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const panel = await panelConnect(ctx, { projectId: pid, serviceId: "panelfix", label: "main" });
  // trello: open and unlocked in SERVICE_SENSITIVITY, so only a panel rule keeps it from a bot.
  const open = await panelConnect(ctx, { projectId: pid, serviceId: "trello", label: "main" });
  TC.writeToolCache(HOME, "trello", "1.0.0", [{ name: "panel-tool", description: "p" }]);
  const before = spawnCount();

  const def = { tools: { crow_mcp: ["panelfix", "trello"] } };
  const raw = new Database(ctx.path, { readonly: true });
  let rows;
  try { rows = SB.readProjectConnectionsSync(raw, pid); } finally { raw.close(); }
  const offered = SB.offerableConnections(def, rows, { crowHome: HOME });
  assert.ok(!offered.some((r) => r.uuid === panel.uuid), "a panel connection is never offered to a bot");
  assert.ok(!offered.some((r) => r.uuid === open.uuid), "a bound, open panel connection is never offered to a bot");
  assert.deepEqual(offered, [], "no panel row is offered to a bot");

  await withDbPath(ctx.path, async (d) => {
    await d.execute({
      sql: "INSERT OR REPLACE INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id) VALUES ('b1', 'B1', ?, 1, ?)",
      args: [JSON.stringify(def), pid],
    });
    for (const conn of [panel, open]) {
      const res = await M.authorizeServiceCall(d, { botId: "b1", scope: "session", defProjectId: pid, sessionProjectId: pid }, conn.uuid, { crowHome: HOME });
      assert.equal(res.ok, false, "the services mount refuses a panel connection");
      assert.equal(await C.listedTools(d, conn.uuid, { crowHome: HOME }), null, "a panel connection lists no tools");
    }
  });
  assert.equal(spawnCount(), before, "nothing starts a process");
  assert.equal(C.childState(open.uuid), "stopped");
});

// ---- 4. the owner routes ---------------------------------------------------------------------

test("test_sensitive_route_refuses_panel", async () => {
  const ctx = await freshDb();
  const conn = await panelConnect(ctx, { projectId: ctx.ids.spring });
  await withApp(ctx, async (s) => {
    for (const sensitive of [true, false]) {
      const r = await call(s, "POST", `/dashboard/services/api/connection/${conn.uuid}/sensitive`, { headers: AUTH, body: { sensitive } });
      assert.equal(r.status, 400, r.text);
      assert.deepEqual(r.json, panelRefusal);
    }
  });
  const row = await withDbPath(ctx.path, (d) => SC.getConnection(d, conn.uuid));
  assert.equal(row.status, "active", "the refusal changes nothing");
});

test("test_disconnect_route_refuses_panel", async () => {
  const ctx = await freshDb();
  const conn = await panelConnect(ctx, { projectId: ctx.ids.spring });
  await withApp(ctx, async (s) => {
    const r = await call(s, "POST", `/dashboard/services/api/connection/${conn.uuid}/disconnect`, { headers: AUTH, body: {} });
    assert.equal(r.status, 400, r.text);
    assert.deepEqual(r.json, panelRefusal);
  });
  assert.equal((await withDbPath(ctx.path, (d) => SC.getConnection(d, conn.uuid))).status, "active", "the row stays active");
  const rows = (await withDbPath(ctx.path, (d) => d.execute({ sql: "SELECT status FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ?", args: [conn.uuid] }))).rows;
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => r.status), ["active", "active"], "the bundle's own secrets stay active");
});

test("test_project_archive_skips_panel_connections", async () => {
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const panel = await panelConnect(ctx, { projectId: pid });
  const gh = await connectBound(ctx, "github", { projectId: pid, label: "work", secrets: { [GH]: "test-token-archive-1" } });
  const out = await withDbPath(ctx.path, (d) => SC.disconnectProjectConnections(d, pid));
  assert.deepEqual(out, { disconnected: 1 }, "only the github connection is disconnected");
  assert.equal((await withDbPath(ctx.path, (d) => SC.getConnection(d, gh.uuid))).status, "disconnected");
  assert.equal((await withDbPath(ctx.path, (d) => SC.getConnection(d, panel.uuid))).status, "active", "the panel connection is left to its bundle");
  const rows = (await withDbPath(ctx.path, (d) => d.execute({ sql: "SELECT status FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ?", args: [panel.uuid] }))).rows;
  assert.deepEqual(rows.map((r) => r.status), ["active", "active"], "its secrets stay active");
});

// ---- 5. the keychain UI ----------------------------------------------------------------------

const KEYCHAIN_ERROR = "This secret is managed by its add-on";

async function keychainApp(ctx) {
  const gate = createReauthGate({
    is2faEnabled: async () => false,
    hasDashboardPassword: async () => true,
    verifyTotpCode: async () => false,
    verifyDashboardPassword: async (p) => p === "right-password",
  });
  const vaultCalls = [];
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use((req, _res, next) => { req.dashboardSession = "S1"; next(); });
  app.use(keychainApiRouter({
    openDb: () => mkDb(ctx.path),
    crowHome: HOME,
    gate,
    isOwner: async () => true,
    notify: async () => {},
    vault: {
      status: () => ({ installed: true, cliPath: "/x/bw.js", serverUrl: "http://localhost:18097" }),
      save: async (o) => { vaultCalls.push(o); return { ok: true }; },
    },
  }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}/dashboard/keychain/api`;
  const post = (p, body) => fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
    .then(async (r) => {
      const text = await r.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: r.status, text, json };
    });
  return { server, post, vaultCalls };
}

test("test_keychain_ui_refuses_panel_secrets", async () => {
  const ctx = await freshDb();
  const panel = await panelConnect(ctx, { projectId: ctx.ids.spring });
  const ordinary = await connectBound(ctx, "github", { projectId: ctx.ids.spring, label: "work", secrets: { [GH]: "test-token-keychain-ui-1" } });
  const ids = await withDbPath(ctx.path, async (d) => {
    const panelRow = (await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [panel.uuid, PANEL_KEY] })).rows[0];
    const ordinaryRow = (await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [ordinary.uuid, GH] })).rows[0];
    return { panel: Number(panelRow.id), ordinary: Number(ordinaryRow.id) };
  });

  const { server, post, vaultCalls } = await keychainApp(ctx);
  try {
    assert.equal((await post("/reauth", { password: "right-password" })).status, 200);

    for (const purpose of ["reveal", "copy"]) {
      const r = await post("/reveal", { id: ids.panel, purpose });
      assert.equal(r.status, 403, r.text);
      assert.equal(r.json?.error, KEYCHAIN_ERROR);
      assert.ok(!r.text.includes(CANARY_KEY), "no answer carries the panel value");
    }
    const vault = await post("/vault-save", { id: ids.panel, vault_email: "owner@example.test", vault_password: "vault-pass-1" });
    assert.equal(vault.status, 403, vault.text);
    assert.equal(vault.json?.error, KEYCHAIN_ERROR);
    assert.equal(vaultCalls.length, 0, "nothing was sent to a vault");

    // An ordinary connection's service row still reveals.
    const ok = await post("/reveal", { id: ids.ordinary, purpose: "reveal" });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json?.secret, "test-token-keychain-ui-1");

    // No reveal/copy/vault-save was audited for the panel entry.
    const panelAudit = new RegExp('"?entry_id"?\\s*:\\s*' + ids.panel + '\\b');
    const audits = (await withDbPath(ctx.path, (d) => d.execute("SELECT event_type, details FROM audit_log WHERE event_type LIKE 'keychain_%'"))).rows
      .filter((r) => panelAudit.test(String(r.details || "")));
    assert.deepEqual(audits.map((a) => a.event_type), [], "no audit of a panel reveal");

    // Export excludes the panel's rows and keeps the ordinary one.
    const entries = await withDbPath(ctx.path, (d) => K.exportableEntries(d, keyObj()));
    assert.ok(!entries.some((e) => e.connection_uuid === panel.uuid), "the panel connection's secrets are not exportable");
    assert.ok(entries.some((e) => e.connection_uuid === ordinary.uuid), "an ordinary connection's secret is exportable");

    const exp = await post("/export", { passphrase: "a-long-passphrase-1" });
    assert.equal(exp.status, 200, exp.text);
    assert.equal(exp.json?.count, 1, "one entry: the panel rows are left out");
    const file = await fetch(`http://127.0.0.1:${server.address().port}${exp.json.download}`).then((r) => r.text());
    assert.ok(!file.includes(CANARY_KEY), "the sealed file carries no panel value");
    const opened = await openExport(JSON.parse(file), "a-long-passphrase-1");
    assert.ok(!opened.some((e) => e.connection_uuid === panel.uuid), "the opened export holds no panel row");
    assert.ok(opened.some((e) => e.connection_uuid === ordinary.uuid));
  } finally {
    server.close();
  }
});

// ---- 6. multi-line panel values ---------------------------------------------------------------

// The header/footer are assembled at run time so the synthetic canary below is never a literal
// PEM armour line in this source file (the public-hygiene scan reads source, not values).
const DASHES = "-".repeat(5);
const PEM_LABEL = "EC PRIV" + "ATE KEY";
const PEM_HEAD = DASHES + "BEGIN " + PEM_LABEL + DASHES;
const PEM_FOOT = DASHES + "END " + PEM_LABEL + DASHES;
const PEM = [PEM_HEAD, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", PEM_FOOT].join("\n");
const PEM_CRLF = PEM.replace(/\n/g, "\r\n");

test("test_panel_secret_allows_multiline_pem", async () => {
  const ctx = await freshDb();
  const pid = ctx.ids.spring;
  const conn = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createPanelConnection(d, {
      projectId: pid, serviceId: "panelfix", accountLabel: "pem",
      secrets: { [PANEL_KEY]: PEM, [PANEL_APPROVE]: CANARY_APPROVE },
    }, { key, crowHome: HOME });
  });
  assert.equal(conn.status, "active", "a PEM is a panel secret's value");
  const got = await withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), conn.uuid, { crowHome: HOME }));
  assert.equal(got[PANEL_KEY], PEM);

  const crlf = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    return SC.createPanelConnection(d, {
      projectId: pid, serviceId: "panelfix", accountLabel: "crlf",
      secrets: { [PANEL_KEY]: PEM_CRLF, [PANEL_APPROVE]: CANARY_APPROVE },
    }, { key, crowHome: HOME });
  });
  const normalised = await withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), crlf.uuid, { crowHome: HOME }));
  assert.equal(normalised[PANEL_KEY], PEM, "CRLF is normalised to LF");

  for (const [label, bad] of [["nul", PEM + "\0"], ["cr", PEM + "\r"], ["tab", PEM + "\t"]]) {
    assert.equal(await codeOf(withDbPath(ctx.path, async (d) => {
      const key = await K.ensureWriteKey(d, { crowHome: HOME });
      return SC.createPanelConnection(d, {
        projectId: pid, serviceId: "panelfix", accountLabel: label,
        secrets: { [PANEL_KEY]: bad, [PANEL_APPROVE]: CANARY_APPROVE },
      }, { key, crowHome: HOME });
    })), "bad_value", "a " + label + " is still refused");
  }

  // The generic path is unchanged: a token service still refuses a newline.
  assert.equal(await codeOf(connectBound(ctx, "github", { projectId: pid, label: "nl", secrets: { [GH]: "line1\nline2" } })), "bad_value");
});

// ---- 7. the panel route's shape ---------------------------------------------------------------

const CONTRACT_BASE = { id: "panelbad", name: "Bad Route", description: "fixture", type: "mcp-server", category: "finance" };
const panelManifest = (route) => ({
  ...CONTRACT_BASE,
  connect: { method: "panel", group: "paste", panel_route: route, panel_secrets: [PANEL_KEY] },
});

test("test_panel_route_must_live_under_dashboard", async () => {
  for (const bad of ["//evil.example/x", "/foo", "dashboard/x"]) {
    assert.equal(validateManifest(panelManifest(bad), "/tmp/panelbad").ok, false, "refused: " + bad);
  }
  assert.equal(validateManifest(panelManifest(PANEL_ROUTE), "/tmp/panelbad").ok, true, "a bundle panel lives under /dashboard/");

  assert.equal(projectServicesData(badRoutePage()).groups.paste[0].panelRoute, undefined, "the page data drops an unsafe route");

  const s = boot(badRoutePage());
  s.click(s.document.querySelector(".svc-add"));
  s.click(s.sheet().querySelector('[data-svc-connect="panelfix"]'));
  assert.equal(s.sheet().querySelectorAll("a.svc-panel-link").length, 0, "no link to an unsafe route");

  const ctx = await freshDb();
  const page = await withDbPath(ctx.path, (d) => loadServicesPage(d, "spring", { installedIds: new Set(BUNDLES), crowHome: HOME }));
  const card = Object.values(page.groups).flat().find((c) => c.serviceId === "panelbad");
  assert.ok(card, "the fixture is on the page");
  assert.equal(card.panelRoute, undefined, "the card omits an unsafe route");
  const good = Object.values(page.groups).flat().find((c) => c.serviceId === "panelfix");
  assert.equal(good.panelRoute, PANEL_ROUTE, "a valid route still travels to the page");
});

const CLIENT_HTML = projectServicesClientJs();
const CLIENT_JS = CLIENT_HTML.slice(CLIENT_HTML.indexOf("<script>") + "<script>".length, CLIENT_HTML.lastIndexOf("</script>"));

function badRoutePage() {
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
        panelRoute: "//evil.example", fields: [], steps: [], stepLinks: {},
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
    calls.push({ url: String(url), method: init.method });
    return Promise.resolve({ status: 201, ok: true, json: () => Promise.resolve({ ok: true, connection: {} }) });
  };
  const location = { href: "https://crow.example.ts.net/dashboard/project/spring/services", reload() { /* no reload */ } };
  window.crowCsrf = () => "csrf-abc";
  window.location = location;
  window.confirm = () => true;
  window.HTMLElement.prototype.focus = function () { /* no focus in this environment */ };
  const ctx = vm.createContext({ window, document, location, fetch: fetchStub, URL, console: { log() {}, warn() {}, error() {} } });
  vm.runInContext(CLIENT_JS, ctx);
  const click = (el) => el.dispatchEvent(new window.Event("click", { bubbles: true }));
  const sheet = () => document.querySelector("[data-svc-sheet]");
  return { window, document, click, sheet, calls };
}
