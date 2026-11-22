/**
 * Panel-method project services, review fixes round 2: a permanent project delete is refused while
 * a panel connection is active (its keychain rows are the bundle panel's, so purging the connection
 * row would orphan them), the keychain UI guard fails closed for an orphaned or re-pointed panel
 * row, panelSecretsFor reads the connection row itself instead of trusting a caller's object, and a
 * connect whose binding cannot be recorded leaves no connection row, no keychain row and no
 * service.connect audit row.
 *
 * A scratch Crow home, a per-test init-db database and the echo MCP fixture as every installed
 * add-on: never the real ~/.crow or ~/.pi. Every secret here is an obvious synthetic value.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(REPO, "tests", "fixtures", "echo-mcp-server.mjs");
const HOME = mkdtempSync(join(tmpdir(), "crow-panel-lc-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-panel-lc-data-"));
mkdirSync(join(HOME, "secrets"), { recursive: true, mode: 0o700 });
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = DATA;
delete process.env.CROW_DB_PATH;
process.env.CROW_AUTO_UPDATE = "0";
process.env.CROW_DISABLE_HEALTH_MONITOR = "1";
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_DISABLE_NOSTR = "1";
delete process.env.CROW_SERVICES_UI;

const CAT = await import("../servers/shared/service-catalog.js");
const SC = await import("../servers/shared/service-connections.js");
const SENS = await import("../servers/shared/service-sensitivity.js");
const L = await import("../servers/shared/project-lifecycle.js");
const K = await import("../servers/gateway/keychain/store.js");
const { anchoredPath, readSecretValuesFile, writeSecretValuesFile } = await import("../servers/shared/secret-values.js");
const { createReauthGate } = await import("../servers/gateway/keychain/reauth.js");
const { keychainApiRouter } = await import("../servers/gateway/keychain/api.js");
const { loadKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { createDbClient } = await import("../servers/db.js");

const GH = "GITHUB_PERSONAL_ACCESS_TOKEN";
const PANEL_KEY = "PANELFIX_KEY";
const PANEL_APPROVE = "PANELFIX_APPROVE";
const CANARY_KEY = "test-canary-lc-panelkey-9137b";
const CANARY_APPROVE = "test-canary-lc-approve-2c46d";
const OTHER_KEY = "test-canary-lc-other-key-58a2e";
const OTHER_APPROVE = "test-canary-lc-other-approve-71f0b";
const GH_TOKEN = "test-token-lc-github-4";
const MANUAL_SECRET = "test-manual-lc-secret-9";
const PANEL_ROUTE = "/dashboard/panelfix";
const SPAWNS = join(HOME, "spawns.log");
const BUNDLES = ["github", "panelfix"];
const KEYCHAIN_ERROR = "This secret is managed by its add-on";

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
  connect: { method: "panel", group: "paste", panel_route: PANEL_ROUTE, panel_secrets: [PANEL_KEY, PANEL_APPROVE] },
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

// ---- databases, projects, connections ---------------------------------------------------------

const DIRS = [HOME, DATA];
const mkDb = (path) => createDbClient(path);
async function withDbPath(path, fn) {
  const d = mkDb(path);
  try { return await fn(d); } finally { d.close(); }
}

let dbN = 0;
async function freshDb() {
  const dir = mkdtempSync(join(tmpdir(), `crow-panel-lc-db${++dbN}-`));
  DIRS.push(dir);
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe", cwd: REPO });
  return { path: join(dir, "crow.db"), dir };
}

/** A project with its local-owner member row (the owner rule the delete asks for). */
async function mkProject(ctx, name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return withDbPath(ctx.path, async (d) => {
    const r = await d.execute({ sql: "INSERT INTO project_spaces (slug, name) VALUES (?, ?) RETURNING id", args: [slug, name] });
    const id = Number(r.rows[0].id);
    await d.execute({ sql: "INSERT INTO project_members (project_id, contact_id, role) VALUES (?, NULL, 'owner')", args: [id] });
    return id;
  });
}

const panelSecrets = () => ({ [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE });

/** A panel connection plus the binding and fingerprints the panel's own connect path records. */
async function panelConnect(ctx, { projectId, serviceId = "panelfix", label = "main", secrets } = {}) {
  const values = secrets ?? panelSecrets();
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

/** A project delete as the dashboard drives it; nothing here reaches storage or a backend. */
const del = (db, id, name) => L.deleteProject(db, id, {
  confirmName: name, storageDelete: async () => {}, disconnectBackend: () => true,
});

// ---- the keychain UI harness ------------------------------------------------------------------

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

/** The panel connection's entry in the owner's connection bindings file, removed the way a
 *  missing binding reads (one anchored JSON line, through the module's own writer). */
async function removeBinding(uuid) {
  const p = anchoredPath({ ...process.env, CROW_HOME: HOME }, SENS.CONNECTION_BINDINGS_FILENAME);
  const file = readSecretValuesFile(p, { raw: true });
  const map = JSON.parse(file.lines[0]);
  delete map[uuid];
  writeSecretValuesFile(p, [JSON.stringify(map)], { raw: true });
}

after(async () => {
  for (const d of DIRS) rmScratch(d);
});

// ---- 1. a project delete refuses while a panel connection is active ---------------------------

test("test_project_delete_refused_with_active_panel_connection", async () => {
  const ctx = await freshDb();
  const held = await mkProject(ctx, "Panel Held");
  const panel = await panelConnect(ctx, { projectId: held });

  const summary = await withDbPath(ctx.path, (d) => L.deleteSummary(d, held));
  assert.deepEqual(summary.blocked, { code: "panel_connected", detail: "Disconnect Panel Fixture in its panel first" });

  const refused = await withDbPath(ctx.path, (d) => del(d, held, "Panel Held"));
  assert.equal(refused.ok, false);
  assert.equal(refused.code, "panel_connected");
  assert.equal(refused.detail, "Disconnect Panel Fixture in its panel first");

  await withDbPath(ctx.path, async (d) => {
    const row = await SC.getConnection(d, panel.uuid);
    assert.ok(row, "the panel connection row is still there");
    assert.equal(row.status, "active", "it is still active");
    const keys = (await d.execute({
      sql: "SELECT status FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? ORDER BY id",
      args: [panel.uuid],
    })).rows;
    assert.equal(keys.length, 2, "both panel secrets are still there");
    assert.deepEqual(keys.map((r) => r.status), ["active", "active"], "both stay active");
    const project = (await d.execute({ sql: "SELECT status, archived_at FROM project_spaces WHERE id = ?", args: [held] })).rows[0];
    assert.equal(project.archived_at, null, "the project is not a tombstone");
    assert.notEqual(project.status, "archived");
  });

  // A project with only an ordinary connection still deletes.
  const plain = await mkProject(ctx, "GitHub Only");
  const gh = await connectBound(ctx, "github", { projectId: plain, secrets: { [GH]: GH_TOKEN } });
  const gone = await withDbPath(ctx.path, (d) => del(d, plain, "GitHub Only"));
  assert.equal(gone.ok, true, JSON.stringify(gone));
  await withDbPath(ctx.path, async (d) => {
    assert.equal(await SC.getConnection(d, gh.uuid), null, "the ordinary connection's row is purged");
    const tomb = (await d.execute({ sql: "SELECT archived_at FROM project_spaces WHERE id = ?", args: [plain] })).rows[0];
    assert.ok(tomb.archived_at, "the project was deleted");
  });

  // Disconnected through the store, the delete proceeds.
  await withDbPath(ctx.path, (d) => SC.disconnectConnection(d, panel.uuid));
  const after = await withDbPath(ctx.path, (d) => L.deleteSummary(d, held));
  assert.equal(after.blocked, null);
  const released = await withDbPath(ctx.path, (d) => del(d, held, "Panel Held"));
  assert.equal(released.ok, true, JSON.stringify(released));
  await withDbPath(ctx.path, async (d) => {
    assert.equal(await SC.getConnection(d, panel.uuid), null, "the disconnected panel row is purged with the project");
    const tomb = (await d.execute({ sql: "SELECT archived_at FROM project_spaces WHERE id = ?", args: [held] })).rows[0];
    assert.ok(tomb.archived_at);
  });
});

// ---- 2. the keychain guard fails closed -------------------------------------------------------

test("test_keychain_guard_fails_closed_for_orphaned_and_repointed_panel_rows", async () => {
  const ctx = await freshDb();
  const pid = await mkProject(ctx, "Keychain Guard");
  const panel = await panelConnect(ctx, { projectId: pid });
  const gh = await connectBound(ctx, "github", { projectId: pid, secrets: { [GH]: GH_TOKEN } });

  const ids = await withDbPath(ctx.path, async (d) => {
    const one = async (sql, args) => (await d.execute({ sql, args })).rows[0];
    const panelKey = await one("SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", [panel.uuid, PANEL_KEY]);
    const panelApprove = await one("SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", [panel.uuid, PANEL_APPROVE]);
    const ghRow = await one("SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", [gh.uuid, GH]);
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    const manual = await K.addManualSecret(d, key, { label: "Ordinary login", secret: MANUAL_SECRET });
    return { panelKey: Number(panelKey.id), panelApprove: Number(panelApprove.id), gh: Number(ghRow.id), manual: Number(manual.id) };
  });

  // One panel row re-pointed at the github connection, then the panel connection row removed: the
  // other panel row is an orphan.
  await withDbPath(ctx.path, async (d) => {
    await d.execute({ sql: "UPDATE crow_keychain SET connection_uuid = ? WHERE id = ?", args: [gh.uuid, ids.panelApprove] });
    await d.execute({ sql: "DELETE FROM service_connections WHERE uuid = ?", args: [panel.uuid] });
  });

  const { server, post } = await keychainApp(ctx);
  try {
    assert.equal((await post("/reauth", { password: "right-password" })).status, 200);

    for (const [where, id] of [["orphaned", ids.panelKey], ["re-pointed", ids.panelApprove]]) {
      const r = await post("/reveal", { id, purpose: "reveal" });
      assert.equal(r.status, 403, where);
      assert.equal(r.json?.error, KEYCHAIN_ERROR, where);
      for (const canary of [CANARY_KEY, CANARY_APPROVE]) assert.ok(!r.text.includes(canary), where + ": no answer carries a panel value");
    }

    // An ordinary service row and an ordinary manual row still reveal.
    const svc = await post("/reveal", { id: ids.gh, purpose: "reveal" });
    assert.equal(svc.status, 200, "the ordinary service row still reveals");
    assert.equal(svc.json?.secret, GH_TOKEN);
    const manual = await post("/reveal", { id: ids.manual, purpose: "reveal" });
    assert.equal(manual.status, 200, "the ordinary manual row still reveals");
    assert.equal(manual.json?.secret, MANUAL_SECRET);

    // Export leaves both panel rows out, whatever connection_uuid they now name.
    const entries = await withDbPath(ctx.path, (d) => K.exportableEntries(d, keyObj()));
    assert.ok(!entries.some((e) => e.bundle_id === "panelfix"), "no panel-bundle row is exportable");
    assert.ok(entries.some((e) => e.connection_uuid === gh.uuid && e.env_key === GH), "the ordinary service row is exportable");
    assert.ok(entries.some((e) => e.kind === "manual" && e.label === "Ordinary login"), "the ordinary manual row is exportable");
    for (const canary of [CANARY_KEY, CANARY_APPROVE]) assert.ok(!JSON.stringify(entries).includes(canary));

    const exp = await post("/export", { passphrase: "a-long-passphrase-1" });
    assert.equal(exp.status, 200, exp.text);
    assert.equal(exp.json?.count, 2, "only the two ordinary entries are exported");
  } finally {
    server.close();
  }
});

// ---- 3. panelSecretsFor reads the connection row itself ---------------------------------------

test("test_panel_secrets_for_reads_the_row_itself", async () => {
  const ctx = await freshDb();
  const pid = await mkProject(ctx, "Panel Reader");
  const healthy = await panelConnect(ctx, { projectId: pid, label: "healthy" });
  const swapped = await panelConnect(ctx, {
    projectId: pid, label: "swapped", secrets: { [PANEL_KEY]: CANARY_KEY, [PANEL_APPROVE]: CANARY_APPROVE },
  });
  const donor = await panelConnect(ctx, {
    projectId: pid, label: "donor", secrets: { [PANEL_KEY]: OTHER_KEY, [PANEL_APPROVE]: OTHER_APPROVE },
  });
  const disconnected = await panelConnect(ctx, { projectId: pid, label: "off" });
  const rewritten = await panelConnect(ctx, { projectId: pid, label: "rewritten" });
  const unbound = await panelConnect(ctx, { projectId: pid, label: "unbound" });

  assert.deepEqual(
    await withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), healthy.uuid, { crowHome: HOME })),
    panelSecrets(),
    "a healthy row returns both values",
  );

  const refusal = async (uuid) => {
    try {
      await withDbPath(ctx.path, (d) => SC.panelSecretsFor(d, keyObj(), uuid, { crowHome: HOME }));
      return null;
    } catch (err) {
      return err;
    }
  };

  const unknown = randomUUID();
  assert.equal((await refusal(unknown))?.code, "fingerprint_mismatch", "an unknown uuid is refused");

  await withDbPath(ctx.path, (d) => d.execute({ sql: "UPDATE service_connections SET status = 'disconnected' WHERE uuid = ?", args: [disconnected.uuid] }));
  assert.equal((await refusal(disconnected.uuid))?.code, "fingerprint_mismatch", "a disconnected row is refused");

  await withDbPath(ctx.path, (d) => d.execute({
    sql: "UPDATE service_connections SET service_id = 'github', bundle_id = 'github', method = 'token' WHERE uuid = ?",
    args: [rewritten.uuid],
  }));
  assert.equal((await refusal(rewritten.uuid))?.code, "fingerprint_mismatch", "a row rewritten to another service is refused");

  await removeBinding(unbound.uuid);
  assert.equal((await refusal(unbound.uuid))?.code, "fingerprint_mismatch", "a row without its binding is refused");

  // A sealed value copied in from another panel connection no longer matches the fingerprints.
  await withDbPath(ctx.path, async (d) => {
    const mine = (await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [swapped.uuid, PANEL_KEY] })).rows[0];
    const theirs = (await d.execute({ sql: "SELECT secret_sealed, key_id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [donor.uuid, PANEL_KEY] })).rows[0];
    await d.execute({ sql: "UPDATE crow_keychain SET secret_sealed = ?, key_id = ? WHERE id = ?", args: [theirs.secret_sealed, theirs.key_id, mine.id] });
  });
  const swappedErr = await refusal(swapped.uuid);
  assert.equal(swappedErr?.code, "fingerprint_mismatch", "a swapped sealed value is refused");
  for (const canary of [CANARY_KEY, CANARY_APPROVE, OTHER_KEY, OTHER_APPROVE]) {
    assert.ok(!String(swappedErr?.message).includes(canary), "the refusal carries no value");
  }
});

// ---- 4. a binding that cannot be recorded leaves nothing --------------------------------------

test("test_throwing_record_binding_leaves_nothing", async () => {
  const ctx = await freshDb();
  const pid = await mkProject(ctx, "Binding Fails");

  const thrown = await withDbPath(ctx.path, async (d) => {
    const key = await K.ensureWriteKey(d, { crowHome: HOME });
    try {
      await SC.createPanelConnection(d, {
        projectId: pid, serviceId: "panelfix", accountLabel: "main", config: {}, secrets: panelSecrets(),
      }, {
        key,
        crowHome: HOME,
        recordBinding: () => { throw new Error("injected binding failure"); },
      });
      return null;
    } catch (err) {
      return err;
    }
  });
  assert.ok(thrown, "the connect is refused");
  const message = String(thrown.message);
  for (const canary of [CANARY_KEY, CANARY_APPROVE]) {
    assert.ok(!message.includes(canary), "the thrown error carries no secret value");
  }

  await withDbPath(ctx.path, async (d) => {
    assert.equal((await d.execute({ sql: "SELECT uuid FROM service_connections WHERE project_id = ?", args: [pid] })).rows.length, 0,
      "no connection row is left behind");
    assert.equal((await d.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service'", args: [] })).rows.length, 0,
      "no keychain row is left behind");
    assert.equal((await d.execute({
      sql: "SELECT id FROM project_audit_log WHERE project_id = ? AND action = 'service.connect'", args: [pid],
    })).rows.length, 0, "no service.connect audit row is left behind");
  });
});