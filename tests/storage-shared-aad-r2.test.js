/**
 * storage.shared.* AAD, release 2: the gated writer, the owner-save conversion, the boot era
 * record and the one-way era.
 *
 * Release 1 shipped the READER for `enc:v2:` credentials. Release 2 adds:
 *   - the settings save that writes the bound form (and re-seals both keys when the endpoint or
 *     the SSL flag moves), only after the pre-flight passes;
 *   - the boot conversion (servers/gateway/boot/storage-shared-aad.js), gated on the fleet;
 *   - the era (servers/shared/storage-shared-era.js): host state file + DB mirror, after which a
 *     reader refuses `enc:v1:` and plaintext, whatever the peer capability rows say;
 *   - the once-a-day owner alert (servers/shared/storage-shared-alert.js), with no words of its own.
 *
 * Every test shares ONE real init-db database, reset between tests; the settings save runs
 * against a tiny local S3 stub for its listBuckets pre-flight (no network).
 */
import "./fixtures/storage-aad-r2-home.mjs";
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { chmodSync, closeSync, existsSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import {
  STORAGE_SHARED_CREDENTIAL_KEYS, openStorageSharedValue, storageSharedAad,
} from "../servers/shared/storage-shared-seal.js";
import { sealSecret, sealSecretBound } from "../servers/sharing/secret-box.js";
import { loadOrCreateIdentity } from "../servers/sharing/identity.js";
import { loadSharedStorageFromDb, readSharedStorageSettingsSync, SHARED_STORAGE_UNREADABLE } from "../servers/storage/s3-client.js";
import { peersStorageAadCapable, SYNC_SA_KEY_PREFIX } from "../servers/sharing/tailnet-sync.js";
import { getOrCreateLocalInstanceId } from "../servers/gateway/instance-registry.js";
import { runStorageSharedAadBoot } from "../servers/gateway/boot/storage-shared-aad.js";
import {
  STORAGE_ERA_SETTING, STORAGE_ERA_STATE_FILENAME, _resetStorageEraCacheForTest, readStorageEraState,
  removeStorageEraState, storageEraStatePath, writeStorageEraState,
} from "../servers/shared/storage-shared-era.js";
import { _resetStorageAlertForTest } from "../servers/shared/storage-shared-alert.js";
import { _setAlertsRootForTest, alertsDirs } from "../servers/shared/alert-spool.js";
import { makeRealDb, addPeerRow } from "./fixtures/sync-fleet.mjs";
import { _setEligibilityForTest } from "../servers/shared/sync-emit.js";
import { InstanceSyncManager } from "../servers/sharing/instance-sync.js";

const [KEY_ACCESS, KEY_SECRET] = STORAGE_SHARED_CREDENTIAL_KEYS;
const ACCESS = "crow-access-key-01";
const SECRET = "crow-secret-key-aaaaaaaaaaaaaaaaaaaaaaaa";
const identity = loadOrCreateIdentity();
const SECRETS_DIR = join(process.env.CROW_HOME, "secrets");

let dir;
let dbPath;
let db; // libsql-shaped client
let raw; // better-sqlite3 handle, for planting and inspecting rows
let localId;
const stubs = [];

/** A tiny S3 stub: GET / answers ListAllMyBuckets (200) or 403. */
async function stub(ok = true, { accessKey = null } = {}) {
  const server = http.createServer((req, res) => {
    // With `accessKey`, the store only knows that one key id (SigV4 names it in the header).
    const known = accessKey === null || String(req.headers.authorization || "").includes(`Credential=${accessKey}/`);
    if (ok && known) {
      res.writeHead(200, { "content-type": "application/xml" });
      res.end('<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Owner><ID>x</ID><DisplayName>x</DisplayName></Owner><Buckets><Bucket><Name>crow-files</Name><CreationDate>2020-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>');
    } else {
      res.writeHead(403, { "content-type": "application/xml" });
      res.end('<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>denied</Message></Error>');
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  stubs.push(server);
  return { endpoint: `127.0.0.1:${server.address().port}` };
}

const v1 = (plain) => sealSecret(plain, identity);
const v2 = (key, plain, endpoint, ssl = false) => sealSecretBound(plain, identity, storageSharedAad(key, endpoint, ssl));
const put = (key, value) => raw.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))").run(key, value);
const get = (key) => raw.prepare("SELECT value FROM dashboard_settings WHERE key = ?").get(key)?.value ?? null;
const openAt = (key, endpoint, ssl = false) => openStorageSharedValue(get(key), { settingKey: key, endpoint, useSSL: ssl, identity });
function plant(endpoint, access, secret, ssl = false) {
  put("storage.shared.endpoint", endpoint);
  put("storage.shared.use_ssl", ssl ? "true" : "false");
  put(KEY_ACCESS, access);
  put(KEY_SECRET, secret);
}
const snapshot = () => JSON.stringify(raw.prepare("SELECT key, value FROM dashboard_settings WHERE key LIKE 'storage.%' ORDER BY key").all());
const eraFile = () => readStorageEraState(SECRETS_DIR).state;
const mirrorRows = () => raw.prepare("SELECT COUNT(*) AS n FROM dashboard_settings_overrides WHERE key = ?").get(STORAGE_ERA_SETTING).n;
const pendingAlerts = () => { try { return readdirSync(alertsDirs().pending).filter((f) => f.endsWith(".json")); } catch { return []; } };

function convert(over = {}) {
  return runStorageSharedAadBoot({
    dbPath, crowHome: process.env.CROW_HOME, identity, gate: () => true, mirrorInstanceId: localId, log: () => {}, ...over,
  });
}

async function save(payload) {
  const { default: section } = await import("../servers/gateway/dashboard/settings/sections/shared-storage.js");
  let status = 200; let answer = null;
  const res = { status(c) { status = c; return this; }, json(o) { answer = o; } };
  const handled = await section.handleAction({
    req: { body: { payload: JSON.stringify({ region: "us-east-1", bucket_prefix: "crow", ...payload }) } },
    res, db, action: "save",
  });
  assert.equal(handled, true);
  return { status, answer };
}

/** Run `fn` with console output captured; returns every line written. */
async function captured(fn) {
  const lines = [];
  const real = { log: console.log, warn: console.warn, error: console.error };
  console.log = console.warn = console.error = (...a) => { lines.push(a.map(String).join(" ")); };
  try { await fn(); } finally { Object.assign(console, real); }
  return lines;
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "crow-storage-aad-r2-"));
  db = await makeRealDb(dir);
  dbPath = join(dir, "crow.db");
  raw = new Database(dbPath);
  raw.pragma("busy_timeout = 5000");
  localId = getOrCreateLocalInstanceId();
});

after(async () => {
  for (const s of stubs) { try { s.close(); } catch { /* closed */ } }
  try { raw.close(); } catch { /* closed */ }
  try { db.close?.(); } catch { /* closed */ }
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  raw.prepare("DELETE FROM dashboard_settings WHERE key LIKE 'storage.%'").run();
  raw.prepare("DELETE FROM dashboard_settings_overrides").run();
  raw.prepare("DELETE FROM crow_instances").run();
  removeStorageEraState(SECRETS_DIR);
  _resetStorageEraCacheForTest();
  _resetStorageAlertForTest();
  _setAlertsRootForTest(mkdtempSync(join(dir, "alerts-")));
});

const markSa = (peer, value) => raw.prepare(
  "INSERT OR REPLACE INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, ?, ?, datetime('now'))",
).run(`${SYNC_SA_KEY_PREFIX}${peer}`, localId, String(value));

/* ───────────────────────────── 1. the fleet gate and the owner-save conversion ───────────────────────────── */

test("fleet gate: an unknown peer keeps v1; sa>=1 peers get v2 with NO era; all sa>=2 converts AND records the era", async () => {
  const s = await stub();
  await addPeerRow(db, "peerOld");
  const gate = (level) => peersStorageAadCapable(db, localId, level);
  assert.equal(await gate(1), false, "a peer that never advertised sa");

  // The boot pass never converts, whatever the fleet says.
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  assert.equal((await convert({ gate: () => gate(2) })).state, "gate-closed");

  // Unknown peer: the owner save writes v1 exactly as before, and records nothing.
  const w0 = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
  assert.equal(w0.status, 200);
  assert.equal(get(KEY_ACCESS).startsWith("enc:v1:"), true);
  assert.equal(eraFile(), "absent");

  // A release-1 peer (sa:1) reads v2 but still WRITES v1: v2 is written, but NO era.
  markSa("peerOld", 1);
  assert.equal(await gate(1), true);
  assert.equal(await gate(2), false);
  const w1 = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
  assert.equal(w1.status, 200);
  assert.equal(get(KEY_ACCESS).startsWith("enc:v2:"), true, "a pre-era writer with sa>=1 peers writes v2");
  assert.equal(get(KEY_SECRET).startsWith("enc:v2:"), true);
  assert.equal(eraFile(), "absent", "no era while a peer can still write v1");
  assert.equal(mirrorRows(), 0);
  assert.equal((await convert({ gate: () => gate(2) })).state, "gate-closed", "boot: gate closed");

  // A non-integer level is not a level.
  markSa("peerOld", "2.5");
  assert.equal(await gate(2), false);

  // Every peer at sa:2: the owner's save is the CONVERSION and records the era.
  markSa("peerOld", 2);
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  // Blank keys filled from stored v1: NOT bound, NO era (they could be an exchanged pair).
  const wBlank = await save({ endpoint: s.endpoint, use_ssl: false });
  assert.equal(wBlank.status, 200);
  assert.equal(get(KEY_ACCESS).startsWith("enc:v1:"), true, "a blank-key save over stored v1 writes v1 exactly as before");
  assert.equal(eraFile(), "absent");
  assert.equal(mirrorRows(), 0);
  // Both keys TYPED in this save: the pre-flight proved them, so it binds and records the era.
  const w2 = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
  assert.equal(w2.status, 200, "both keys typed: pre-flighted and bound");
  assert.equal(openAt(KEY_ACCESS, s.endpoint).version, "v2");
  assert.equal(openAt(KEY_SECRET, s.endpoint).plaintext, SECRET);
  assert.equal(eraFile(), "converted");
  assert.equal(mirrorRows(), 1);
  // Past the era a v1 value is refused.
  put(KEY_ACCESS, v1(ACCESS));
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
});

test("the owner-save conversion emits with a FRESH lamport (the converted rows reach peers)", async () => {
  const s = await stub();
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  raw.prepare("UPDATE dashboard_settings SET lamport_ts = 0 WHERE key LIKE 'storage.%'").run();
  _setEligibilityForTest(() => true);
  try {
    const r = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
    assert.equal(r.status, 200);
  } finally {
    _setEligibilityForTest(null);
  }
  for (const key of [KEY_ACCESS, KEY_SECRET]) {
    const ts = raw.prepare("SELECT lamport_ts AS t FROM dashboard_settings WHERE key = ?").get(key).t;
    assert.ok(ts > 0, `${key} was stamped with a fresh lamport`);
  }
  assert.equal(eraFile(), "converted");
});

/* ───────────────────────────── 2-4. the owner save ───────────────────────────── */

async function eraOnWithPair(endpoint, ssl = false) {
  plant(endpoint, v2(KEY_ACCESS, ACCESS, endpoint, ssl), v2(KEY_SECRET, SECRET, endpoint, ssl), ssl);
  put("storage.shared.region", "us-east-1");
  put("storage.shared.bucket_prefix", "crow");
  writeStorageEraState(SECRETS_DIR, { rows: 2 });
}

test("an endpoint-only change whose pre-flight passes re-seals BOTH keys under the new AAD (the old AAD no longer opens them)", async () => {
  const a = await stub();
  const b = await stub();
  await eraOnWithPair(a.endpoint);
  const r = await save({ endpoint: b.endpoint, use_ssl: false });
  assert.equal(r.status, 200);
  assert.equal(get("storage.shared.endpoint"), b.endpoint);
  for (const [key, plain] of [[KEY_ACCESS, ACCESS], [KEY_SECRET, SECRET]]) {
    assert.deepEqual(openAt(key, b.endpoint), { ok: true, plaintext: plain, version: "v2" });
    assert.equal(openAt(key, a.endpoint).reason, "storage_credentials_unbound");
  }
});

test("a use_ssl-only change also re-seals both keys under the new flag", async () => {
  const a = await stub();
  await eraOnWithPair(a.endpoint, false);
  const r = await save({ endpoint: a.endpoint, use_ssl: true });
  // The stub speaks plain HTTP, so the HTTPS pre-flight fails: nothing was written.
  assert.equal(r.status, 400);
  assert.equal(openAt(KEY_ACCESS, a.endpoint, false).ok, true, "still bound to the old flag");
});

test("a failed pre-flight writes nothing; the old blobs still open under the OLD AAD", async () => {
  const a = await stub();
  const bad = await stub(false);
  await eraOnWithPair(a.endpoint);
  const before = snapshot();
  const r = await save({ endpoint: bad.endpoint, use_ssl: false });
  assert.equal(r.status, 400);
  assert.match(r.answer.error, /^MinIO pre-flight failed/);
  assert.equal(snapshot(), before, "no row moved");
  assert.equal(openAt(KEY_ACCESS, a.endpoint).ok, true);
  assert.equal(openAt(KEY_SECRET, a.endpoint).ok, true);
});

test("an endpoint change plus key re-entry, as an ordinary owner flow, seals both keys v2 under the new AAD", async () => {
  const a = await stub();
  const b = await stub();
  await eraOnWithPair(a.endpoint);
  const r = await save({ endpoint: b.endpoint, use_ssl: false, access_key: "garage-access-02", secret_key: "garage-secret-bbbbbbbbbbbbbbbbbbbbbbbb" });
  assert.equal(r.status, 200);
  assert.equal(openAt(KEY_ACCESS, b.endpoint).plaintext, "garage-access-02");
  assert.equal(openAt(KEY_SECRET, b.endpoint).plaintext, "garage-secret-bbbbbbbbbbbbbbbbbbbbbbbb");
  assert.equal(get(KEY_ACCESS).startsWith("enc:v2:"), true);
  assert.equal(get(KEY_SECRET).startsWith("enc:v2:"), true);
  assert.equal(openAt(KEY_ACCESS, a.endpoint).ok, false);
});

test("a save that changes nothing re-seals nothing (no fresh nonces churning the sync feed)", async () => {
  const a = await stub();
  await eraOnWithPair(a.endpoint);
  const before = snapshot();
  const r = await save({ endpoint: a.endpoint, use_ssl: false });
  assert.equal(r.status, 200);
  assert.equal(snapshot(), before);
});

/* ───────────────────────────── 5. a bot rewrites the endpoint ───────────────────────────── */

test("a bot's raw endpoint rewrite: the first reader rings the alert (once), and a blank-key owner save is a 400 that writes nothing", async () => {
  const a = await stub();
  const bot = await stub();
  await eraOnWithPair(a.endpoint);
  put("storage.shared.endpoint", bot.endpoint); // the raw write

  assert.equal(pendingAlerts().length, 0);
  assert.equal(await loadSharedStorageFromDb(db, identity), null, "storage is off");
  assert.equal(pendingAlerts().length, 1, "the first failed open rang the bell");
  assert.match(pendingAlerts()[0], /storage-credentials-unbound\.json$/);
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
  assert.equal(readSharedStorageSettingsSync(dbPath, identity).reason, SHARED_STORAGE_UNREADABLE);
  assert.equal(pendingAlerts().length, 1, "once a UTC day per instance");

  const before = snapshot();
  const r = await save({ endpoint: bot.endpoint, use_ssl: false });
  assert.equal(r.status, 400);
  assert.equal(r.answer.error, "access_key and secret_key required");
  assert.equal(snapshot(), before, "nothing was written");
  // The old blobs still open under the ORIGINAL endpoint's AAD.
  assert.equal(openStorageSharedValue(get(KEY_ACCESS), { settingKey: KEY_ACCESS, endpoint: a.endpoint, useSSL: false, identity }).ok, true);
  assert.equal(openStorageSharedValue(get(KEY_SECRET), { settingKey: KEY_SECRET, endpoint: a.endpoint, useSSL: false, identity }).ok, true);
});

test("the alert is the bare spool alert: default title, no body, only the code and the day", async () => {
  const a = await stub();
  await eraOnWithPair(a.endpoint);
  put("storage.shared.endpoint", "127.0.0.1:1");
  await loadSharedStorageFromDb(db, identity);
  const [name] = pendingAlerts();
  const body = JSON.parse(readFileSync(join(alertsDirs().pending, name), "utf8"));
  assert.equal(body.title, "Crow alert");
  assert.equal(body.body, null);
  assert.equal(body.code, "storage_credentials_unbound");
});

/* ───────────────────────────── 6. the boot pass never binds what the DB holds ───────────────────────────── */

async function assertBootLeavesAlone(access, secret, why, endpointOverride) {
  const s = await stub();
  plant(endpointOverride ?? s.endpoint, access, secret);
  const before = snapshot();
  const out = await convert();
  assert.equal(out.state, "awaiting-owner-save", `${why}: ${out.state}`);
  assert.equal(snapshot(), before, `${why}: no row was written`);
  assert.equal(eraFile(), "absent", `${why}: no era`);
  assert.equal(mirrorRows(), 0);
}

test("boot: an EXCHANGED v1 pair (access and secret swapped) is never bound", async () => {
  await assertBootLeavesAlone(v1(SECRET), v1(ACCESS), "exchanged");
});

test("boot: a re-pointed endpoint is never bound to the owner's credentials", async () => {
  await assertBootLeavesAlone(v1(ACCESS), v1(SECRET), "re-pointed", "attacker.example.test:9000");
});

test("boot: identical, same-plaintext, non-canonical, nested, one-row and junk values are all left exactly as they are", async () => {
  const blob = v1(ACCESS);
  await assertBootLeavesAlone(blob, blob, "identical");
  await assertBootLeavesAlone(v1(ACCESS), v1(ACCESS), "same plaintext");
  await assertBootLeavesAlone(v1(ACCESS) + "\n", v1(SECRET), "noncanonical");
  await assertBootLeavesAlone(v1(v1(ACCESS)), v1(SECRET), "nested");
  await assertBootLeavesAlone(ACCESS, SECRET, "plaintext");
  await assertBootLeavesAlone("enc:zzz", v1(SECRET), "junk");
  const s = await stub();
  put("storage.shared.endpoint", s.endpoint);
  put(KEY_ACCESS, v1(ACCESS));
  const before = snapshot();
  assert.equal((await convert()).state, "awaiting-owner-save");
  assert.equal(snapshot(), before);
});

test("the owner save is the conversion: an exchanged pair fails the pre-flight at the real store and nothing is written", async () => {
  // A store that knows only the genuine access key id: the exchanged pair sends the SECRET as
  // the key id and is refused, so the save never reaches a write.
  const store = await stub(true, { accessKey: ACCESS });
  plant(store.endpoint, v1(SECRET), v1(ACCESS));
  const before = snapshot();
  const r = await save({ endpoint: store.endpoint, use_ssl: false });
  assert.equal(r.status, 400);
  assert.match(r.answer.error, /^MinIO pre-flight failed/);
  assert.equal(snapshot(), before);
  assert.equal(eraFile(), "absent");
  // Control: the genuine pair converts.
  plant(store.endpoint, v1(ACCESS), v1(SECRET));
  assert.equal((await save({ endpoint: store.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET })).status, 200);
  assert.equal(eraFile(), "converted");
});

/* ───────────────────────────── 7. after the era ───────────────────────────── */

test("after the era v1 and plaintext are refused (storage off), and the peer capability rows cannot re-open them", async () => {
  const s = await stub();
  await addPeerRow(db, "peerA");
  markSa("peerA", 2);
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  assert.equal((await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET })).status, 200);
  assert.equal(eraFile(), "converted");

  // A v1 value arrives later (a bot's raw write).
  put(KEY_ACCESS, v1(ACCESS));
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
  assert.equal(readSharedStorageSettingsSync(dbPath, identity).ok, false);
  // Plaintext likewise.
  put(KEY_ACCESS, ACCESS);
  put(KEY_SECRET, SECRET);
  assert.equal(await loadSharedStorageFromDb(db, identity), null);

  // Flipping every sa row to 0, or deleting every peer row, does NOT re-open v1.
  raw.prepare("UPDATE dashboard_settings_overrides SET value = '0' WHERE substr(key, 1, ?) = ?").run(SYNC_SA_KEY_PREFIX.length, SYNC_SA_KEY_PREFIX);
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
  raw.prepare("DELETE FROM crow_instances").run();
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
  put(KEY_ACCESS, v1(ACCESS));
  put(KEY_SECRET, v1(SECRET));
  assert.equal(await loadSharedStorageFromDb(db, identity), null);

  // Deleting the DB mirror alone does not re-open v1: the host state file holds.
  raw.prepare("DELETE FROM dashboard_settings_overrides WHERE key = ?").run(STORAGE_ERA_SETTING);
  assert.equal(await loadSharedStorageFromDb(db, identity), null);
  assert.equal(readSharedStorageSettingsSync(dbPath, identity).ok, false);

  // Control: a properly bound pair opens.
  put(KEY_ACCESS, v2(KEY_ACCESS, ACCESS, s.endpoint));
  put(KEY_SECRET, v2(KEY_SECRET, SECRET, s.endpoint));
  const cfg = await loadSharedStorageFromDb(db, identity);
  assert.equal(cfg?.accessKey, ACCESS);
  assert.equal(cfg?.secretKey, SECRET);
});

test("a planted mirror alone refuses v1 for readers, is not 'post-era' for the writer, and never stands in for the host file", async () => {
  const s = await stub();
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  raw.prepare("INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at, lamport_ts) VALUES (?, ?, 'x', datetime('now'), 0)").run(STORAGE_ERA_SETTING, "bot");
  assert.equal(await loadSharedStorageFromDb(db, identity), null, "a mirror may only ADD refusals");
  assert.equal(eraFile(), "absent");
  assert.equal((await convert()).state, "awaiting-owner-save", "boot records no era on the word of a mirror");
  assert.equal(eraFile(), "absent");
  // The owner heals it by re-entering the keys: the save (no peers → gate open) converts and
  // writes the HOST file.
  const r = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
  assert.equal(r.status, 200);
  assert.equal(eraFile(), "converted");
  assert.equal((await loadSharedStorageFromDb(db, identity))?.accessKey, ACCESS);
});

/* ───────────────────────────── 7b. the inbound sync guard ───────────────────────────── */

const applyInbound = (row, lamport, op = "update") =>
  InstanceSyncManager.prototype._applyDashboardSetting.call({ db }, op, row, lamport);

test("sync: after the era, v1 arriving with a TIED lamport is dropped, the local v2 kept, and the alert rings", async () => {
  const s = await stub();
  await eraOnWithPair(s.endpoint);
  raw.prepare("UPDATE dashboard_settings SET lamport_ts = 5 WHERE key LIKE 'storage.shared.%'").run();
  const local = get(KEY_ACCESS);
  assert.equal(pendingAlerts().length, 0);
  await applyInbound({ key: KEY_ACCESS, value: v1(ACCESS) }, 5);
  assert.equal(get(KEY_ACCESS), local, "the tied v1 did not replace the local v2");
  assert.equal(pendingAlerts().length, 1);
  // A higher lamport and plaintext are dropped the same way.
  await applyInbound({ key: KEY_ACCESS, value: v1(ACCESS) }, 99);
  await applyInbound({ key: KEY_SECRET, value: SECRET }, 99);
  assert.equal(get(KEY_ACCESS), local);
  assert.equal(get(KEY_SECRET).startsWith("enc:v2:"), true);
  assert.equal(pendingAlerts().length, 1, "once a day");
  // A bound value from a converted peer still applies.
  const fresh = v2(KEY_ACCESS, "rotated-access-03", s.endpoint);
  await applyInbound({ key: KEY_ACCESS, value: fresh }, 100);
  assert.equal(get(KEY_ACCESS), fresh);
});

test("sync: after the era a synced DELETE of a credential row applies, then a synced v1 INSERT for it is dropped and the alert rings", async () => {
  const s = await stub();
  await eraOnWithPair(s.endpoint);
  assert.equal(pendingAlerts().length, 0);
  await applyInbound({ key: KEY_ACCESS }, 50, "delete");
  assert.equal(get(KEY_ACCESS), null, "the delete applied");
  await applyInbound({ key: KEY_ACCESS, value: v1(ACCESS) }, 51, "insert");
  assert.equal(get(KEY_ACCESS), null, "the v1 insert was dropped; the row stays gone");
  assert.equal(pendingAlerts().length, 1, "the alert rang");
  // A bound insert is still welcome.
  const bound = v2(KEY_ACCESS, ACCESS, s.endpoint);
  await applyInbound({ key: KEY_ACCESS, value: bound }, 52, "insert");
  assert.equal(get(KEY_ACCESS), bound);
});

test("a pre-era blank-key save over stored v1 or plaintext writes v1 and records no era, even with every peer at sa>=2 (a re-pointed form address cannot capture the keys)", async () => {
  const s = await stub();
  const bot = await stub();
  await addPeerRow(db, "peerNew");
  markSa("peerNew", 2);
  for (const [a, k] of [[v1(ACCESS), v1(SECRET)], [ACCESS, SECRET]]) {
    plant(s.endpoint, a, k);
    // The form pre-filled the endpoint from a bot-writable row: the bot's server answers.
    const lines = await captured(async () => {
      const r = await save({ endpoint: bot.endpoint, use_ssl: false });
      assert.equal(r.status, 200);
    });
    assert.equal(get(KEY_ACCESS), a, "the stored key was not re-sealed");
    assert.equal(get(KEY_SECRET), k);
    assert.equal(eraFile(), "absent");
    assert.equal(mirrorRows(), 0);
    assert.equal(lines.filter((l) => /old form/.test(l)).length, 1, "one value-free log line");
  }
});

test("a post-era blank-key save with stored v2 still re-seals for an address change", async () => {
  const a = await stub();
  const b = await stub();
  await eraOnWithPair(a.endpoint);
  const r = await save({ endpoint: b.endpoint, use_ssl: false });
  assert.equal(r.status, 200);
  assert.equal(openAt(KEY_ACCESS, b.endpoint).version, "v2");
  // Pre-era too: a stored v2 pair (opens only for the stored address) may be re-bound by a blank save.
  removeStorageEraState(SECRETS_DIR);
  _resetStorageEraCacheForTest();
  const c = await stub();
  plant(b.endpoint, v2(KEY_ACCESS, ACCESS, b.endpoint), v2(KEY_SECRET, SECRET, b.endpoint));
  assert.equal((await save({ endpoint: c.endpoint, use_ssl: false })).status, 200);
  assert.equal(openAt(KEY_ACCESS, c.endpoint).version, "v2");
  assert.equal(eraFile(), "converted", "a bound pair re-bound at the gate records the era");
});

test("the save's era-write failure rings the once-a-day alert as well as warning", async () => {
  const s = await stub();
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  // Make the secrets dir unusable: a regular file where the directory must be.
  const { rmSync: rm, writeFileSync: wf, mkdirSync } = await import("node:fs");
  rm(SECRETS_DIR, { recursive: true, force: true });
  wf(SECRETS_DIR, "not a directory");
  let lines;
  try {
    lines = await captured(async () => {
      const r = await save({ endpoint: s.endpoint, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
      assert.equal(r.status, 200);
    });
  } finally {
    rm(SECRETS_DIR, { force: true });
    mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
  }
  assert.equal(get(KEY_ACCESS).startsWith("enc:v2:"), true, "the rows were written");
  assert.equal(eraFile(), "absent");
  assert.ok(lines.some((l) => /era could not be recorded/.test(l)));
  assert.equal(pendingAlerts().length, 1);
});

test("sync: a re-emit from a non-converted peer cannot overwrite the converted instance's v2", async () => {
  const s = await stub();
  await eraOnWithPair(s.endpoint);
  const before = snapshot();
  await applyInbound({ key: KEY_ACCESS, value: v1(ACCESS) }, 1_000_000);
  await applyInbound({ key: KEY_SECRET, value: v1(SECRET) }, 1_000_000);
  assert.equal(snapshot(), before);
});

test("sync: before the era a v1 value applies as it always did (and the mirror alone does not change that)", async () => {
  const s = await stub();
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  raw.prepare("INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at, lamport_ts) VALUES (?, ?, 'x', datetime('now'), 0)").run(STORAGE_ERA_SETTING, "bot");
  const incoming = v1("peer-access-04");
  await applyInbound({ key: KEY_ACCESS, value: incoming }, 7);
  assert.equal(get(KEY_ACCESS), incoming);
});

test("S2: the save reads the GLOBAL storage.shared.* rows only, never a per-instance override", async () => {
  const a = await stub();
  await eraOnWithPair(a.endpoint);
  raw.prepare("INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at, lamport_ts) VALUES (?, ?, ?, datetime('now'), 0)").run("storage.shared.endpoint", localId, "attacker.example.test:9000");
  const r = await save({ endpoint: a.endpoint, use_ssl: false });
  assert.equal(r.status, 200, "the stored keys opened under the GLOBAL endpoint, as the readers read it");
  assert.equal(openAt(KEY_ACCESS, a.endpoint).ok, true);
});

test("the state file is read from the secrets dir it is given, including an fd-anchored /proc/self/fd path", () => {
  const anchored = mkdtempSync(join(dir, "anchored-"));
  const fd = openSync(anchored, "r");
  try {
    const path = `/proc/self/fd/${fd}`;
    assert.equal(readStorageEraState(path).state, "absent");
    writeFileSync(join(anchored, STORAGE_ERA_STATE_FILENAME), JSON.stringify({ converted_at: "2026-01-01T00:00:00.000Z", rows: 2 }), { mode: 0o600 });
    _resetStorageEraCacheForTest();
    assert.equal(readStorageEraState(path).state, "converted");
  } finally {
    closeSync(fd);
  }
});

test("a symlinked or group-writable state file is not proof of an era", () => {
  const d = mkdtempSync(join(dir, "hostile-"));
  const target = join(d, "real.json");
  writeFileSync(target, JSON.stringify({ converted_at: "2026-01-01T00:00:00.000Z" }), { mode: 0o600 });
  symlinkSync(target, storageEraStatePath(d));
  assert.equal(readStorageEraState(d).state, "unreadable");
  rmSync(storageEraStatePath(d));
  writeFileSync(storageEraStatePath(d), JSON.stringify({ converted_at: "2026-01-01T00:00:00.000Z" }), { mode: 0o666 });
  // The create mode is masked by the umask (022 in CI leaves 0644, which is not group-writable): set it.
  chmodSync(storageEraStatePath(d), 0o666);
  _resetStorageEraCacheForTest();
  assert.equal(readStorageEraState(d).state, "unreadable");
});

/* ───────────────────────────── 8-9. env-only and unnormalizable ───────────────────────────── */

test("an env-only install (no storage.shared rows) records the era and changes nothing else", async () => {
  const before = snapshot();
  const out = await convert();
  assert.equal(out.state, "marked-empty");
  assert.equal(snapshot(), before);
  assert.equal(eraFile(), "converted");
  assert.equal(mirrorRows(), 1);
});

test("an unnormalizable endpoint (IPv6 literal, a path) stays v1 and keeps working; no era", async () => {
  const s = await stub();
  for (const endpoint of ["[::1]:9000", `${s.endpoint}/minio`]) {
    plant(endpoint, v1(ACCESS), v1(SECRET));
    const before = snapshot();
    const out = await convert();
    assert.equal(out.state, "awaiting-owner-save");
    assert.equal(snapshot(), before);
    assert.equal(eraFile(), "absent");
  }
  // The path endpoint still reads (legacy split) ...
  assert.equal((await loadSharedStorageFromDb(db, identity))?.accessKey, ACCESS);
  // ... and a pre-era owner save for it writes v1 and logs one line, with no era.
  const lines = await captured(async () => {
    const r = await save({ endpoint: `${s.endpoint}/minio`, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
    assert.equal(r.status, 200);
  });
  assert.equal(get(KEY_ACCESS).startsWith("enc:v1:"), true);
  assert.equal(lines.filter((l) => /cannot be bound/.test(l)).length, 1);
  assert.equal(eraFile(), "absent");
});

test("post-era, a save for an endpoint that cannot be bound is refused before anything is written", async () => {
  const s = await stub();
  await eraOnWithPair(s.endpoint);
  const before = snapshot();
  const r = await save({ endpoint: `${s.endpoint}/minio`, use_ssl: false, access_key: ACCESS, secret_key: SECRET });
  assert.equal(r.status, 400);
  assert.equal(snapshot(), before);
});

/* ───────────────────────────── 10. no value in any log or alert ───────────────────────────── */

test("no log line and no alert file carries a key, a plaintext, an endpoint or a blob", async () => {
  const s = await stub();
  const blobs = [v1(ACCESS), v1(SECRET)];
  const lines = await captured(async () => {
    // Boot leaves v1 alone (logs).
    plant(s.endpoint, blobs[0], blobs[1]);
    await convert({ log: (l) => console.log(l) });
    // Reader refusal path (post-era, v1).
    writeStorageEraState(SECRETS_DIR, { rows: 2 });
    await loadSharedStorageFromDb(db, identity);
    await convert({ log: (l) => console.log(l) });
    // A swapped bound blob, and an inbound v1.
    plant(s.endpoint, v2(KEY_SECRET, SECRET, s.endpoint), v2(KEY_SECRET, SECRET, s.endpoint));
    await loadSharedStorageFromDb(db, identity);
    await applyInbound({ key: KEY_ACCESS, value: blobs[0] }, 99);
  });
  const files = pendingAlerts().map((f) => readFileSync(join(alertsDirs().pending, f), "utf8"));
  const port = s.endpoint.split(":")[1];
  for (const text of [...lines, ...files]) {
    for (const needle of [ACCESS, SECRET, s.endpoint, port, "enc:v1:", "enc:v2:", ...blobs]) {
      assert.equal(text.includes(needle), false, `leaked ${needle.slice(0, 12)} in: ${text.slice(0, 80)}`);
    }
  }
  assert.ok(lines.length > 0 && files.length > 0, "the scenario really logged and alerted");
});

/* ───────────────────────────── 11. junk ───────────────────────────── */

test("one junk value never crashes boot: left alone, no era, the boot goes on", async () => {
  const s = await stub();
  for (const junk of ["enc:zzz", "enc:v9:abc", Buffer.from("not text"), "ENC:V1:abc"]) {
    plant(s.endpoint, junk, v1(SECRET));
    const before = snapshot();
    const out = await convert();
    assert.equal(out.state, "awaiting-owner-save", String(junk));
    assert.equal(snapshot(), before);
    assert.equal(eraFile(), "absent");
  }
  // A bound row that does not open for this address rings the alert and records no era.
  plant(s.endpoint, v2(KEY_ACCESS, ACCESS, "elsewhere.example.test:9000"), v2(KEY_SECRET, SECRET, "elsewhere.example.test:9000"));
  const out = await convert();
  assert.equal(out.state, "bound-unopenable");
  assert.equal(eraFile(), "absent");
  assert.equal(pendingAlerts().length, 1);
  // A garbage state file is "unreadable", not a crash and not an era.
  writeFileSync(storageEraStatePath(SECRETS_DIR), "{not json", { mode: 0o600 });
  _resetStorageEraCacheForTest();
  assert.equal(readStorageEraState(SECRETS_DIR).state, "unreadable");
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  assert.equal((await convert()).state, "awaiting-owner-save");
});

test("a crash after the commit (both rows bound, no era) is finished by recording the era alone", async () => {
  const s = await stub();
  plant(s.endpoint, v2(KEY_ACCESS, ACCESS, s.endpoint), v2(KEY_SECRET, SECRET, s.endpoint));
  const before = snapshot();
  const out = await convert();
  assert.equal(out.state, "marked-bound");
  assert.equal(snapshot(), before);
  assert.equal(eraFile(), "converted");
});

test("the boot scan after the era rings the alert for a stored credential that is not bound", async () => {
  const s = await stub();
  writeStorageEraState(SECRETS_DIR, { rows: 2 });
  plant(s.endpoint, v1(ACCESS), v1(SECRET));
  const out = await convert({ gate: () => false });
  assert.equal(out.state, "converted-earlier");
  assert.equal(pendingAlerts().length, 1);
  assert.equal(mirrorRows(), 1, "the missing mirror was caught up from the host file");
});
