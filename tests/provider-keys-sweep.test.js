/**
 * The shared provider-key seal pass (design §3.1–§3.5) and its unseal reversal.
 *
 * Fixtures are real scratch instances: a fresh `crow.db` from the repo's own
 * scripts/init-db.js, a real keychain key file, real provider rows. Nothing here
 * touches ~/.crow: CROW_HOME is a temp dir and the alert spool is retargeted per
 * test.
 *
 * Every "key" below is `sentinel-<uuid>`; the hygiene test at the end asserts
 * that no surface (stdout/stderr, an alert file, a returned reason) ever repeats
 * one.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { captureOutput } from "./helpers/sentinel-scan.mjs";

const REPO = join(import.meta.dirname, "..");
const UNSEAL_TOOL = join(REPO, "scripts", "ops", "provider-keys-unseal.mjs");

// A scratch home for everything this FILE does; each test gets its own home
// under the SAME CROW_HOME owner (alerts resolve through it).
const FILE_HOME = mkdtempSync(join(tmpdir(), "crow-pk-sweep-home-"));
const PRISTINE_DATA = join(FILE_HOME, "pristine");
mkdirSync(PRISTINE_DATA, { recursive: true, mode: 0o700 });
process.env.CROW_HOME = FILE_HOME;
execFileSync(process.execPath, ["scripts/init-db.js"],
  { env: { ...process.env, CROW_HOME: FILE_HOME, CROW_DATA_DIR: PRISTINE_DATA }, stdio: "pipe", cwd: REPO });
const PRISTINE_DB = join(PRISTINE_DATA, "crow.db");

// A per-test home derives its data dir (<home>/data), so the env must not pin
// one: servers/shared/crow-home.js falls back to the home's own data/.
delete process.env.CROW_DATA_DIR;
delete process.env.CROW_DB_PATH;

const { sealPlaintextKeys, unsealAllKeys, backupDirFor, backupFiles, SWEEP_ALERTS } =
  await import("../servers/gateway/keychain/provider-keys-sweep.js");
const { residueStatePath, _setFreeSpaceForTest, _setDeviceForTest, _setResidueScanProbeForTest, _resetResidueBootScanForTest } =
  await import("../servers/gateway/keychain/provider-keys-sweep.js");
const { createKeychainKey, keychainKeyPath, loadKeychainKey } =
  await import("../servers/gateway/keychain/key.js");
const { seal: sealKey, open: openKey } = await import("../servers/gateway/keychain/provider-key-box.js");
const { providerKeyFp, parseStoredKey } = await import("../servers/shared/provider-key-shape.js");
const { legacyConsentFingerprint, sealedConsentFingerprint } =
  await import("../servers/gateway/keychain/provider-keys-sweep.js");
const { _setAlertsRootForTest } = await import("../servers/shared/alert-spool.js");
const { KEY_SAVE_REFUSED } = await import("../servers/gateway/addon-secrets-seal.js");
const { runMigrations } = await import("../scripts/migrations/runner.mjs");

const MIGRATIONS_DIR = join(REPO, "scripts", "migrations");

const OTHER_KEY = { id: "fedcba9876543210", seed: randomBytes(32) };
const SALT = "a".repeat(64);
const sentinel = () => `sentinel-${randomUUID()}`;

after(() => {
  _setAlertsRootForTest(null);
  try { rmSync(FILE_HOME, { recursive: true, force: true }); } catch { /* best effort */ }
});

/** A fresh instance home with a copy of the pristine crow.db, and its own alert spool. */
async function instance(t, { key = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), "crow-pk-sweep-"));
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbPath = join(dataDir, "crow.db");
  const source = new Database(PRISTINE_DB, { readonly: true, fileMustExist: true });
  try { await source.backup(dbPath); } finally { source.close(); }
  // One self-contained file per test: the pristine database may be WAL-mode.
  const copy = new Database(dbPath);
  try { copy.pragma("journal_mode = DELETE"); } finally { copy.close(); }
  const alertsRoot = join(home, "alerts");
  // The pass judges "does this database belong to this home" against the process
  // env as well (a co-hosted gateway boots with its own CROW_HOME), so a test
  // instance must BE the process's home while it runs.
  const savedHome = process.env.CROW_HOME;
  process.env.CROW_HOME = home;
  // Each instance is a fresh gateway for the residue pass too: the "already
  // scanned this boot" flag belongs to a process, and this test file reuses one.
  _resetResidueBootScanForTest();
  t.after(() => {
    process.env.CROW_HOME = savedHome;
    _setAlertsRootForTest(null);
    _setFreeSpaceForTest(null);
    _setDeviceForTest(null);
    _setResidueScanProbeForTest(null);
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  _setAlertsRootForTest(alertsRoot);
  let kcKey = null;
  if (key) kcKey = createKeychainKey({ crowHome: home });
  return { home, dataDir, dbPath, alertsRoot, key: kcKey };
}

function withDb(dbPath, fn) {
  const db = new Database(dbPath);
  try { return fn(db); } finally { db.close(); }
}

function addProvider(dbPath, rows) {
  withDb(dbPath, (db) => {
    const ins = db.prepare(
      "INSERT INTO providers (id, base_url, api_key, host, provider_type, created_at, updated_at, lamport_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const row of rows) {
      ins.run(row.id, row.base_url ?? "https://api.example.com/v1", row.api_key ?? null,
        row.host ?? "local", row.provider_type ?? "openai", row.created_at ?? "2026-01-01T00:00:00.000Z",
        row.updated_at ?? "2026-02-02T00:00:00.000Z", row.lamport_ts ?? 7);
    }
  });
}

const providerRow = (dbPath, id) => withDb(dbPath, (db) => db.prepare("SELECT * FROM providers WHERE id = ?").get(id));

function setConsent(dbPath, entries) {
  withDb(dbPath, (db) => {
    db.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('llm_cloud_consent_salt', ?)").run(SALT);
    db.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('llm_cloud_door_rows', ?)")
      .run(JSON.stringify(entries));
  });
}

const consentOf = (dbPath) => JSON.parse(withDb(dbPath, (db) =>
  db.prepare("SELECT value FROM dashboard_settings WHERE key = 'llm_cloud_door_rows'").get().value));

function alertCodes(alertsRoot) {
  const dir = join(alertsRoot, "pending");
  let names;
  try { names = readdirSync(dir).filter((n) => n.endsWith(".json")); } catch { return []; }
  return names.sort().map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")));
}

/** Every TEXT cell of every user table that contains `needle`. */
function rowsHolding(dbPath, needle) {
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  const hits = [];
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all()
      .map((r) => r.name);
    for (const table of tables) {
      let columns;
      try { columns = db.prepare(`PRAGMA table_info("${table}")`).all(); } catch { continue; }
      for (const column of columns) {
        try {
          const hit = db.prepare(`SELECT 1 AS hit FROM "${table}" WHERE CAST("${column.name}" AS TEXT) LIKE ? LIMIT 1`)
            .get(`%${needle}%`);
          if (hit) hits.push(`${table}.${column.name}`);
        } catch { /* virtual table or a type it cannot cast */ }
      }
    }
  } finally {
    db.close();
  }
  return hits;
}

// ─── the happy path ────────────────────────────────────────────────────────

test("a pass seals every plaintext cell, backs up first, rewrites consent, and leaves updated_at/lamport_ts alone", async (t) => {
  const inst = await instance(t);
  const plainA = sentinel();
  const plainB = sentinel();
  addProvider(inst.dbPath, [
    { id: "prov-a", api_key: plainA },
    { id: "prov-b", api_key: `  ${plainB}  ` }, // raw bytes are sealed, not a trimmed copy
    { id: "prov-local", api_key: "none" },
    { id: "prov-null", api_key: null },
    { id: "prov-empty", api_key: "" },
  ]);
  setConsent(inst.dbPath, {
    "prov-a": { target: "https://api.example.com/v1", keyFp: legacyConsentFingerprint(SALT, plainA), at: "2026-03-01T00:00:00.000Z", by: "owner" },
    "prov-b": { target: "https://api.example.com/v1", keyFp: "1111111111111111", at: "2026-03-01T00:00:00.000Z", by: "owner" },
  });

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });

  assert.equal(out.deferred, false);
  assert.deepEqual(
    { sealed: out.counts.sealed, alreadySealed: out.counts.alreadySealed, keyless: out.counts.keyless, unreadable: out.counts.unreadable, consentRewritten: out.counts.consentRewritten },
    { sealed: 2, alreadySealed: 0, keyless: 3, unreadable: 0, consentRewritten: 1 },
  );

  // Sealed, opening back to the EXACT bytes.
  const a = providerRow(inst.dbPath, "prov-a");
  const b = providerRow(inst.dbPath, "prov-b");
  assert.equal(parseStoredKey(a.api_key).kind, "envelope");
  assert.equal(openKey({ slotId: "prov-a", stored: a.api_key, key: inst.key }), plainA);
  assert.equal(openKey({ slotId: "prov-b", stored: b.api_key, key: inst.key }), `  ${plainB}  `);
  assert.equal(parseStoredKey(b.api_key).fp, providerKeyFp(plainB), "fp is the trimmed value's");

  // An unseal is not a user edit: the row's stamps do not move.
  for (const row of [a, b]) {
    assert.equal(row.updated_at, "2026-02-02T00:00:00.000Z");
    assert.equal(row.lamport_ts, 7);
  }

  // The sentinels: none and NULL untouched.
  assert.equal(providerRow(inst.dbPath, "prov-local").api_key, "none");
  assert.equal(providerRow(inst.dbPath, "prov-null").api_key, null);
  assert.equal(providerRow(inst.dbPath, "prov-empty").api_key, "");

  // The backup: one verified 0600 copy in a 0700 directory, holding the plaintext.
  const backups = backupFiles(inst.home);
  assert.equal(backups.length, 1);
  assert.equal((statSync(join(inst.home, "secrets")).mode & 0o777), 0o700);
  assert.equal((statSync(backupDirFor(inst.home)).mode & 0o777), 0o700);
  assert.equal((statSync(backups[0]).mode & 0o777), 0o600);
  assert.equal(providerRow(backups[0], "prov-a").api_key, plainA);
  assert.equal(out.counts.backup, backups[0]);
  // No temp file is left behind.
  assert.deepEqual(readdirSync(backupDirFor(inst.home)).filter((n) => n.endsWith(".tmp")), []);

  // Consent: the entry that named the plaintext now names the sealed key.
  const consent = consentOf(inst.dbPath);
  assert.equal(consent["prov-a"].keyFp, sealedConsentFingerprint(SALT, providerKeyFp(plainA)));
  assert.equal(consent["prov-a"].target, "https://api.example.com/v1");
  assert.equal(consent["prov-b"].keyFp, "1111111111111111", "an entry for another key is never rewritten");

  // And the plaintext is nowhere in a live row any more.
  assert.deepEqual(rowsHolding(inst.dbPath, plainA), []);
  assert.deepEqual(rowsHolding(inst.dbPath, plainB), []);
  assert.deepEqual(alertCodes(inst.alertsRoot), [], "a clean pass alerts nobody");
});

test("a second pass is a no-op: everything is already sealed, and no new backup is taken", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);

  const first = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(first.counts.sealed, 1);
  const sealedValue = providerRow(inst.dbPath, "prov-a").api_key;

  const second = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(second.deferred, false);
  assert.deepEqual(
    { sealed: second.counts.sealed, alreadySealed: second.counts.alreadySealed, keyless: second.counts.keyless },
    { sealed: 0, alreadySealed: 1, keyless: 0 },
  );
  assert.equal(second.counts.backup, null, "nothing was written, so nothing was backed up");
  assert.equal(providerRow(inst.dbPath, "prov-a").api_key, sealedValue);
  assert.equal(backupFiles(inst.home).length, 1);
});

test("malformed cells and envelopes sealed under another key are counted unreadable and left byte-identical", async (t) => {
  const inst = await instance(t);
  const malformed = "pk1:0123456789abcdef:not-a-fingerprint:AAAA";
  const foreign = sealKey({ slotId: "prov-foreign", plaintext: sentinel(), key: OTHER_KEY });
  const plain = sentinel();
  addProvider(inst.dbPath, [
    { id: "prov-malformed", api_key: malformed },
    { id: "prov-foreign", api_key: foreign },
    { id: "prov-a", api_key: plain },
  ]);

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.counts.sealed, 1);
  assert.equal(out.counts.unreadable, 2);
  assert.equal(out.counts.alreadySealed, 0);
  assert.equal(providerRow(inst.dbPath, "prov-malformed").api_key, malformed);
  assert.equal(providerRow(inst.dbPath, "prov-foreign").api_key, foreign);
  assert.equal(openKey({ slotId: "prov-a", stored: providerRow(inst.dbPath, "prov-a").api_key, key: inst.key }), plain);
  // A foreign envelope is not something this home can read, but it blocks a mint.
  assert.deepEqual(alertCodes(inst.alertsRoot), []);
});

// ─── refusals (design §3.2) ────────────────────────────────────────────────

test("no key file with a sealed row already on the instance: REFUSED, KEY_SAVE_REFUSED alerted, nothing written", async (t) => {
  const inst = await instance(t, { key: false });
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  // A sealed row from a lost key file: this home must never mint over it.
  withDb(inst.dbPath, (db) => db.prepare("UPDATE providers SET api_key = ? WHERE id = 'prov-a'")
    .run(sealKey({ slotId: "prov-a", plaintext: plain, key: OTHER_KEY })));
  addProvider(inst.dbPath, [{ id: "prov-b", api_key: sentinel() }]);

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "key-missing");
  assert.equal(out.counts.sealed, 0);

  const alerts = alertCodes(inst.alertsRoot);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].code, SWEEP_ALERTS.KEY_MISSING);
  assert.equal(alerts[0].body, KEY_SAVE_REFUSED, "the alert body is the one shared refusal sentence");
  // Nothing was minted, nothing was backed up, nothing was sealed.
  assert.equal(loadKeychainKey({ crowHome: inst.home }), null);
  assert.equal(backupFiles(inst.home).length, 0);
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-b").api_key).kind, "plain");
});

test("a missing key with crow_keychain rows is refused too: a new key would orphan the add-on secrets", async (t) => {
  const inst = await instance(t, { key: false });
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);
  withDb(inst.dbPath, (db) => db.prepare(
    "INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin) VALUES ('extension', 'x', 'b', 'E', 'blob', ?, 'typed')",
  ).run(OTHER_KEY.id));

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "key-missing");
  assert.equal(loadKeychainKey({ crowHome: inst.home }), null);
});

test("a missing key with nothing to lose mints this instance's first key (and mintIfSafe=false refuses)", async (t) => {
  const inst = await instance(t, { key: false });
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }, { id: "prov-local", api_key: "none" }]);

  const refused = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, mintIfSafe: false });
  assert.equal(refused.deferred, true);
  assert.equal(refused.reason, "key-missing");
  assert.equal(loadKeychainKey({ crowHome: inst.home }), null);
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-a").api_key).kind, "plain");

  const minted = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(minted.deferred, false);
  assert.equal(minted.counts.sealed, 1);
  const key = loadKeychainKey({ crowHome: inst.home });
  assert.ok(key, "the pass minted a key");
  assert.equal(openKey({ slotId: "prov-a", stored: providerRow(inst.dbPath, "prov-a").api_key, key }), plain);
});

test("a damaged key file is refused, never replaced", async (t) => {
  const inst = await instance(t, { key: false });
  mkdirSync(join(inst.home, "secrets"), { recursive: true, mode: 0o700 });
  writeFileSync(keychainKeyPath(inst.home), "{\"v\":1,\"id\":\"short\",\"key\":\"AAAA\"}\n", { mode: 0o600 });
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "key-invalid");
  assert.equal(readFileSync(keychainKeyPath(inst.home), "utf8"), "{\"v\":1,\"id\":\"short\",\"key\":\"AAAA\"}\n",
    "a restorable key file is never overwritten");
  assert.equal(alertCodes(inst.alertsRoot)[0].code, SWEEP_ALERTS.KEY_MISSING);
});

test("a database that belongs to another Crow home is refused with the home-mismatch alert", async (t) => {
  const inst = await instance(t);
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);
  const otherHome = join(inst.home, "another-instance");
  mkdirSync(otherHome, { recursive: true, mode: 0o700 });

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: otherHome });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "home-mismatch");
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-a").api_key).kind, "plain");
  const alerts = alertCodes(inst.alertsRoot);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].code, SWEEP_ALERTS.HOME_MISMATCH);
  assert.equal(alerts[0].body, null);
});

test("a store with no providers table defers quietly (no alert, no backup)", async (t) => {
  const inst = await instance(t);
  withDb(inst.dbPath, (db) => db.exec("DROP TABLE providers"));

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "providers-absent");
  assert.deepEqual(alertCodes(inst.alertsRoot), []);
  assert.equal(backupFiles(inst.home).length, 0);
});

test("an unreadable database file defers with the db-error alert and no driver message", async (t) => {
  const inst = await instance(t);
  writeFileSync(inst.dbPath, "this is not a sqlite database at all\n");

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "db-error");
  assert.deepEqual(Object.keys(out).sort(), ["counts", "deferred", "reason"],
    "a deferral carries a reason token — never a driver message");

  const alerts = alertCodes(inst.alertsRoot);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].code, SWEEP_ALERTS.DB_ERROR);
  assert.ok(!JSON.stringify(alerts[0]).includes("sqlite"), "no driver text in the alert");
});

test("a backup that cannot be created refuses before anything is written", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  // secrets/backups exists as a FILE, so the backup dir cannot be created.
  mkdirSync(join(inst.home, "secrets"), { recursive: true, mode: 0o700 });
  writeFileSync(join(inst.home, "secrets", "backups"), "not a directory\n");

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, true);
  assert.equal(out.reason, "backup-failed");
  assert.equal(providerRow(inst.dbPath, "prov-a").api_key, plain, "nothing was sealed");
  assert.equal(alertCodes(inst.alertsRoot)[0].code, SWEEP_ALERTS.BACKUP_FAILED);
});

test("M2 retention: the oldest pre-seal copy plus the newest two, and nothing else", async (t) => {
  const inst = await instance(t);
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);
  const dir = backupDirFor(inst.home);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const daysAgo = (d) => (Date.now() - d * 24 * 60 * 60 * 1000) / 1000;
  const plant = (name, at) => {
    const path = join(dir, name);
    writeFileSync(path, "placeholder\n", { mode: 0o600 });
    utimesSync(path, at, at);
  };
  plant("crow-pre-seal-2026-01-01T00-00-00-000Z.db", daysAgo(40));   // the first copy: kept
  plant("crow-pre-seal-2026-01-02T00-00-00-000Z.db", daysAgo(30));   // past the cap: deleted
  plant("crow-pre-seal-2026-01-03T00-00-00-000Z.db", daysAgo(2));    // newest two: kept
  plant("crow-pre-seal-2026-01-04T00-00-00-000Z.db", daysAgo(1 / 24)); // fresh: no new copy taken

  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, false);
  assert.equal(out.counts.backup, null, "a verified copy from within a day is reused, not duplicated");

  const left = readdirSync(dir).filter((n) => n.endsWith(".db")).sort();
  assert.deepEqual(left, [
    "crow-pre-seal-2026-01-01T00-00-00-000Z.db",
    "crow-pre-seal-2026-01-03T00-00-00-000Z.db",
    "crow-pre-seal-2026-01-04T00-00-00-000Z.db",
  ], `oldest pre-seal copy + newest two: ${left.join(", ")}`);
});

test("M2: a fresh pass takes at most one copy a day, so a bot cannot fill the disk", async (t) => {
  const inst = await instance(t);
  const dir = backupDirFor(inst.home);
  for (let i = 0; i < 3; i += 1) {
    addProvider(inst.dbPath, [{ id: `prov-${i}`, api_key: sentinel() }]);
    const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
    assert.equal(out.deferred, false);
    assert.equal(out.counts.sealed, 1);
  }
  assert.equal(readdirSync(dir).filter((n) => n.endsWith(".db")).length, 1,
    "three passes in one day leave exactly one copy");
  // A day later the copy is no longer fresh: the next pass takes its own.
  const only = readdirSync(dir).filter((n) => n.endsWith(".db"))[0];
  const old = (Date.now() - 2 * 24 * 60 * 60 * 1000) / 1000;
  utimesSync(join(dir, only), old, old);
  addProvider(inst.dbPath, [{ id: "prov-later", api_key: sentinel() }]);
  const later = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(later.counts.sealed, 1);
  assert.ok(later.counts.backup, "a copy older than a day does not stand in for this pass");
});

test("L4: nothing is pruned while any envelope on the instance is unreadable", async (t) => {
  const inst = await instance(t);
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);
  // A cell nothing can open: the copies are the only way back, so retention stops.
  addProvider(inst.dbPath, [{ id: "prov-bad", api_key: "pk1:0123456789abcdef:not-a-fingerprint:AAAA" }]);
  const dir = backupDirFor(inst.home);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const olds = [];
  for (let i = 1; i <= 4; i += 1) {
    const name = `crow-pre-seal-2026-02-0${i}T00-00-00-000Z.db`;
    const path = join(dir, name);
    writeFileSync(path, "placeholder\n", { mode: 0o600 });
    const at = (Date.now() - (40 - i) * 24 * 60 * 60 * 1000) / 1000;
    utimesSync(path, at, at);
    olds.push(name);
  }
  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, false);
  assert.equal(out.counts.unreadable, 1);
  const left = readdirSync(dir).filter((n) => n.endsWith(".db"));
  for (const name of olds) assert.ok(left.includes(name), `${name} survived: an unreadable envelope means no deletion at all`);
});

// ─── freed-space residue (review round 1 H3, M3) ───────────────────────────

/** The raw bytes of crow.db and its -wal (the two files a plaintext page can sit in). */
function rawDatabaseBytes(dbPath) {
  const parts = [];
  for (const file of [dbPath, `${dbPath}-wal`]) {
    try { parts.push(readFileSync(file)); } catch { /* absent */ }
  }
  return Buffer.concat(parts);
}

const holdsBytes = (dbPath, value) => rawDatabaseBytes(dbPath).indexOf(Buffer.from(value, "utf8")) !== -1;

/** An earlier write of `plain` into a row that was then deleted: its bytes stay in a free page. */
function plantFreedPage(dbPath, plain) {
  withDb(dbPath, (db) => {
    db.pragma("secure_delete = OFF"); // what an older build (or another connection) left on
    db.exec("CREATE TABLE IF NOT EXISTS scratch_junk (id INTEGER PRIMARY KEY, payload TEXT)");
    db.prepare("INSERT INTO scratch_junk (payload) VALUES (?)").run("x".repeat(300) + plain + "y".repeat(300));
    db.exec("DELETE FROM scratch_junk");
  });
}

function plantResidueMarker(home) {
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  writeFileSync(residueStatePath(home), JSON.stringify({ residue: "pending", at: "2026-03-01T00:00:00.000Z" }) + "\n", { mode: 0o600 });
}

/** The marker as this home stores it (null when there is none). */
function residueStateOf(home) {
  try { return JSON.parse(readFileSync(residueStatePath(home), "utf8")); } catch { return null; }
}
const residuePendingOf = (home) => residueStateOf(home)?.residue === "pending";

/**
 * Run `fn` with every `VACUUM` counted: the boot-before-listen pass may rebuild
 * the file, and no other pass may (round 2). Restores the patched method always.
 */
async function countVacuums(fn) {
  const original = Database.prototype.exec;
  let vacuums = 0;
  Database.prototype.exec = function exec(sql, ...rest) {
    if (/^\s*VACUUM\b/i.test(String(sql))) vacuums += 1;
    return original.call(this, sql, ...rest);
  };
  try {
    return { out: await fn(), vacuums };
  } finally {
    Database.prototype.exec = original;
  }
}

test("H3: the boot-before-listen pass (allowVacuum) clears a plaintext an EARLIER write left in a freed page", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  plantFreedPage(inst.dbPath, plain);
  assert.equal(holdsBytes(inst.dbPath, plain), true, "the fixture really leaves the value in the file's bytes");

  const { out, vacuums } = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  assert.equal(out.deferred, false);
  assert.equal(out.counts.sealed, 1);
  assert.equal(vacuums, 1, "the pre-listen pass rebuilds the file");
  assert.equal(out.counts.residue, undefined, "the freed space was reclaimed and verified in the same pass");
  assert.deepEqual(rowsHolding(inst.dbPath, plain), [], "no live cell holds it");
  assert.equal(holdsBytes(inst.dbPath, plain), false, "no byte of it survives in crow.db or its -wal");
  assert.equal(existsSync(residueStatePath(inst.home)), false, "nothing left to retry");
});

test("H3 round 2: a pass without allowVacuum (post-listen boot, hourly tick, 0040) seals but NEVER rebuilds the file — it persists residue pending", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  plantFreedPage(inst.dbPath, plain);

  const { out, vacuums } = await countVacuums(() => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home }));
  assert.equal(out.deferred, false);
  assert.equal(out.counts.sealed, 1, "the key is still sealed");
  assert.equal(vacuums, 0, "only the pre-listen pass may VACUUM");
  assert.equal(out.counts.residue, "pending");
  assert.equal(holdsBytes(inst.dbPath, plain), true, "the residue is still there, on purpose");
  assert.equal(residuePendingOf(inst.home), true, "the marker tells the next boot's pass to look");
  assert.equal(statSync(residueStatePath(inst.home)).mode & 0o777, 0o600, "the marker is 0600");
  assert.deepEqual(alertCodes(inst.alertsRoot), [], "a pass that was never allowed to vacuum rings nothing");
});

test("H3 round 2: migration 0040's pass never VACUUMs either, and leaves the residue for the boot pass", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  plantFreedPage(inst.dbPath, plain);
  withDb(inst.dbPath, (db) => {
    db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, sha TEXT)");
    const record = db.prepare("INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, datetime('now'))");
    for (const name of readdirSync(MIGRATIONS_DIR)) {
      if (!/^\d{4}-[a-z0-9-]+\.mjs$/.test(name)) continue;
      const id = name.replace(/\.mjs$/, "");
      if (id !== "0040-seal-provider-keys") record.run(id);
    }
  });

  const { out: result, vacuums } = await countVacuums(() => runMigrations({
    migrationsDir: MIGRATIONS_DIR, dbPath: inst.dbPath, tasksDbPath: join(inst.dataDir, "tasks.db"), log: () => {},
  }));
  assert.deepEqual(result.applied, ["0040-seal-provider-keys"], "the migration applied");
  assert.equal(vacuums, 0, "the migration pass never rebuilds crow.db");
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-a").api_key).kind, "envelope", "the key is sealed");
  assert.equal(residuePendingOf(inst.home), true, "the boot pass gets to finish it");

  // And the next boot's pre-listen pass does finish it.
  const { out: boot, vacuums: bootVacuums } = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  assert.equal(boot.deferred, false);
  assert.equal(bootVacuums, 1);
  assert.equal(holdsBytes(inst.dbPath, plain), false);
  assert.equal(residuePendingOf(inst.home), false, "the marker is gone once the files scan clean");
});

test("H3: a later pass keeps clearing residue from the persisted marker, with no plaintext of its own", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  // The boot pass seals it and finds nothing to rebuild yet.
  assert.equal((await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true })).counts.sealed, 1);

  // An old binary writes the same value again after the seal, then deletes the row;
  // a pass could not reclaim it and left the marker.
  plantFreedPage(inst.dbPath, plain);
  plantResidueMarker(inst.home);
  assert.equal(holdsBytes(inst.dbPath, plain), true);

  // The hourly pass: no plaintext cell at all, so the needles come from OPENING
  // the envelopes with this home's key — and it may not rebuild the file. (The
  // flag reset models a LATER boot: the pass that ran at boot is long done, and a
  // marker is exactly what tells this one to read the files again.)
  _resetResidueBootScanForTest();
  const hourly = await countVacuums(() => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home }));
  assert.equal(hourly.out.deferred, false);
  assert.equal(hourly.out.counts.sealed, 0);
  assert.equal(hourly.vacuums, 0, "an hourly tick never rebuilds crow.db");
  assert.equal(hourly.out.counts.residue, "pending");
  assert.equal(holdsBytes(inst.dbPath, plain), true);
  assert.equal(residuePendingOf(inst.home), true, "the marker stays for the next boot");

  // The boot pass that finds it again clears it.
  const out = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  assert.equal(out.out.deferred, false);
  assert.equal(out.out.counts.residue, undefined, "cleared without a plaintext in hand");
  assert.equal(out.vacuums, 1);
  assert.equal(holdsBytes(inst.dbPath, plain), false);
  assert.equal(existsSync(residueStatePath(inst.home)), false, "the marker is gone");
});

test("H3 round 2: without room for a second copy the boot pass skips the rebuild, keeps residue pending, and rings ONE bell", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  assert.equal((await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true })).counts.sealed, 1);
  plantFreedPage(inst.dbPath, plain);
  plantResidueMarker(inst.home);

  _setFreeSpaceForTest(() => 0);
  try {
    const first = await countVacuums(
      () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
    assert.equal(first.vacuums, 0, "no rebuild on a disk without room for it");
    assert.equal(first.out.counts.residue, "pending");
    assert.equal(holdsBytes(inst.dbPath, plain), true);
    assert.equal(residuePendingOf(inst.home), true);
    assert.equal(residueStateOf(inst.home).vacuumAlerted, true, "the period remembers its one bell");
    const alerts = alertCodes(inst.alertsRoot);
    assert.equal(alerts.length, 1, "exactly one alert");
    assert.equal(alerts[0].code, "provider-keys-vacuum-skipped");
    assert.equal(alerts[0].title, "Crow alert", "the default title, no body");
    assert.equal(alerts[0].body, null);

    // The next pass on the same unresolved residue: pending, but no second file.
    const second = await countVacuums(
      () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
    assert.equal(second.vacuums, 0);
    assert.equal(second.out.counts.residue, "pending");
    assert.equal(alertCodes(inst.alertsRoot).length, 1, "one bell per pending period, not per pass");
    // Including a pass that is not allowed to vacuum at all.
    assert.equal((await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home })).counts.residue, "pending");
    assert.equal(alertCodes(inst.alertsRoot).length, 1);
  } finally {
    _setFreeSpaceForTest(null);
  }
  // A fresh pending marker (the remembered bell lost) with the disk healed: the
  // rebuild runs and clears it, so nothing rings.
  plantResidueMarker(inst.home);
  const healed = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  assert.equal(healed.vacuums, 1, "the disk has room again");
  assert.equal(healed.out.counts.residue, undefined);
  assert.equal(existsSync(residueStatePath(inst.home)), false);
  assert.equal(holdsBytes(inst.dbPath, plain), false);
  assert.equal(alertCodes(inst.alertsRoot).length, 1, "no bell: the rebuild went through");

  // A NEW pending period (the old marker was cleared, fresh residue appeared and
  // the disk is full again) rings its own bell.
  _setFreeSpaceForTest(() => 0);
  try {
    plantFreedPage(inst.dbPath, plain);
    plantResidueMarker(inst.home);
    const again = await countVacuums(
      () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
    assert.equal(again.vacuums, 0);
    assert.equal(again.out.counts.residue, "pending");
    assert.equal(alertCodes(inst.alertsRoot).length, 2, "one bell per pending period");
  } finally {
    _setFreeSpaceForTest(null);
  }
});

test("M1: ONE rebuild per pending period — a value also held by a LIVE cell elsewhere is left there, the marker cleared, no rescan after", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  // A LIVE cell outside `providers` holds the same string (a profile blob, a memory,
  // a chat): VACUUM cannot remove it, so every rebuild would find it again.
  withDb(inst.dbPath, (db) => {
    db.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('fixture_note', ?)")
      .run(`a note about ${plain}`);
  });

  const lines = [];
  const { out, vacuums } = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true, log: (l) => lines.push(l) }));
  assert.equal(vacuums, 1, "the rebuild ran — once");
  assert.equal(out.deferred, false);
  assert.equal(out.counts.residue, undefined, "the freed-space job is DONE, not pending");
  assert.equal(existsSync(residueStatePath(inst.home)), false, "no marker: a later pass has nothing to retry");
  assert.ok(
    lines.includes("  provider keys: 1 key(s) also stored elsewhere in the database; free-space wipe done"),
    `the fixed, count-only line: ${lines.join(" | ")}`,
  );
  assert.deepEqual(alertCodes(inst.alertsRoot), [], "nothing left to bell about");
  // What remains is a live row, not freed space — the reason the wipe stops there.
  assert.deepEqual(rowsHolding(inst.dbPath, plain), ["dashboard_settings.value"]);

  // The NEXT boot (a new process's flag) does not vacuum: the marker is gone.
  _resetResidueBootScanForTest();
  const next = await countVacuums(
    () => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  assert.equal(next.vacuums, 0, "the wipe is not repeated on every boot");
  assert.equal(next.out.counts.residue, undefined);
  assert.equal(existsSync(residueStatePath(inst.home)), false);

  // And an hourly pass does not read the whole database: no marker, no scan.
  _resetResidueBootScanForTest();
  let scans = 0;
  _setResidueScanProbeForTest(() => { scans += 1; });
  try {
    const hourly = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
    assert.equal(hourly.deferred, false);
    assert.equal(hourly.counts.residue, undefined);
    assert.equal(scans, 0, "hourly passes rescan only while a marker exists");
  } finally {
    _setResidueScanProbeForTest(null);
  }
});

test("NIT: a pass that runs after the boot pass (same process) does not rescan; a later boot's pass does", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  // The pre-listen pass seals and scans (nothing to reclaim yet).
  assert.equal((await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true })).counts.sealed, 1);
  // Residue it could not have seen, and the marker a later pass meets.
  plantFreedPage(inst.dbPath, plain);
  plantResidueMarker(inst.home);

  let scans = 0;
  _setResidueScanProbeForTest(() => { scans += 1; });
  try {
    const post = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: false });
    assert.equal(post.deferred, false);
    assert.equal(scans, 0, "the boot pass already read this database in this process");
    assert.equal(post.counts.residue, "pending", "the marker is still the truth");
    assert.equal(residuePendingOf(inst.home), true);

    // A NEW process (the next boot, or an hourly tick long after) does the read.
    _resetResidueBootScanForTest();
    const later = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
    assert.ok(scans > 0, "a pass with no earlier scan reads the files");
    assert.equal(later.counts.residue, "pending", "and finds the residue the boot pass left");
  } finally {
    _setResidueScanProbeForTest(null);
  }
});

test("L1: a VACUUM needs room for BOTH copies — 2.1× (db + -wal) on one filesystem, or 1.1× on each of two", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  assert.equal((await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true })).counts.sealed, 1);

  const totalBytes = () => statSync(inst.dbPath).size
    + (existsSync(`${inst.dbPath}-wal`) ? statSync(`${inst.dbPath}-wal`).size : 0);
  const tempDir = mkdtempSync(join(tmpdir(), "crow-pk-temp-"));
  const savedTmp = process.env.SQLITE_TMPDIR;
  process.env.SQLITE_TMPDIR = tempDir;
  t.after(() => {
    if (savedTmp === undefined) delete process.env.SQLITE_TMPDIR; else process.env.SQLITE_TMPDIR = savedTmp;
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  const onTemp = (dir) => resolve(dir) === resolve(tempDir);
  // Only two directories matter: SQLite's temp dir, and the database's own
  // filesystem (a test cannot move a scratch directory between real devices).
  const pendingRun = async () => {
    // An earlier write's freed page is what a rebuild is FOR: plant one per round,
    // since a successful rebuild removes it.
    plantFreedPage(inst.dbPath, plain);
    plantResidueMarker(inst.home);
    return countVacuums(() => sealPlaintextKeys(inst.dbPath, { crowHome: inst.home, allowVacuum: true }));
  };

  // One filesystem carries both copies: 2.0x is not enough, 2.2x is.
  _setDeviceForTest(() => 42);
  _setFreeSpaceForTest(() => Math.floor(totalBytes() * 2.0));
  const short = await pendingRun();
  assert.equal(short.vacuums, 0, "2.1× on the one filesystem is the floor");
  assert.equal(short.out.counts.residue, "pending");
  _setFreeSpaceForTest(() => Math.ceil(totalBytes() * 2.2));
  const roomy = await pendingRun();
  assert.equal(roomy.vacuums, 1, "2.2× lets the rebuild run");
  assert.equal(roomy.out.counts.residue, undefined);

  // Two filesystems: 1.1× of (db + -wal) on the database's own, AND 1.1× of the
  // database on SQLite's temp dir.
  _setDeviceForTest((dir) => (onTemp(dir) ? 7 : 42));
  _setFreeSpaceForTest((dir) => (onTemp(dir) ? 1e12 : Math.floor(totalBytes() * 1.0)));
  const dbShort = await pendingRun();
  assert.equal(dbShort.vacuums, 0, "the database's own filesystem still needs its copy");
  _setFreeSpaceForTest((dir) => (onTemp(dir) ? Math.floor(totalBytes() * 1.0) : Math.ceil(totalBytes() * 1.1)));
  const tempShort = await pendingRun();
  assert.equal(tempShort.vacuums, 0, "and SQLite's temp dir needs room for its copy too");
  _setFreeSpaceForTest(() => Math.ceil(totalBytes() * 1.1));
  const both = await pendingRun();
  assert.equal(both.vacuums, 1, "1.1× on each side is enough when the copies land apart");
  assert.equal(both.out.counts.residue, undefined);
  assert.equal(holdsBytes(inst.dbPath, plain), false);
  assert.equal(alertCodes(inst.alertsRoot).filter((a) => a.code === "provider-keys-vacuum-skipped").length, 3,
    "each pending period that could not rebuild rang once");
});

test("NIT: the marker's temp file is created exclusively under a random name, never over a stale one", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  plantFreedPage(inst.dbPath, plain);
  mkdirSync(join(inst.home, "secrets"), { recursive: true, mode: 0o700 });
  // The OLD deterministic temp name, left behind by a writer that was killed.
  const stale = `${residueStatePath(inst.home)}.${process.pid}.tmp`;
  writeFileSync(stale, "half-written\n", { mode: 0o600 });

  // A pass that may not vacuum persists the marker (keepResiduePending).
  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.counts.residue, "pending");
  assert.equal(residuePendingOf(inst.home), true, "the marker was written");
  assert.equal(readFileSync(stale, "utf8"), "half-written\n", "the stale temp file is never adopted or rewritten");
  assert.deepEqual(
    readdirSync(join(inst.home, "secrets")).filter((n) => n.endsWith(".tmp")),
    [stale.slice(stale.lastIndexOf("/") + 1)],
    "no temp file is left behind by this write",
  );
  assert.equal(statSync(residueStatePath(inst.home)).mode & 0o777, 0o600);
});

test("H3/M3: without a key that opens an envelope the marker stays pending, on a non-deferred result", async (t) => {
  const inst = await instance(t);
  // An envelope this home cannot open: no needle can be derived from it.
  addProvider(inst.dbPath, [
    { id: "prov-foreign", api_key: sealKey({ slotId: "prov-foreign", plaintext: sentinel(), key: OTHER_KEY }) },
  ]);
  plantResidueMarker(inst.home);
  const out = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, false, "a residue retry is not a deferral");
  assert.equal(out.counts.residue, "pending");
  assert.equal(existsSync(residueStatePath(inst.home)), true, "the next pass tries again");
  assert.equal(statSync(residueStatePath(inst.home)).mode & 0o777, 0o600, "the marker is 0600");
});

// ─── only the pre-listen pass may rebuild the file (round 2) ───────────────

test("the wiring: allowVacuum is true only in the boot pass that runs before the listeners open", () => {
  const read = (rel) => readFileSync(join(REPO, rel), "utf8");
  const gateway = read("servers/gateway/index.js");
  const bootAt = gateway.indexOf("allowVacuum: true");
  assert.ok(bootAt > 0, "the gateway's own boot pass asks for the rebuild");
  assert.ok(gateway.indexOf("app.listen(") > bootAt, "and it runs BEFORE the HTTP listeners open");
  for (const rel of [
    "servers/gateway/boot/post-listen.js",
    "servers/gateway/boot/admin-api.js",
    "scripts/migrations/0040-seal-provider-keys.mjs",
  ]) {
    const src = read(rel);
    assert.equal(src.includes("allowVacuum: true"), false, `${rel} never rebuilds the file`);
    assert.equal(src.includes("allowVacuum: false"), true, `${rel} says so explicitly`);
  }
});

// ─── the unseal reversal ───────────────────────────────────────────────────

test("unsealAllKeys puts the exact bytes back, backs up first, and leaves the stamps alone", async (t) => {
  const inst = await instance(t);
  const plainA = sentinel();
  const plainB = `  ${sentinel()}\n`;
  addProvider(inst.dbPath, [
    { id: "prov-a", api_key: plainA },
    { id: "prov-b", api_key: plainB },
    { id: "prov-local", api_key: "none" },
  ]);
  const sealedRun = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(sealedRun.counts.sealed, 2);
  const sealsBefore = backupFiles(inst.home).length;

  const out = await unsealAllKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(out.deferred, false);
  assert.equal(out.counts.unsealed, 2);
  assert.equal(out.counts.keyless, 1);
  assert.equal(providerRow(inst.dbPath, "prov-a").api_key, plainA);
  assert.equal(providerRow(inst.dbPath, "prov-b").api_key, plainB);
  assert.equal(providerRow(inst.dbPath, "prov-a").updated_at, "2026-02-02T00:00:00.000Z");
  assert.equal(providerRow(inst.dbPath, "prov-a").lamport_ts, 7);

  const names = backupFiles(inst.home).map((p) => p.split("/").pop());
  assert.equal(names.length, sealsBefore + 1);
  assert.ok(names.some((n) => n.startsWith("crow-pre-unseal-")), names.join(", "));
  assert.equal((statSync(out.counts.backup).mode & 0o777), 0o600);
  // The unseal backup holds the SEALED cells — the state it can be rolled back to.
  assert.equal(parseStoredKey(providerRow(out.counts.backup, "prov-a").api_key).kind, "envelope");
});

test("unsealAllKeys refuses without a key file, and writes nothing", async (t) => {
  const inst = await instance(t);
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sentinel() }]);
  await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  const sealedValue = providerRow(inst.dbPath, "prov-a").api_key;
  assert.equal(parseStoredKey(sealedValue).kind, "envelope");

  // The key file vanishes: nothing can be opened, so nothing is unsealed.
  rmSync(keychainKeyPath(inst.home), { force: true });
  const backupsBefore = backupFiles(inst.home).length;

  const refused = await unsealAllKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(refused.deferred, true);
  assert.equal(refused.reason, "key-missing");
  assert.equal(refused.counts.unsealed, 0);
  assert.equal(providerRow(inst.dbPath, "prov-a").api_key, sealedValue, "the sealed cell is untouched");
  assert.equal(backupFiles(inst.home).length, backupsBefore, "a refusal takes no backup");
  assert.equal(alertCodes(inst.alertsRoot).at(-1).code, SWEEP_ALERTS.KEY_MISSING);
});

// ─── the migration entry (0040) ─────────────────────────────────────────────

test("migration 0040 runs the pass through the real registry; a refusal is a deferral, never an applied row", async (t) => {
  const inst = await instance(t, { key: false });
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }, { id: "prov-sealed", api_key: "none" }]);
  withDb(inst.dbPath, (db) => {
    // A realistic source: every other migration is already recorded.
    db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, sha TEXT)");
    const record = db.prepare("INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, datetime('now'))");
    for (const name of readdirSync(MIGRATIONS_DIR)) {
      if (!/^\d{4}-[a-z0-9-]+\.mjs$/.test(name)) continue;
      const id = name.replace(/\.mjs$/, "");
      if (id !== "0040-seal-provider-keys") record.run(id);
    }
    // A sealed row already on the instance, plus a lost key file: a refusal.
    db.prepare("UPDATE providers SET api_key = ? WHERE id = 'prov-sealed'")
      .run(sealKey({ slotId: "prov-sealed", plaintext: sentinel(), key: OTHER_KEY }));
  });
  const recordedCount = withDb(inst.dbPath, (db) => db.prepare("SELECT COUNT(*) AS c FROM schema_migrations").get().c);
  assert.ok(recordedCount > 30, `the fixture records every other migration (recorded ${recordedCount})`);

  const settings = { migrationsDir: MIGRATIONS_DIR, dbPath: inst.dbPath, tasksDbPath: join(inst.dataDir, "tasks.db"), log: () => {} };
  const refused = await runMigrations(settings);
  assert.deepEqual(refused.deferred, ["0040-seal-provider-keys"]);
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-a").api_key).kind, "plain", "nothing was sealed");

  // Give the instance its key: the retry applies, and the plaintext is sealed.
  const key = createKeychainKey({ crowHome: inst.home });
  const applied = await runMigrations(settings);
  const again = await runMigrations(settings);

  // A refusal is a deferral, never an applied row; with a key, the retry seals.
  assert.deepEqual(refused.applied, [], "first call applied");
  assert.deepEqual(refused.deferred, ["0040-seal-provider-keys"], "first call deferred");
  assert.deepEqual(applied.applied, ["0040-seal-provider-keys"], "second call applied");
  assert.equal(openKey({ slotId: "prov-a", stored: providerRow(inst.dbPath, "prov-a").api_key, key }), plain);
  assert.deepEqual(again.applied, [], "third call applied");
  assert.ok(again.skipped.includes("0040-seal-provider-keys"), "once recorded, the pass is skipped");
  assert.equal(again.skipped.length, 42, "every migration but the one this run applied is skipped (0042-reports-pickup is the newest)");

  // The module's own contract: id equals the file name, and a rollback is unsafe.
  const mod = await import("../scripts/migrations/0040-seal-provider-keys.mjs");
  assert.equal(mod.id, "0040-seal-provider-keys");
  assert.equal(mod.rollbackSafe, false);
});

// ─── secret hygiene ────────────────────────────────────────────────────────

test("hygiene: a pass that seals, and one that refuses, never repeat a key on any surface", async (t) => {
  const out = captureOutput(t);
  const inst = await instance(t);
  const sealedPlain = sentinel();
  const refusedPlain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: sealedPlain }]);

  const ok = await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  assert.equal(ok.deferred, false);
  assert.equal(JSON.stringify(ok).includes(sealedPlain), false);

  // Now a refusal, with a plaintext in hand: a foreign envelope is already on
  // the instance, so a missing key must never mint over it.
  const bare = await instance(t, { key: false });
  addProvider(bare.dbPath, [{ id: "prov-sealed", api_key: "none" }, { id: "prov-a", api_key: refusedPlain }]);
  withDb(bare.dbPath, (db) => db.prepare("UPDATE providers SET api_key = ? WHERE id = 'prov-sealed'")
    .run(sealKey({ slotId: "prov-sealed", plaintext: refusedPlain, key: OTHER_KEY })));
  const refused = await sealPlaintextKeys(bare.dbPath, { crowHome: bare.home });
  assert.equal(refused.deferred, true);
  assert.equal(JSON.stringify(refused).includes(refusedPlain), false);

  const text = out.text();
  for (const value of [sealedPlain, refusedPlain, sealedPlain.trim(), refusedPlain.trim()]) {
    assert.equal(text.includes(value), false, "nothing printed a key");
  }
  for (const root of [inst.alertsRoot, bare.alertsRoot]) {
    for (const alert of alertCodes(root)) {
      assert.equal(JSON.stringify(alert).includes(sealedPlain), false);
      assert.equal(JSON.stringify(alert).includes(refusedPlain), false);
    }
  }
  // The sealed value's envelope is not a surface either.
  assert.equal(text.includes(providerRow(inst.dbPath, "prov-a").api_key.slice(0, 24)), false);
});

// ─── the unseal CLI ────────────────────────────────────────────────────────

test("the unseal tool needs --yes, prints counts only, and exits 1 on a refusal", async (t) => {
  const inst = await instance(t);
  const plain = sentinel();
  addProvider(inst.dbPath, [{ id: "prov-a", api_key: plain }]);
  await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });

  const run = (...args) => spawnSync(process.execPath, [UNSEAL_TOOL, ...args], {
    cwd: REPO, encoding: "utf8", env: { ...process.env },
  });

  const noYes = run("--crow-home", inst.home);
  assert.equal(noYes.status, 1);
  assert.match(noYes.stderr, /--yes is required/);
  assert.equal(parseStoredKey(providerRow(inst.dbPath, "prov-a").api_key).kind, "envelope", "nothing was unsealed");

  const ok = run("--crow-home", inst.home, "--yes");
  assert.equal(ok.status, 0, ok.stderr || ok.stdout);
  assert.match(ok.stdout, /^outcome: unsealed$/m);
  assert.match(ok.stdout, /^unsealed: 1;/m);
  assert.equal(ok.stdout.includes(plain), false, "the tool never prints a key");
  assert.equal(providerRow(inst.dbPath, "prov-a").api_key, plain);

  // A second run has nothing to open, but still succeeds with a zero count.
  const again = run("--crow-home", inst.home, "--yes");
  assert.equal(again.status, 0, again.stderr || again.stdout);
  assert.match(again.stdout, /^unsealed: 0;/m);

  // Without its key file the tool refuses and exits 1.
  await sealPlaintextKeys(inst.dbPath, { crowHome: inst.home });
  rmSync(keychainKeyPath(inst.home), { force: true });
  const refused = run("--crow-home", inst.home, "--yes");
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /^outcome: refused \(key-missing\)$/m);
});