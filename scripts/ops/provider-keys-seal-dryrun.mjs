#!/usr/bin/env node
/**
 * Provider-key seal DRY RUN (design §4): run the real migration 0040 against a
 * COPY of a live instance's databases, inside a scratch Crow home, and report
 * what the real pass would do — counts and PASS/STOP, nothing else.
 *
 *   node scripts/ops/provider-keys-seal-dryrun.mjs \
 *     --source-home <dir> --scratch <dir> [--label <text>] [--omit-key] [--strict-source]
 *
 * The source instance is treated as read-only evidence, never as a target:
 *   * crow.db and tasks.db are copied with better-sqlite3's ONLINE backup API
 *     from a READ-ONLY handle (an external open of a live WAL crow.db that
 *     writes is the one thing that must never happen);
 *   * the keychain key is copied 0600 unless --omit-key, which models the
 *     "crow.db restored onto a machine without its key" case;
 *   * the source home is checked for exactly the things THIS tool or the seal
 *     pass could write there (checks 19–22): the key file, the provider-keys
 *     backup dir, a seal alert spooled under alerts/, and the providers rows /
 *     0040 bookkeeping row. A live gateway keeps writing crow.db, its -wal and
 *     its logs while a dry run is in progress, so a whole-tree fingerprint on a
 *     LIVE home can only ever STOP on the gateway's own writes — it is offered
 *     only with --strict-source, for a stopped home (check 23).
 *
 * The migration runs through the REAL registry (runMigrations with CROW_HOME /
 * CROW_DATA_DIR / CROW_DB_PATH pointed at the scratch home), so what is verified
 * is the production path, not a re-implementation of it.
 *
 * Checks follow design §4's numbering (1–12, all of them gates on a sealed
 * home); the extra evidence checks a live run also needs are 13+.
 *
 * Nothing here prints a key value, an envelope, a key id or a driver message —
 * every output line is buffered and scanned (raw, base64 and hex) before it is
 * written, and a line that would carry a value is withheld (check 12).
 */
import { createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync,
} from "node:fs";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { runMigrations } from "../migrations/runner.mjs";
import { parseStoredKey } from "../../servers/shared/provider-key-shape.js";
import { open as openProviderKey } from "../../servers/gateway/keychain/provider-key-box.js";
import { loadKeychainKey } from "../../servers/gateway/keychain/key.js";
import {
  BACKUP_SUBDIR, legacyConsentFingerprint, sealPlaintextKeys, sealedConsentFingerprint,
} from "../../servers/gateway/keychain/provider-keys-sweep.js";
import { KEY_SAVE_REFUSED } from "../../servers/gateway/addon-secrets-seal.js";

const MIGRATION_ID = "0040-seal-provider-keys";
const REPO = resolve(import.meta.dirname, "..", "..");
const MIGRATIONS_DIR = join(REPO, "scripts", "migrations");
const CONSENT_KEY = "llm_cloud_door_rows";
const CONSENT_SALT_KEY = "llm_cloud_consent_salt";

/** The migration REGISTRY's own tables: it creates and writes them on any run. */
const BOOKKEEPING_TABLES = Object.freeze(["schema_migrations", "schema_migrations_deferred"]);
/** A sqlite_master row that belongs to the registry's own bookkeeping (or its autoindex). */
const isBookkeepingRow = (row) => BOOKKEEPING_TABLES.includes(String(row.name))
  || BOOKKEEPING_TABLES.includes(String(row.tbl_name));
/** The profile blobs a seal must leave byte-equal (design §4 (6)) — dashboard_settings text. */
const PROFILE_KEYS = Object.freeze(["stt_profiles", "tts_profiles", "ai_profiles", "vision_profiles"]);
/** The history/version tables checked for equal counts (design §4 (7)). */
const VERSION_TABLES = Object.freeze(["item_versions", "item_versions_erase", "artifact_versions", "report_versions"]);
/** The alert slugs the seal pass raises — never spooled under the SOURCE home. */
const SEAL_ALERT_MARKERS = Object.freeze(["keychain-key-missing", "provider-keys-"]);
const CHECK12_PREFIX = "check 12 ";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write(
    "usage: node scripts/ops/provider-keys-seal-dryrun.mjs --source-home <dir> --scratch <dir> " +
    "[--label <text>] [--omit-key] [--strict-source]\n",
  );
  process.exit(2);
}

function parseArgs(argv) {
  const out = { label: null, sourceHome: null, scratch: null, omitKey: false, strictSource: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--label") out.label = argv[++i] ?? null;
    else if (arg === "--source-home") out.sourceHome = argv[++i] ?? null;
    else if (arg === "--scratch") out.scratch = argv[++i] ?? null;
    else if (arg === "--omit-key") out.omitKey = true;
    else if (arg === "--strict-source") out.strictSource = true;
    else if (arg === "--help" || arg === "-h") usage();
    else usage(`unexpected argument: ${arg}`);
  }
  if (!out.sourceHome) usage("--source-home is required");
  if (!out.scratch) usage("--scratch is required");
  return out;
}

// ─── small helpers ─────────────────────────────────────────────────────────

const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const sha256Text = (value) => createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
const quoteId = (name) => `"${String(name).replace(/"/g, '""')}"`;

function modeOf(path) {
  try { return statSync(path).mode & 0o777; } catch { return null; }
}

function mode0600(path) {
  return modeOf(path) === 0o600;
}

/** `{present:false}`, or the file's size + mode + sha256 — read-only evidence. */
function fileEvidence(path) {
  let st;
  try { st = statSync(path); } catch { return { present: false }; }
  if (!st.isFile()) return { present: "other" };
  try {
    return { present: true, size: st.size, mode: st.mode & 0o777, sha256: sha256File(path) };
  } catch {
    return { present: "unreadable" };
  }
}

/**
 * A directory's entries (name, whether it is a directory, and a file's sha256),
 * or null when the directory does not exist. Read-only.
 *
 * Used for the two source-side directories the seal could create files in: an
 * "absent before, present after" difference is exactly what a tool-written file
 * looks like.
 */
function dirEvidence(dir) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return null; }
  const out = [];
  for (const entry of entries) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) { out.push(`${entry.name}/\t-`); continue; }
    if (!entry.isFile()) { out.push(`${entry.name}\tother`); continue; }
    try { out.push(`${entry.name}\t${sha256File(abs)}`); } catch { out.push(`${entry.name}\tunreadable`); }
  }
  return out.sort();
}

/** The alert spool's file names per subdirectory, or an empty map when absent. */
function alertNames(home) {
  const out = new Map();
  for (const sub of ["pending", "delivered", "bad"]) {
    let names;
    try { names = readdirSync(join(home, "alerts", sub)).filter((n) => n.endsWith(".json")).sort(); } catch { continue; }
    out.set(sub, names);
  }
  return out;
}

/** Every alert file's text under this home (for the output scan). */
function alertTexts(home) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) { walk(abs); continue; }
      try { out.push(readFileSync(abs, "utf8")); } catch { /* unreadable: nothing to scan */ }
    }
  };
  walk(join(home, "alerts"));
  return out;
}

/** The parses of this home's pending alerts (design §4 (11) wants exactly one). */
function pendingAlerts(home) {
  let names;
  try { names = readdirSync(join(home, "alerts", "pending")).filter((n) => n.endsWith(".json")).sort(); } catch { return []; }
  return names.map((name) => {
    try { return { name, record: JSON.parse(readFileSync(join(home, "alerts", "pending", name), "utf8")) }; }
    catch { return { name, record: null }; }
  });
}

/**
 * Every file under `root`: relative path, size, mtime, sha256. Read-only.
 *
 * Only used behind --strict-source (a STOPPED home). A live gateway rewrites
 * crow.db, its -wal and its logs continuously, so this can never be a gate on a
 * running instance — that is what checks 19–22 are for.
 *
 * `-shm` sidecars are skipped on purpose: a read-only open of a WAL database
 * makes SQLite create that shared-memory scratch file (and drop it again on
 * close). It holds no data, and counting it would turn a harmless open into a
 * false "the source was written" STOP.
 */
function snapshotTree(root) {
  const out = [];
  const walk = (dir, rel) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) { walk(abs, relPath); continue; }
      if (!entry.isFile()) { out.push(`${relPath}\tother`); continue; }
      if (entry.name.endsWith("-shm")) continue;
      try {
        const st = statSync(abs);
        out.push(`${relPath}\t${st.size}\t${Math.round(st.mtimeMs)}\t${sha256File(abs)}`);
      } catch {
        out.push(`${relPath}\tunreadable`);
      }
    }
  };
  walk(root, "");
  return out.sort();
}

function tableExists(db, name) {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(name); } catch { return false; }
}

function quickCheck(path) {
  let db = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    const check = db.pragma("quick_check");
    const verdict = Array.isArray(check) ? String(check[0]?.quick_check ?? check[0]) : String(check);
    return verdict === "ok";
  } catch {
    return false;
  } finally {
    if (db) { try { db.close(); } catch { /* already closed */ } }
  }
}

/** Online copy of a live SQLite file, from a READ-ONLY handle. */
async function copyDatabase(src, dest) {
  // `timeout` installs the busy handler BEFORE the class reads the header: a live
  // gateway may hold a write lock at the exact moment the copy starts.
  const db = new Database(src, { readonly: true, fileMustExist: true, timeout: 15000 });
  try {
    db.pragma("busy_timeout = 15000");
    await db.backup(dest);
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
  chmodSync(dest, 0o600);
  // The copy is ours to write: DELETE journal mode keeps the scratch instance
  // in one self-contained file per database, with no sidecars to leak.
  const copy = new Database(dest);
  try { copy.pragma("journal_mode = DELETE"); } finally { copy.close(); }
  for (const suffix of ["-wal", "-shm"]) {
    try { chmodSync(dest + suffix, 0o600); } catch { /* no sidecar */ }
  }
}

function providerRows(db) {
  return db.prepare("SELECT id, api_key FROM providers ORDER BY id").all();
}

/** `providers.api_key` digests per row id — a change detector that never holds a value. */
function providerRowDigests(db) {
  if (!tableExists(db, "providers")) return [];
  return providerRows(db).map((row) => ({
    id: String(row.id),
    digest: sha256Text(JSON.stringify(row.api_key ?? null)),
  }));
}

/** Has the seal's source-side evidence changed? (design §4 (A.d)) */
function sourceEvidence(path) {
  let db = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true, timeout: 15000 });
    db.pragma("busy_timeout = 15000");
    db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
    const sealed = tableExists(db, "schema_migrations")
      && !!db.prepare("SELECT 1 FROM schema_migrations WHERE id = ?").get(MIGRATION_ID);
    return { rows: providerRowDigests(db), sealed };
  } catch {
    return null;
  } finally {
    if (db) { try { db.close(); } catch { /* already closed */ } }
  }
}

/**
 * A database's schema and per-table row counts, read-only.
 *
 * The registry's own bookkeeping tables are excluded: runMigrations creates them
 * lazily and writes exactly one row into them per run, and that write happens on
 * every run — applied or deferred — so counting it as "the seal changed the
 * database" would STOP every dry run of every home.
 */
function dbState(path) {
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    db.pragma("busy_timeout = 10000");
    const schema = db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").all()
      .filter((row) => !isBookkeepingRow(row));
    const counts = {};
    for (const row of schema) {
      if (row.type !== "table") continue;
      try { counts[row.name] = Number(db.prepare(`SELECT COUNT(*) AS c FROM ${quoteId(row.name)}`).get().c); }
      catch { counts[row.name] = null; }
    }
    return { schema, counts };
  } finally {
    db.close();
  }
}

/**
 * Same schema rows and same count for every table (design §4 (2)). Returns the
 * first difference as a short, value-free description ("schema", "table:<name>").
 */
function dbStateDiff(before, after) {
  if (!before || !after) return "unreadable";
  const wasSchema = new Map(before.schema.map((row) => [`${row.type}:${row.name}`, JSON.stringify(row)]));
  const nowSchema = new Map(after.schema.map((row) => [`${row.type}:${row.name}`, JSON.stringify(row)]));
  for (const key of new Set([...wasSchema.keys(), ...nowSchema.keys()])) {
    if (wasSchema.get(key) !== nowSchema.get(key)) return `schema:${key}`;
  }
  const names = new Set([...Object.keys(before.counts), ...Object.keys(after.counts)]);
  for (const name of names) if (before.counts[name] !== after.counts[name]) return `table:${name}`;
  return null;
}

/**
 * A digest of every table's full content, bookkeeping tables excepted.
 *
 * Used where "the database file's sha256 must be unchanged" is what the design
 * asks for but a file sha cannot express it: runMigrations writes its own
 * bookkeeping row on a REFUSED run too (a fresh deferral row), so the file bytes
 * always move. Everything the SEAL could have written is in here.
 */
function dataDigest(path) {
  const db = new Database(path, { readonly: true, fileMustExist: true });
  const parts = [];
  try {
    db.pragma("busy_timeout = 10000");
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all()
      .map((row) => String(row.name))
      .filter((name) => !BOOKKEEPING_TABLES.includes(name));
    for (const table of tables) {
      let rows;
      try { rows = db.prepare(`SELECT * FROM ${quoteId(table)}`).all().map((row) => JSON.stringify(row)).sort(); }
      catch { rows = ["unreadable"]; }
      parts.push(`${table}\u0000${rows.join("\u0001")}`);
    }
  } catch {
    return "unreadable";
  } finally {
    db.close();
  }
  return createHash("sha256").update(parts.join("\u0002")).digest("hex");
}

/** Every `providers` column except `api_key`, per row — the seal may touch only the key. */
function providerShapes(path) {
  let db = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    if (!tableExists(db, "providers")) return null;
    const keep = db.prepare("PRAGMA table_info(providers)").all()
      .map((column) => String(column.name))
      .filter((name) => name !== "api_key");
    const rows = db.prepare(`SELECT ${keep.map(quoteId).join(", ")} FROM providers ORDER BY id`).all();
    const out = new Map();
    for (const row of rows) {
      out.set(String(row.id), JSON.stringify(keep.map((name) => [name, row[name] ?? null])));
    }
    return out;
  } catch {
    return null;
  } finally {
    if (db) { try { db.close(); } catch { /* already closed */ } }
  }
}

/**
 * The profile blobs (design §4 (6)): `dashboard_settings` rows keyed
 * stt_profiles / tts_profiles / ai_profiles / vision_profiles, plus the
 * per-instance overrides of the same keys, as sha256 per key. That IS the real
 * storage — there is no profile table; every reader goes through
 * readSetting()/writeSetting() on these two.
 */
function profileDigests(path) {
  let db = null;
  const out = new Map();
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    const placeholders = PROFILE_KEYS.map(() => "?").join(", ");
    if (tableExists(db, "dashboard_settings")) {
      const rows = db.prepare(`SELECT key, value FROM dashboard_settings WHERE key IN (${placeholders})`)
        .all(...PROFILE_KEYS);
      for (const row of rows) out.set(`dashboard_settings:${row.key}`, sha256Text(row.value));
    }
    if (tableExists(db, "dashboard_settings_overrides")) {
      const rows = db
        .prepare(`SELECT key, instance_id, value FROM dashboard_settings_overrides WHERE key IN (${placeholders})`)
        .all(...PROFILE_KEYS);
      for (const row of rows) out.set(`overrides:${row.instance_id}:${row.key}`, sha256Text(row.value));
    }
    return out;
  } catch {
    return out;
  } finally {
    if (db) { try { db.close(); } catch { /* already closed */ } }
  }
}

function sameMap(a, b) {
  if (!a || !b) return a === b;
  if (a.size !== b.size) return false;
  for (const [key, value] of a) if (b.get(key) !== value) return false;
  return true;
}

/**
 * Version-table counts and every `USING fts5` table's integrity + doc count
 * (design §4 (7)), for one scratch database.
 *
 * fts5's `integrity-check` is only accepted on a READ-WRITE handle
 * (SQLITE_READONLY otherwise) and writes nothing — the file's sha256 is
 * unchanged by it — so the handle is the scratch copy's own, never the source's.
 */
function versionAndFtsReport(label, path, before) {
  const problems = [];
  let checked = 0;
  if (!before) return { ok: true, checked: 0, problems };
  let after;
  try { after = dbState(path); } catch { return { ok: false, checked, problems: [`${label}: unreadable`] }; }

  for (const table of VERSION_TABLES) {
    const was = before.counts[table];
    const now = after.counts[table];
    if (was === undefined && now === undefined) continue; // absent on this instance
    checked += 1;
    if (was !== now) problems.push(`${label}:${table} count`);
  }

  const fts = before.schema
    .filter((row) => row.type === "table" && /USING\s+fts5/i.test(String(row.sql || "")))
    .map((row) => String(row.name));
  if (fts.length) {
    let db = null;
    try {
      db = new Database(path, { fileMustExist: true });
      db.pragma("busy_timeout = 10000");
      for (const name of fts) {
        checked += 1;
        try { db.prepare(`INSERT INTO ${quoteId(name)}(${quoteId(name)}) VALUES('integrity-check')`).run(); }
        catch { problems.push(`${label}:${name} integrity`); }
      }
    } catch {
      problems.push(`${label}: fts unreadable`);
    } finally {
      if (db) { try { db.close(); } catch { /* already closed */ } }
    }
    for (const name of fts) {
      if (before.counts[name] !== after.counts[name]) problems.push(`${label}:${name} doc count`);
    }
  }
  return { ok: problems.length === 0, checked, problems };
}

/** The files (by basename) in which some plaintext appears RAW. */
function rawScanHits(files, plaintexts) {
  const needles = plaintexts
    .filter((value) => typeof value === "string" && value.length > 0)
    .map((value) => Buffer.from(value, "utf8"));
  if (needles.length === 0) return [];
  const hits = [];
  for (const file of files) {
    if (!existsSync(file)) continue;
    let buf;
    try { buf = readFileSync(file); } catch { continue; }
    for (const needle of needles) if (buf.indexOf(needle) !== -1) { hits.push(file.split("/").pop()); break; }
  }
  return hits;
}

/** The raw, base64 and hex spellings of every plaintext — what output may never carry. */
function secretForms(plaintexts) {
  const forms = new Set();
  for (const value of plaintexts) {
    if (typeof value !== "string" || value === "") continue;
    const bytes = Buffer.from(value, "utf8");
    for (const form of [value, bytes.toString("base64"), bytes.toString("hex")]) {
      if (form.length >= 6) forms.add(form);
    }
  }
  return [...forms];
}

function carriesSecret(texts, forms) {
  if (forms.length === 0) return false;
  const hay = Array.isArray(texts) ? texts.join("\n") : String(texts ?? "");
  return forms.some((form) => hay.includes(form));
}

function readConsentMap(db) {
  try {
    if (!tableExists(db, "dashboard_settings")) return null;
    const rows = db.prepare("SELECT key, value FROM dashboard_settings WHERE key IN (?, ?)").all(CONSENT_KEY, CONSENT_SALT_KEY);
    const byKey = new Map(rows.map((r) => [r.key, r.value]));
    const raw = byKey.get(CONSENT_KEY);
    const salt = byKey.get(CONSENT_SALT_KEY);
    if (typeof raw !== "string" || !raw) return { consent: {}, salt: typeof salt === "string" ? salt : null };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { consent: {}, salt: typeof salt === "string" ? salt : null };
    return { consent: parsed, salt: typeof salt === "string" ? salt : null };
  } catch {
    return null;
  }
}

/** Does any TEXT column of any user table hold `needle`? (Raw, base64 and hex forms.) */
function findPlaintextInRows(db, needle) {
  const forms = [needle, Buffer.from(needle, "utf8").toString("base64"), Buffer.from(needle, "utf8").toString("hex")];
  let tables;
  try {
    tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map((r) => r.name);
  } catch {
    return false;
  }
  for (const table of tables) {
    let columns;
    try {
      columns = db.prepare(`PRAGMA table_info(${JSON.stringify(table)})`).all();
    } catch {
      continue;
    }
    for (const column of columns) {
      for (const form of forms) {
        if (!form) continue;
        try {
          const hit = db
            .prepare(`SELECT 1 AS hit FROM ${JSON.stringify(table)} WHERE CAST(${JSON.stringify(column.name)} AS TEXT) LIKE ? ESCAPE '\\' LIMIT 1`)
            .get(`%${String(form).replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
          if (hit) return true;
        } catch {
          // A non-text column or a virtual table: nothing to scan.
        }
      }
    }
  }
  return false;
}

const verifyCopyFile = (path, providersCount, rowDigests) => {
  let db = null;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
    const check = db.pragma("quick_check");
    const verdict = Array.isArray(check) ? String(check[0]?.quick_check ?? check[0]) : String(check);
    if (verdict !== "ok") return false;
    if (!tableExists(db, "providers")) return false;
    if (Number(db.prepare("SELECT COUNT(*) AS c FROM providers").get()?.c ?? -1) !== providersCount) return false;
    const read = db.prepare("SELECT api_key FROM providers WHERE id = ?");
    for (const { id, digest } of rowDigests) {
      const row = read.get(id);
      if (sha256Text(row?.api_key) !== digest) return false;
    }
    return true;
  } catch {
    return false;
  } finally {
    if (db) { try { db.close(); } catch { /* already closed */ } }
  }
};

/** Run `fn` with the process env pointed at the scratch instance (the pass reads it). */
async function inScratchEnv(scratch, scratchData, scratchCrowDb, fn) {
  const saved = {
    CROW_HOME: process.env.CROW_HOME,
    CROW_DATA_DIR: process.env.CROW_DATA_DIR,
    CROW_DB_PATH: process.env.CROW_DB_PATH,
    CROW_ALLOW_SHARED_DATA_DIR: process.env.CROW_ALLOW_SHARED_DATA_DIR,
  };
  try {
    process.env.CROW_HOME = scratch;
    process.env.CROW_DATA_DIR = scratchData;
    process.env.CROW_DB_PATH = scratchCrowDb;
    process.env.CROW_ALLOW_SHARED_DATA_DIR = "1";
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

// ─── the dry run ───────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const sourceHome = resolve(args.sourceHome);
  const scratch = resolve(args.scratch);

  const checks = [];
  const add = (num, name, pass, detail = null) => {
    const entry = { num, name, pass: !!pass, detail };
    checks.push(entry);
    return entry;
  };

  // Where the source instance keeps its files.
  const sourceCrowDb = [join(sourceHome, "data", "crow.db"), join(sourceHome, "crow.db")].find((p) => existsSync(p)) ?? null;
  const sourceTasksDb = [join(sourceHome, "data", "tasks.db"), join(sourceHome, "tasks.db")].find((p) => existsSync(p)) ?? null;
  const sourceKey = join(sourceHome, "secrets", "keychain.key");
  const sourceBackupDir = join(sourceHome, ...BACKUP_SUBDIR);
  if (!sourceCrowDb) usage(`no crow.db under ${sourceHome} (looked in data/ and the home itself)`);

  // The source is EVIDENCE, and this is the last moment nothing of ours exists:
  // capture exactly the things this tool or the seal could write there.
  const sourceKeyBefore = fileEvidence(sourceKey);
  const sourceBackupBefore = dirEvidence(sourceBackupDir);
  const sourceAlertsBefore = alertNames(sourceHome);
  const sourceTreeBefore = args.strictSource ? snapshotTree(sourceHome) : null;

  // A scratch instance: 0700 home, 0700 data dir, copies of both databases.
  const scratchData = join(scratch, "data");
  const scratchSecrets = join(scratch, "secrets");
  const scratchKey = join(scratchSecrets, "keychain.key");
  mkdirSync(scratch, { recursive: true, mode: 0o700 });
  mkdirSync(scratchData, { recursive: true, mode: 0o700 });
  mkdirSync(scratchSecrets, { recursive: true, mode: 0o700 });
  chmodSync(scratch, 0o700);
  chmodSync(scratchData, 0o700);
  chmodSync(scratchSecrets, 0o700);

  const scratchCrowDb = join(scratchData, "crow.db");
  const scratchTasksDb = join(scratchData, "tasks.db");
  await copyDatabase(sourceCrowDb, scratchCrowDb);
  if (sourceTasksDb) await copyDatabase(sourceTasksDb, scratchTasksDb);
  const tasksShaAfterCopy = sourceTasksDb ? sha256File(scratchTasksDb) : null;

  // Everything the pass must leave exactly as the copy arrived (design §4 (2),
  // (5), (6), (7), (11)): schema + counts, full content digest, provider row
  // shapes, profile blobs, and the source-side evidence BEFORE the seal.
  const crowBefore = dbState(scratchCrowDb);
  const tasksBefore = sourceTasksDb ? dbState(scratchTasksDb) : null;
  const dataDigestAfterCopy = dataDigest(scratchCrowDb);
  const providersBefore = providerShapes(scratchCrowDb);
  const profilesBefore = profileDigests(scratchCrowDb);

  const sourceKeyPresent = sourceKeyBefore.present === true;
  let keyCopied = false;
  if (sourceKeyPresent && !args.omitKey) {
    copyFileSync(sourceKey, scratchKey);
    chmodSync(scratchKey, 0o600);
    keyCopied = true;
  }
  const sourceKeySha = sourceKeyPresent ? sourceKeyBefore.sha256 : null;

  // What the source holds, read off the COPY (the source stays untouched).
  const sourceDb = new Database(scratchCrowDb, { readonly: true, fileMustExist: true });
  const sourceRows = tableExists(sourceDb, "providers") ? providerRows(sourceDb) : [];
  const sourceConsent = readConsentMap(sourceDb);
  const sourceEvidenceBefore = {
    rows: providerRowDigests(sourceDb),
    sealed: tableExists(sourceDb, "schema_migrations")
      && !!sourceDb.prepare("SELECT 1 FROM schema_migrations WHERE id = ?").get(MIGRATION_ID),
  };
  sourceDb.close();
  const plaintextById = new Map();
  for (const row of sourceRows) {
    if (parseStoredKey(row.api_key).kind === "plain") plaintextById.set(row.id, row.api_key);
  }
  const plaintexts = [...plaintextById.values()];

  // The real registry, against the scratch instance only.
  const runLog = [];
  let outcome;
  let registryFailed = false;
  try {
    outcome = await inScratchEnv(scratch, scratchData, scratchCrowDb, () => runMigrations({
      migrationsDir: MIGRATIONS_DIR,
      dbPath: scratchCrowDb,
      tasksDbPath: scratchTasksDb,
      log: (line) => runLog.push(String(line)),
    }));
  } catch {
    // No driver message, no stack: the registry's failure is a STOP below.
    registryFailed = true;
    outcome = { applied: [], skipped: [], deferred: [], newlyDeferred: [] };
    runLog.length = 0;
  }

  const deferralLine = runLog.find((line) => line.startsWith(`${MIGRATION_ID} deferred —`));
  const refusal = outcome.deferred.includes(MIGRATION_ID);
  const refusalReason = refusal ? (/deferred — (.+), will retry$/.exec(deferralLine || "")?.[1] ?? "refused") : null;

  const db = new Database(scratchCrowDb, { readonly: true, fileMustExist: true });
  let counts;
  let foundInCells = 0;
  try {
    const rows = tableExists(db, "providers") ? providerRows(db) : [];
    const scratchById = new Map(rows.map((r) => [r.id, r.api_key]));

    // ── counts ──
    let keyless = 0;
    let unreadable = 0;
    let sealed = 0;
    for (const row of rows) {
      const kind = parseStoredKey(row.api_key).kind;
      if (kind === "none") keyless += 1;
      else if (kind === "malformed") unreadable += 1;
    }
    for (const id of plaintextById.keys()) {
      if (parseStoredKey(scratchById.get(id)).kind === "envelope") sealed += 1;
    }
    counts = { providers: rows.length, plain: plaintextById.size, sealed, keyless, unreadable };

    // ── 1: only the not-yet-applied migration set was 0040 ──
    add(1, "applied set is exactly the seal migration",
      !registryFailed && outcome.applied.every((id) => id === MIGRATION_ID),
      registryFailed ? "the registry stopped" : (outcome.applied.join(",") || "none"));

    // ── 3: every sealed value opens back to the exact key ──
    if (refusal) {
      add(3, "round trip", true, "refused: nothing sealed");
    } else {
      const key = loadKeychainKey({ crowHome: scratch });
      let failures = 0;
      for (const [id, plaintext] of plaintextById) {
        const stored = scratchById.get(id);
        if (parseStoredKey(stored).kind !== "envelope") { failures += 1; continue; }
        if (openProviderKey({ slotId: id, stored, key }) !== plaintext) failures += 1;
      }
      add(3, "round trip", failures === 0, `${failures} failed`);
    }

    // ── 4: no plaintext key is left in a providers row (or, on a refusal, nothing changed) ──
    if (refusal) {
      const unchanged = sourceRows.every((row) => scratchById.get(row.id) === row.api_key);
      add(4, "provider keys as expected", unchanged, "refused: unchanged");
    } else {
      const leftover = rows.filter((row) => parseStoredKey(row.api_key).kind === "plain").length;
      add(4, "provider keys as expected", leftover === 0, `${leftover} left in the clear`);
    }

    // ── 8: the cloud-door consent fingerprints were converted ──
    const scratchConsent = readConsentMap(db);
    if (!sourceConsent || !scratchConsent) {
      add(8, "consent fingerprints", true, "no consent on this instance");
    } else if (refusal) {
      const same = JSON.stringify(sourceConsent.consent) === JSON.stringify(scratchConsent.consent);
      add(8, "consent fingerprints", same, "refused: unchanged");
    } else {
      let expected = 0;
      let wrong = 0;
      const salt = sourceConsent.salt;
      for (const [rowId, entry] of Object.entries(sourceConsent.consent)) {
        const plaintext = plaintextById.get(rowId);
        if (typeof plaintext !== "string" || !entry || typeof entry.keyFp !== "string") continue;
        const legacy = legacyConsentFingerprint(salt, plaintext);
        if (entry.keyFp !== legacy) continue;
        expected += 1;
        const nowEntry = scratchConsent.consent[rowId];
        const fp = parseStoredKey(scratchById.get(rowId));
        const want = fp.kind === "envelope" ? sealedConsentFingerprint(salt, fp.fp) : null;
        if (!nowEntry || nowEntry.keyFp !== want) wrong += 1;
      }
      add(8, "consent fingerprints", wrong === 0, `${expected} converted`);
    }

    // ── 13: the plaintext inventory matches the outcome (a row-level scan) ──
    let found = 0;
    for (const plaintext of plaintexts) if (findPlaintextInRows(db, plaintext)) found += 1;
    foundInCells = found;
    add(13, "no plaintext in any table cell",
      refusal ? found === plaintexts.length : found === 0,
      refusal ? `refused: ${found} left in the clear by design` : `${found} found`);

    // ── 14: the provider rows are all still there ──
    add(14, "provider rows preserved", rows.length === sourceRows.length, `${rows.length}`);
  } finally {
    db.close();
  }

  // ── 2: the schema and every table's row count, crow.db AND tasks.db ──
  const crowAfter = dbState(scratchCrowDb);
  const tasksAfter = sourceTasksDb ? dbState(scratchTasksDb) : null;
  const crowDiff = dbStateDiff(crowBefore, crowAfter);
  const tasksDiff = sourceTasksDb ? dbStateDiff(tasksBefore, tasksAfter) : null;
  add(2, "schema and row counts unchanged",
    !crowDiff && !tasksDiff,
    crowDiff ? `crow.db: ${crowDiff}` : (tasksDiff ? `tasks.db: ${tasksDiff}` : (sourceTasksDb ? "crow.db + tasks.db" : "crow.db")));

  // ── 5: no plaintext key in the database's own bytes (crow.db, -wal, -shm) ──
  const dbFiles = [scratchCrowDb, `${scratchCrowDb}-wal`, `${scratchCrowDb}-shm`];
  if (refusal) {
    add(5, "no plaintext in the database bytes",
      dataDigest(scratchCrowDb) === dataDigestAfterCopy, "refused: unchanged");
  } else {
    const hits = rawScanHits(dbFiles, plaintexts);
    add(5, "no plaintext in the database bytes", hits.length === 0,
      hits.length === 0
        ? `${plaintexts.length} value(s) scanned`
        // A hit with no live cell holding the value is residue SQLite left in a
        // freed page (the seal's UPDATE grows the cell, so its old bytes stay in
        // page slack). Reported as the leak it is, and named as such.
        : `found in ${hits.join(",")}${foundInCells === 0 ? " (freed page space, no live cell)" : ""}`);
  }

  // ── 6: only api_key moved; every profile blob is byte-equal ──
  const providersAfter = providerShapes(scratchCrowDb);
  const profilesAfter = profileDigests(scratchCrowDb);
  const rowsSame = providersBefore === null ? providersAfter === null : sameMap(providersBefore, providersAfter);
  const profilesSame = sameMap(profilesBefore, profilesAfter);
  add(6, "provider rows and profile blobs otherwise unchanged",
    rowsSame && profilesSame,
    rowsSame ? (profilesSame ? `${profilesAfter.size} blob(s)` : "a profile blob changed") : "a provider column changed");

  // ── 7: version tables + every fts5 index, in both databases ──
  const versionReport = versionAndFtsReport("crow.db", scratchCrowDb, crowBefore);
  const tasksReport = sourceTasksDb ? versionAndFtsReport("tasks.db", scratchTasksDb, tasksBefore) : { ok: true, checked: 0, problems: [] };
  add(7, "version tables and FTS indexes intact",
    versionReport.ok && tasksReport.ok,
    versionReport.ok && tasksReport.ok
      ? `${versionReport.checked + tasksReport.checked} checked`
      : [...versionReport.problems, ...tasksReport.problems].slice(0, 3).join(", "));

  // ── 9: the pre-seal backup exists, is 0600 in a 0700 dir, and verifies ──
  const backupDir = join(scratch, ...BACKUP_SUBDIR);
  let backupFiles = [];
  try {
    backupFiles = readdirSync(backupDir).filter((n) => n.endsWith(".db"));
  } catch {
    backupFiles = [];
  }
  let strayTemps = 0;
  try { strayTemps = readdirSync(backupDir).filter((n) => n.endsWith(".tmp")).length; } catch { /* none */ }
  const digests = [...plaintextById.entries()].map(([id, plaintext]) => ({ id, digest: sha256Text(plaintext) }));
  const dirModeOk = modeOf(backupDir) === 0o700;
  const copiesOk = backupFiles.length > 0 && dirModeOk
    && backupFiles.every((name) => {
      const copy = join(backupDir, name);
      return mode0600(copy) && quickCheck(copy) && verifyCopyFile(copy, counts.providers, digests);
    });
  add(9, "pre-seal backup 0600 in 0700 and sound",
    refusal ? strayTemps === 0 && (backupFiles.length === 0 || copiesOk) : copiesOk && strayTemps === 0,
    `${backupFiles.length} copy(ies)`);

  // ── 10: a SECOND seal pass is a no-op (sealed 0, no backup, file unchanged) ──
  if (refusal) {
    add(10, "second pass is a no-op", true, "refused: no second pass");
  } else {
    const dbShaBefore = sha256File(scratchCrowDb);
    let second = null;
    try {
      // `allowVacuum: false`, like every pass but the gateway's pre-listen one:
      // this tool must never rebuild the file, so the "unchanged" check below is
      // about the seal alone.
      second = await inScratchEnv(scratch, scratchData, scratchCrowDb,
        () => sealPlaintextKeys(scratchCrowDb, { crowHome: scratch, allowVacuum: false }));
    } catch {
      second = null;
    }
    const dbShaAfter = sha256File(scratchCrowDb);
    const sealedAgain = Number(second?.counts?.sealed ?? -1);
    add(10, "second pass is a no-op",
      !!second && second.deferred === false && sealedAgain === 0
        && (second?.counts?.backup ?? null) === null && dbShaBefore === dbShaAfter,
      second
        ? `sealed ${sealedAgain}, backup ${second?.counts?.backup ? "taken" : "none"}, sha ${dbShaBefore === dbShaAfter ? "unchanged" : "moved"}`
        : "the second pass failed");
  }

  // ── 11: --omit-key refuses without writing anything, and says so once ──
  if (!args.omitKey) {
    add(11, "omit-key refusal", true, "not --omit-key");
  } else if (!refusal) {
    add(11, "omit-key refusal", true, "minted: nothing to orphan");
  } else if (refusalReason !== "key-missing") {
    // A different refusal (no providers table, a failed backup, a foreign home):
    // the key-missing alert is not what this case raises.
    add(11, "omit-key refusal", true, `refused (${refusalReason}): no seal alert`);
  } else {
    const alerts = pendingAlerts(scratch);
    const record = alerts.length === 1 ? alerts[0].record : null;
    // "The database is unchanged" is judged on its CONTENT (dataDigest), not on
    // the file's sha256: runMigrations records this refusal in its own
    // schema_migrations_deferred row, so the bytes always move on a refused run.
    // Everything the SEAL could have written is inside the digest.
    const unchanged = dataDigest(scratchCrowDb) === dataDigestAfterCopy;
    const alertsOk = alerts.length === 1 && !!record
      && record.body === KEY_SAVE_REFUSED && record.title === "Crow alert";
    add(11, "omit-key refusal",
      unchanged && !existsSync(scratchKey) && backupFiles.length === 0 && alertsOk,
      unchanged ? `${alerts.length} alert(s), no key, no backup` : "the database changed");
  }

  // ── 15: the scratch databases are sound ──
  add(15, "scratch database integrity",
    quickCheck(scratchCrowDb) && (!sourceTasksDb || quickCheck(scratchTasksDb)));

  // ── 16: tasks.db was copied and never touched ──
  if (!sourceTasksDb) {
    add(16, "tasks.db untouched", true, "absent");
  } else {
    add(16, "tasks.db untouched", existsSync(scratchTasksDb) && sha256File(scratchTasksDb) === tasksShaAfterCopy);
  }

  // ── 17: the key file the run was given ──
  if (!args.omitKey && !sourceKeyPresent) {
    // The source had no key at all: the pass may mint one (nothing to orphan),
    // and then it must be its own, 0600 — never a copy of anything.
    add(17, "key file as given",
      !existsSync(scratchKey) || mode0600(scratchKey),
      existsSync(scratchKey) ? "minted (the source had none)" : "nothing to seal");
  } else if (!args.omitKey) {
    add(17, "key file as given",
      keyCopied && existsSync(scratchKey) && mode0600(scratchKey) && sha256File(scratchKey) === sourceKeySha,
      "copied 0600");
  } else if (!existsSync(scratchKey)) {
    add(17, "key file as given", true, "omitted");
  } else {
    // Only a freshly minted key may appear, never a copy of the source's.
    add(17, "key file as given", mode0600(scratchKey) && sha256File(scratchKey) !== sourceKeySha, "minted during the pass");
  }

  // ── 18: the migration is recorded exactly when it did not refuse ──
  let recorded = false;
  {
    let book = null;
    try {
      book = new Database(scratchCrowDb, { readonly: true, fileMustExist: true });
      recorded = !!book.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").get()
        && !!book.prepare("SELECT 1 FROM schema_migrations WHERE id = ?").get(MIGRATION_ID);
    } catch {
      recorded = false;
    } finally {
      if (book) { try { book.close(); } catch { /* already closed */ } }
    }
  }
  add(18, "migration bookkeeping", refusal ? !recorded : recorded, refusal ? "not recorded (refused)" : "recorded");

  // ── 19: the source key file is untouched (or still absent) ──
  const sourceKeyAfter = fileEvidence(sourceKey);
  add(19, "source key file untouched",
    JSON.stringify(sourceKeyBefore) === JSON.stringify(sourceKeyAfter),
    sourceKeyBefore.present === true ? "sha256+mode unchanged" : "still absent");

  // ── 20: nothing was created or changed in the source's provider-keys backups ──
  const sourceBackupAfter = dirEvidence(sourceBackupDir);
  add(20, "no backup written under the source",
    JSON.stringify(sourceBackupBefore) === JSON.stringify(sourceBackupAfter),
    sourceBackupBefore === null
      ? (sourceBackupAfter === null ? "still absent" : "created by this run")
      : `${(sourceBackupAfter || []).length} file(s)`);

  // ── 21: no seal alert was spooled under the source home ──
  const sourceAlertsAfter = alertNames(sourceHome);
  const newSealAlerts = [];
  for (const [sub, names] of sourceAlertsAfter) {
    const before = new Set(sourceAlertsBefore.get(sub) || []);
    for (const name of names) {
      if (!before.has(name) && SEAL_ALERT_MARKERS.some((marker) => name.includes(marker))) {
        newSealAlerts.push(`${sub}/${name}`);
      }
    }
  }
  add(21, "no seal alert written under the source",
    newSealAlerts.length === 0,
    newSealAlerts.length === 0 ? "none" : `${newSealAlerts.length} new`);

  // ── 22: the source's providers rows and its 0040 row are unchanged ──
  const sourceEvidenceAfter = sourceEvidence(sourceCrowDb);
  const sourceRowsSame = !!sourceEvidenceAfter
    && JSON.stringify(sourceEvidenceBefore.rows) === JSON.stringify(sourceEvidenceAfter.rows);
  const noNew0040 = !!sourceEvidenceAfter && (!sourceEvidenceAfter.sealed || sourceEvidenceBefore.sealed);
  add(22, "source providers and bookkeeping unchanged",
    sourceRowsSame && noNew0040,
    !sourceEvidenceAfter ? "the source could not be read" : (sourceRowsSame ? "api_key digests unchanged" : "a providers row changed"));

  // ── 23: --strict-source only — the whole tree, for a STOPPED home ──
  if (args.strictSource) {
    add(23, "source home untouched (strict)",
      JSON.stringify(sourceTreeBefore) === JSON.stringify(snapshotTree(sourceHome)),
      "whole-tree snapshot");
  }

  // ── the report: counts and PASS/STOP only ──
  // Every line is buffered and scanned (raw, base64, hex) BEFORE it is written;
  // a line that would carry a plaintext is withheld, never printed.
  const forms = secretForms(plaintexts);
  const renderLines = () => {
    const lines = [
      `label: ${args.label ?? "-"}`,
      `providers: ${counts.providers}; plaintext at start: ${counts.plain}; sealed: ${counts.sealed}; keyless: ${counts.keyless}; unreadable: ${counts.unreadable}`,
      `sealed by this pass: ${counts.sealed}; backups: ${backupFiles.length}; key: ${args.omitKey ? "omitted" : "copied"}`,
      `outcome: ${refusal ? `refused (${refusalReason})` : "sealed"}`,
    ];
    for (const check of [...checks].sort((a, b) => a.num - b.num)) {
      lines.push(`check ${check.num} ${check.name}: ${check.pass ? "PASS" : "STOP"}${check.detail ? ` (${check.detail})` : ""}`);
    }
    return lines;
  };
  const sanitize = (lines) => lines.map((line) => (carriesSecret(line, forms)
    ? "[output line withheld: it carried a plaintext key]"
    : line));

  // ── 12: nothing secret in this tool's own output or in its alert files ──
  {
    const provisional = renderLines();
    const withheld = provisional.filter((line) => !line.startsWith(CHECK12_PREFIX) && carriesSecret(line, forms)).length;
    const alertLeak = carriesSecret(alertTexts(scratch), forms);
    add(12, "no plaintext in output or alert files", withheld === 0 && !alertLeak,
      withheld === 0 && !alertLeak ? `${forms.length} spelling(s) scanned` : "a value would have reached a terminal or the spool");
  }

  const lines = sanitize(renderLines());
  // A sanitized line means check 12 must say STOP, and the report is reprinted
  // once so the STOP line is the one an operator reads.
  const leakedInReport = lines.some((line) => !line.startsWith(CHECK12_PREFIX) && carriesSecret(line, forms));
  if (leakedInReport) {
    const check12 = checks.find((c) => c.num === 12);
    if (check12) check12.pass = false;
  }
  const finalLines = sanitize(renderLines());
  const ok = checks.every((check) => check.pass);
  for (const line of finalLines) process.stdout.write(`${line}\n`);
  process.stdout.write(`result: ${ok ? "PASS" : "STOP"}\n`);
  process.exit(ok ? 0 : 1);
}

await main().catch(() => {
  // No driver message, no stack: the report is PASS/STOP, and a failure is a STOP.
  process.stdout.write("result: STOP\n");
  process.exit(1);
});