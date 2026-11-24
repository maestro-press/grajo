/**
 * The provider-key seal DRY RUN (design §4): the real migration registry, run
 * against a COPY of a fixture instance, reporting counts and PASS/STOP.
 *
 * The fixture is a realistic source home — a crow.db from the repo's own
 * scripts/init-db.js with every migration but 0040 already recorded, a tasks.db
 * with the history/version tables and report_versions, an fts5 index with a row,
 * profile blobs, a keychain key and three provider rows (one plaintext, one
 * "none", one already sealed) — plus the source-side evidence the tool pins:
 * the key file, the provider-keys backup dir (absent), the alert spool (empty)
 * and the providers rows.
 *
 * Runs exercised here:
 *   * the normal run (all 22 checks PASS);
 *   * `--omit-key`, on a copy whose sealed row makes the pass refuse;
 *   * a concurrent writer holding the source crow.db while the run is in flight;
 *   * a file appearing under the source's alert spool mid-run (a STOP);
 *   * `--strict-source`, on a quiet home (PASS) and a home with a stray file;
 *   * the check-5 positive control: a plaintext row whose freed cell is not
 *     reused leaves the value in page slack, which is a STOP.
 *
 * The SOURCE home is never required to be byte-identical: a live gateway keeps
 * writing crow.db, its -wal and its logs while a dry run is in progress, so the
 * tool pins the four things it (or the seal) could write there instead of the
 * whole tree. `--strict-source` is the whole-tree snapshot, for a stopped home.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

import { createKeychainKey, loadKeychainKey } from "../servers/gateway/keychain/key.js";
import { seal as sealProviderKey } from "../servers/gateway/keychain/provider-key-box.js";
import { legacyConsentFingerprint } from "../servers/gateway/keychain/provider-keys-sweep.js";
import { parseStoredKey } from "../servers/shared/provider-key-shape.js";
import { KEY_SAVE_REFUSED } from "../servers/gateway/addon-secrets-seal.js";

const REPO = join(import.meta.dirname, "..");
const SCRIPT = join(REPO, "scripts", "ops", "provider-keys-seal-dryrun.mjs");
const MIGRATIONS_DIR = join(REPO, "scripts", "migrations");
const MIGRATION_ID = "0040-seal-provider-keys";
const SALT = "b".repeat(64);

const roots = [];
after(() => { for (const root of roots) { try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } } });

const PLAIN = `sentinel-${"dryrun-plain"}`;
const SEALED_PLAIN = `sentinel-${"dryrun-sealed"}`;

const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const sha256Text = (value) => createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
const modeOf = (path) => statSync(path).mode & 0o777;

/**
 * A source instance: init-db'd crow.db, every other migration recorded, a
 * tasks.db, profile blobs, an fts5 row, a key and three provider rows.
 *
 * `plaintextRow` decides WHERE in the providers page the plaintext row sits.
 * Inserted LAST, its cell is the topmost one, so SQLite coalesces the space the
 * seal's UPDATE frees with the page's unallocated area and reuses it — the
 * plaintext is gone from the file's bytes (check 5 PASS). Inserted FIRST with
 * rows after it, the freed cell is an interior freeblock and the old bytes stay
 * in page slack — check 5's positive control, and what a real home can look
 * like (`scripts/ops/provider-keys-seal-dryrun.mjs` reports it as "freed page
 * space").
 */
function fixture({ plaintextRow = "last", extraProviders = 0 } = {}) {
  const root = mkdtempSync(join(tmpdir(), "crow-pk-dryrun-"));
  roots.push(root);
  const sourceHome = join(root, "source");
  const dataDir = join(sourceHome, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  execFileSync(process.execPath, ["scripts/init-db.js"],
    { env: { ...process.env, CROW_HOME: sourceHome, CROW_DATA_DIR: dataDir }, stdio: "pipe", cwd: REPO });

  const crowDb = join(dataDir, "crow.db");
  const tasksDb = join(dataDir, "tasks.db");
  createKeychainKey({ crowHome: sourceHome });
  const key = loadKeychainKey({ crowHome: sourceHome });

  const db = new Database(crowDb);
  try {
    db.pragma("journal_mode = DELETE");
    db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, sha TEXT)");
    const record = db.prepare("INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, datetime('now'))");
    for (const name of readdirSync(MIGRATIONS_DIR)) {
      if (!/^\d{4}-[a-z0-9-]+\.mjs$/.test(name)) continue;
      const id = name.replace(/\.mjs$/, "");
      if (id === MIGRATION_ID) continue; // the one migration this dry run is about
      record.run(id);
    }
    const insert = db.prepare(
      "INSERT INTO providers (id, base_url, api_key, host, provider_type, created_at, updated_at, lamport_ts) VALUES (?, ?, ?, 'local', 'openai', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', 3)",
    );
    const rows = {
      plain: () => insert.run("prov-plain", "https://api.example.com/v1", PLAIN),
      none: () => insert.run("prov-none", "http://localhost:11434/v1", "none"),
      sealed: () => insert.run("prov-sealed", "https://sealed.example.com/v1",
        sealProviderKey({ slotId: "prov-sealed", plaintext: SEALED_PLAIN, key })),
      extra: () => { for (let i = 0; i < extraProviders; i += 1) {
        insert.run(`prov-extra-${i}`, `https://extra${i}.example.com/v1`, `sentinel-${`dryrun-extra-${i}`}`);
      } },
    };
    if (plaintextRow === "first") {
      rows.plain(); rows.none(); rows.sealed(); rows.extra();
    } else {
      rows.none(); rows.sealed(); rows.extra(); rows.plain();
    }

    db.prepare("INSERT INTO memories (content, context) VALUES ('a dry-run fixture memory', 'fixture')").run();

    const setting = db.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)");
    setting.run("llm_cloud_consent_salt", SALT);
    setting.run("llm_cloud_door_rows", JSON.stringify({
      "prov-plain": { target: "https://api.example.com/v1", keyFp: legacyConsentFingerprint(SALT, PLAIN), at: "2026-01-03T00:00:00.000Z", by: "owner" },
    }));
    // The profile blobs check 6 pins (dashboard_settings is their real home).
    setting.run("ai_profiles", JSON.stringify([{ id: "p1", provider: "openai", baseUrl: "https://api.example.com/v1" }]));
    setting.run("stt_profiles", JSON.stringify([{ id: "fw", provider: "fasterwhisper", isDefault: true }]));
    db.exec("CREATE TABLE IF NOT EXISTS dashboard_settings_overrides (key TEXT NOT NULL, instance_id TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT, lamport_ts INTEGER DEFAULT 0, PRIMARY KEY (key, instance_id))");
    db.prepare("INSERT OR REPLACE INTO dashboard_settings_overrides (key, instance_id, value) VALUES ('tts_profiles', 'inst-1', ?)")
      .run(JSON.stringify([{ id: "edge", provider: "edge" }]));
  } finally {
    db.close();
  }

  // A tasks.db the migration must never touch, carrying the history tables and
  // report_versions check 7 counts.
  const tasks = new Database(tasksDb);
  try {
    tasks.pragma("journal_mode = DELETE");
    tasks.exec(`
      CREATE TABLE IF NOT EXISTS tasks_items (id INTEGER PRIMARY KEY, title TEXT);
      CREATE TABLE IF NOT EXISTS item_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, item_type TEXT, item_id TEXT, snapshot_json TEXT);
      CREATE TABLE IF NOT EXISTS item_versions_erase (id INTEGER PRIMARY KEY, armed INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS artifact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT, body TEXT);
      CREATE TABLE IF NOT EXISTS report_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT, body TEXT);
    `);
    tasks.prepare("INSERT INTO tasks_items (title) VALUES ('a card')").run();
    tasks.prepare("INSERT INTO item_versions (item_type, item_id, snapshot_json) VALUES ('task', '1', '{}')").run();
    tasks.prepare("INSERT INTO item_versions_erase (id, armed) VALUES (1, 0)").run();
    tasks.prepare("INSERT INTO artifact_versions (artifact_id, body) VALUES ('a1', 'v1')").run();
    tasks.prepare("INSERT INTO report_versions (report_id, body) VALUES ('r1', 'v1')").run();
  } finally {
    tasks.close();
  }

  return { root, sourceHome, dataDir, crowDb, tasksDb, key };
}

function runTool(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: REPO, encoding: "utf8", env: { ...process.env } });
}

/** The tool, in the background, so a test can touch the source while it runs. */
function runToolAsync(args) {
  const child = spawn(process.execPath, [SCRIPT, ...args], { cwd: REPO, env: { ...process.env } });
  const chunks = [];
  child.stdout.on("data", (b) => chunks.push(b));
  child.stderr.on("data", (b) => chunks.push(b));
  const done = new Promise((resolve) => {
    child.on("close", (status) => resolve({ status, stdout: Buffer.concat(chunks).toString("utf8") }));
  });
  return { child, done };
}

async function waitFor(predicate, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  return false;
}

const CHECK_RE = /^check (\d+) (.+?): (PASS|STOP)(?: \((.*)\))?$/;

/** The report's checks, by spec number. */
function checkMap(stdout) {
  const map = new Map();
  for (const line of stdout.split("\n")) {
    const m = CHECK_RE.exec(line);
    if (m) map.set(Number(m[1]), { num: Number(m[1]), name: m[2], verdict: m[3], detail: m[4] ?? null, line });
  }
  return map;
}

const stopLines = (map) => [...map.values()].filter((c) => c.verdict !== "PASS").map((c) => c.line);

/** The scratch instance a run created, for the test's own assertions. */
const scratchDb = (scratch) => join(scratch, "data", "crow.db");

/** The source-side evidence the tool pins: nothing here may change. */
function sourceEvidence(fx) {
  const keyFile = join(fx.sourceHome, "secrets", "keychain.key");
  const backupDir = join(fx.sourceHome, "secrets", "backups", "provider-keys");
  const alerts = join(fx.sourceHome, "alerts", "pending");
  const db = new Database(fx.crowDb, { readonly: true, fileMustExist: true });
  try {
    return {
      key: existsSync(keyFile) ? `${sha256File(keyFile)}:${modeOf(keyFile)}` : "absent",
      backups: existsSync(backupDir) ? readdirSync(backupDir).sort() : "absent",
      alerts: existsSync(alerts) ? readdirSync(alerts).sort() : "absent",
      providers: sha256Text(JSON.stringify(db.prepare("SELECT id, api_key FROM providers ORDER BY id").all())),
      sealedRow: Number(db.prepare("SELECT COUNT(*) AS c FROM schema_migrations WHERE id = ?").get(MIGRATION_ID).c),
    };
  } finally {
    db.close();
  }
}

test("a dry run seals the copy, passes all 22 checks, and never writes the source's evidence", () => {
  const fx = fixture();
  const scratch = join(fx.root, "scratch");
  const before = sourceEvidence(fx);

  const out = runTool(["--source-home", fx.sourceHome, "--scratch", scratch, "--label", "fixture"]);
  assert.equal(out.status, 0, out.stderr || out.stdout);

  // Counts + PASS/STOP only: every check ran and passed (22 without --strict-source).
  const map = checkMap(out.stdout);
  assert.equal(map.size, 22, out.stdout);
  assert.deepEqual(stopLines(map), []);
  assert.match(out.stdout, /^label: fixture$/m);
  assert.match(out.stdout, /^outcome: sealed$/m);
  assert.match(out.stdout, /^sealed by this pass: 1;/m);
  assert.match(out.stdout, /^result: PASS$/m);

  // Design §4's numbering, and the checks the spec asks for by number.
  assert.equal(map.get(1).name, "applied set is exactly the seal migration");
  assert.equal(map.get(2).name, "schema and row counts unchanged");
  assert.equal(map.get(3).name, "round trip");
  assert.equal(map.get(4).name, "provider keys as expected");
  assert.equal(map.get(5).name, "no plaintext in the database bytes");
  assert.equal(map.get(6).name, "provider rows and profile blobs otherwise unchanged");
  assert.equal(map.get(7).name, "version tables and FTS indexes intact");
  assert.equal(map.get(8).name, "consent fingerprints");
  assert.equal(map.get(9).name, "pre-seal backup 0600 in 0700 and sound");
  assert.equal(map.get(10).name, "second pass is a no-op");
  assert.equal(map.get(11).name, "omit-key refusal");
  assert.equal(map.get(12).name, "no plaintext in output or alert files");
  // The extra evidence checks the spec does not number.
  assert.equal(map.get(13).name, "no plaintext in any table cell");
  assert.equal(map.get(18).name, "migration bookkeeping");
  assert.equal(map.get(19).name, "source key file untouched");
  assert.equal(map.get(20).name, "no backup written under the source");
  assert.equal(map.get(21).name, "no seal alert written under the source");
  assert.equal(map.get(22).name, "source providers and bookkeeping unchanged");
  // No 23: the whole-tree snapshot is off by default.
  assert.equal(map.has(23), false);

  // check 6 and 7 actually had something to pin.
  assert.match(map.get(6).detail, /^3 blob\(s\)$/);
  assert.match(map.get(7).detail, /checked$/);

  // The scratch copy is sealed, and the already-sealed row was left alone.
  const db = new Database(scratchDb(scratch), { readonly: true, fileMustExist: true });
  try {
    const rows = new Map(db.prepare("SELECT id, api_key FROM providers").all().map((r) => [r.id, r.api_key]));
    assert.equal(parseStoredKey(rows.get("prov-plain")).kind, "envelope");
    assert.equal(parseStoredKey(rows.get("prov-sealed")).kind, "envelope");
    assert.equal(rows.get("prov-none"), "none");
    // And the consent fingerprint moved to the sealed form.
    const consent = JSON.parse(db.prepare("SELECT value FROM dashboard_settings WHERE key = 'llm_cloud_door_rows'").get().value);
    assert.notEqual(consent["prov-plain"].keyFp, legacyConsentFingerprint(SALT, PLAIN));
    assert.match(consent["prov-plain"].keyFp, /^[0-9a-f]{16}$/);
    // The profile blobs are byte-identical.
    assert.match(db.prepare("SELECT value FROM dashboard_settings WHERE key = 'ai_profiles'").get().value, /"p1"/);
    assert.match(db.prepare("SELECT value FROM dashboard_settings WHERE key = 'stt_profiles'").get().value, /"fw"/);
    assert.match(db.prepare("SELECT value FROM dashboard_settings_overrides WHERE key = 'tts_profiles'").get().value, /"edge"/);
  } finally {
    db.close();
  }

  // A verified pre-seal backup landed in the scratch home: 0600 in a 0700 dir.
  const backupDir = join(scratch, "secrets", "backups", "provider-keys");
  const backups = readdirSync(backupDir).filter((n) => n.endsWith(".db"));
  assert.equal(backups.length, 1);
  assert.equal(modeOf(join(backupDir, backups[0])), 0o600);
  assert.equal(modeOf(backupDir), 0o700);

  // Hygiene: no key value, no envelope and no key id on stdout/stderr — raw,
  // base64 or hex.
  const forms = [PLAIN, SEALED_PLAIN, Buffer.from(PLAIN).toString("base64"), Buffer.from(PLAIN).toString("hex")];
  for (const stream of [out.stdout, out.stderr]) {
    for (const form of forms) assert.equal(stream.includes(form), false);
    assert.equal(stream.includes("pk1:"), false);
    assert.equal(stream.includes(fx.key.id), false);
  }

  // THE invariant (design §4 A): the source's own evidence is untouched. The
  // whole tree is NOT compared — a live gateway writes crow.db continuously.
  assert.deepEqual(sourceEvidence(fx), before);
});

test("--omit-key reports the refusal as PASS, copies no key, backs up nothing, and alerts once", () => {
  const fx = fixture();
  const scratch = join(fx.root, "scratch-omit");
  const before = sourceEvidence(fx);

  const out = runTool(["--source-home", fx.sourceHome, "--scratch", scratch, "--omit-key"]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.match(out.stdout, /^outcome: refused \(key-missing\)$/m);
  assert.match(out.stdout, /^result: PASS$/m);

  const map = checkMap(out.stdout);
  assert.equal(map.size, 22, out.stdout);
  assert.deepEqual(stopLines(map), []);
  // A refused pass is NOT recorded as applied, left the keys as they were, and
  // wrote nothing at all.
  assert.match(map.get(4).detail, /^refused: unchanged$/);
  assert.match(map.get(5).detail, /^refused: unchanged$/);
  assert.match(map.get(10).detail, /^refused: no second pass$/);
  assert.match(map.get(11).detail, /^1 alert\(s\), no key, no backup$/);
  assert.match(map.get(13).detail, /^refused: 1 left in the clear by design$/);
  assert.match(map.get(18).detail, /^not recorded \(refused\)$/);

  assert.equal(existsSync(join(scratch, "secrets", "keychain.key")), false, "no key was copied or minted");
  assert.equal(existsSync(join(scratch, "secrets", "backups", "provider-keys")), false, "no backup was taken");

  // Exactly one spooled alert, with the shared refusal sentence and the default title.
  const pendingDir = join(scratch, "alerts", "pending");
  const alerts = readdirSync(pendingDir).filter((n) => n.endsWith(".json"));
  assert.equal(alerts.length, 1, alerts.join(","));
  const record = JSON.parse(readFileSync(join(pendingDir, alerts[0]), "utf8"));
  assert.equal(record.code, "keychain-key-missing");
  assert.equal(record.body, KEY_SAVE_REFUSED);
  assert.equal(record.title, "Crow alert");

  const db = new Database(scratchDb(scratch), { readonly: true, fileMustExist: true });
  try {
    assert.equal(db.prepare("SELECT api_key FROM providers WHERE id = 'prov-plain'").get().api_key, PLAIN);
    assert.equal(db.prepare("SELECT COUNT(*) AS c FROM schema_migrations WHERE id = ?").get(MIGRATION_ID).c, 0);
  } finally {
    db.close();
  }

  assert.deepEqual(sourceEvidence(fx), before);
});

test("a concurrent writer holding the source crow.db during the run is not a STOP", async () => {
  const fx = fixture();
  const scratch = join(fx.root, "scratch-writer");
  const before = sha256File(fx.crowDb);

  const run = runToolAsync(["--source-home", fx.sourceHome, "--scratch", scratch]);
  // The key copy happens once BOTH databases are copied and their baseline is
  // taken — the source's evidence snapshot is already behind us.
  assert.ok(await waitFor(() => existsSync(join(scratch, "secrets", "keychain.key"))),
    "the tool never got as far as copying the key");
  let wroteDuringRun = false;
  {
    const writer = new Database(fx.crowDb);
    try {
      writer.pragma("busy_timeout = 15000");
      writer.exec("BEGIN EXCLUSIVE");
      writer.prepare("INSERT INTO notifications (type, source, title, priority) VALUES ('system', 'dryrun-writer', 'a concurrent write', 'low')").run();
      writer.prepare("INSERT INTO memories (content) VALUES ('written by a concurrent gateway')").run();
      await new Promise((resolve) => setTimeout(resolve, 80));
      writer.exec("COMMIT");
      wroteDuringRun = run.child.exitCode === null;
    } finally {
      writer.close();
    }
  }
  const out = await run.done;

  assert.ok(wroteDuringRun, "the concurrent write has to land while the tool is running");
  assert.notEqual(before, sha256File(fx.crowDb), "the writer really wrote the source crow.db");
  assert.equal(out.status, 0, out.stdout);
  const map = checkMap(out.stdout);
  assert.deepEqual(stopLines(map), []);
  // The four source checks all held through it.
  for (const num of [19, 20, 21, 22]) assert.equal(map.get(num).verdict, "PASS", map.get(num)?.line);
  assert.match(map.get(22).detail, /^api_key digests unchanged$/);
});

test("a file written under the source mid-run is a STOP (check 21)", async () => {
  const fx = fixture();
  const scratch = join(fx.root, "scratch-intruder");
  const before = sourceEvidence(fx);

  const run = runToolAsync(["--source-home", fx.sourceHome, "--scratch", scratch]);
  assert.ok(await waitFor(() => existsSync(join(scratch, "secrets", "keychain.key"))),
    "the tool never got as far as copying the key");
  const pendingDir = join(fx.sourceHome, "alerts", "pending");
  mkdirSync(pendingDir, { recursive: true, mode: 0o700 });
  writeFileSync(join(pendingDir, "2026-01-01T00-00-00-000Z-keychain-key-missing.json"),
    JSON.stringify({ code: "keychain-key-missing", title: "Crow alert", body: "x", at: "2026-01-01T00:00:00.000Z" }),
    { mode: 0o600 });
  const out = await run.done;

  assert.equal(out.status, 1, out.stdout);
  assert.match(out.stdout, /^result: STOP$/m);
  const map = checkMap(out.stdout);
  assert.equal(map.get(21).verdict, "STOP");
  assert.match(map.get(21).detail, /^1 new$/);
  // Everything else this tool could have written under the source is still clean.
  for (const num of [19, 20, 22]) assert.equal(map.get(num).verdict, "PASS", map.get(num)?.line);
  // The source's key, backups and providers rows are exactly as they were.
  const now = sourceEvidence(fx);
  assert.equal(now.key, before.key);
  assert.equal(now.providers, before.providers);
  assert.equal(now.sealedRow, before.sealedRow);
});

test("--strict-source sees the whole tree: PASS on a quiet home, STOP on a stray write mid-run", async () => {
  const fx = fixture();
  const quiet = runTool(["--source-home", fx.sourceHome, "--scratch", join(fx.root, "scratch-strict-a"), "--strict-source"]);
  assert.equal(quiet.status, 0, quiet.stdout);
  const quietMap = checkMap(quiet.stdout);
  assert.equal(quietMap.size, 23, quiet.stdout);
  assert.equal(quietMap.get(23).name, "source home untouched (strict)");
  assert.equal(quietMap.get(23).verdict, "PASS");

  // A stray file that is not one of the four seal-relevant artefacts, written
  // WHILE the run is in flight: invisible to checks 19–22 (they only look at the
  // key, the backup dir, the alert spool and the providers rows), caught by the
  // whole-tree snapshot.
  const scratch = join(fx.root, "scratch-strict-b");
  const run = runToolAsync(["--source-home", fx.sourceHome, "--scratch", scratch, "--strict-source"]);
  assert.ok(await waitFor(() => existsSync(join(scratch, "secrets", "keychain.key"))),
    "the tool never got as far as copying the key");
  writeFileSync(join(fx.sourceHome, "stray.txt"), "not a seal artefact\n");
  const stray = await run.done;

  assert.equal(stray.status, 1, stray.stdout);
  const strayMap = checkMap(stray.stdout);
  assert.equal(strayMap.get(23).verdict, "STOP");
  assert.deepEqual([...strayMap.values()].filter((c) => c.num !== 23 && c.verdict !== "PASS").map((c) => c.line), []);
});

test("check 5: the seal pass zeroes the freed cell (secure_delete), so no plaintext survives in page slack", () => {
  // The plaintext row FIRST, other rows after it: the seal's UPDATE frees an
  // interior cell. Without secure_delete SQLite would leave the old bytes in
  // page slack; the pass sets it, so the byte scan finds nothing.
  const fx = fixture({ plaintextRow: "first", extraProviders: 4 });
  const scratch = join(fx.root, "scratch-slack");
  const out = runTool(["--source-home", fx.sourceHome, "--scratch", scratch]);
  assert.equal(out.status, 0, out.stdout);
  const map = checkMap(out.stdout);
  assert.equal(map.get(5).verdict, "PASS", map.get(5).line);
  assert.equal(map.get(13).verdict, "PASS");
});

test("the source key file is untouched, and a missing --source-home is a usage error", () => {
  const fx = fixture();
  const keyBefore = `${sha256File(join(fx.sourceHome, "secrets", "keychain.key"))}:${modeOf(join(fx.sourceHome, "secrets", "keychain.key"))}`;
  const out = runTool(["--source-home", fx.sourceHome, "--scratch", join(fx.root, "scratch-key")]);
  assert.equal(out.status, 0, out.stderr || out.stdout);
  assert.equal(`${sha256File(join(fx.sourceHome, "secrets", "keychain.key"))}:${modeOf(join(fx.sourceHome, "secrets", "keychain.key"))}`, keyBefore);
  assert.equal(checkMap(out.stdout).get(19).detail, "sha256+mode unchanged");

  const usage = runTool(["--scratch", join(fx.root, "scratch-usage")]);
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /--source-home is required/);
});