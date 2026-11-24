#!/usr/bin/env node
/**
 * Keychain AAD conversion DRY RUN (operator tool, read-only on the sources).
 *
 *   node scripts/ops/keychain-aad-dryrun.mjs \
 *     --db primary=<path to crow.db> [--db second=<path> …] \
 *     --key-from <crow home holding secrets/keychain.key> \
 *     --home <scratch directory this tool may write in>
 *
 * What it does, per label:
 *
 *   1. `.backup()` the labelled database into `<home>/<label>/data/crow.db` (the source file
 *      itself is only ever opened READ-ONLY);
 *   2. copies `<key-from>/secrets/keychain.key` into `<home>/<label>/secrets/keychain.key`
 *      (0700 dir, 0600 file) — never printed, never compared;
 *   3. runs the REAL conversion (`runKeychainAadBoot`) on that copy, then runs it a SECOND
 *      time: a second boot must change nothing;
 *   4. opens every row of the copy through the real keychain open path
 *      (`keychain/store.js` `openEntrySecret`, which is what a reveal uses) with the key the
 *      copy was given, and counts the successes.
 *
 * It prints counts and verdicts only — never a value, a blob, a key id or a driver message.
 * Exit 0 when every label is PASS, 1 when any label is STOP.
 *
 * The scratch `--home` is ALWAYS cleared before exit — on PASS, on STOP and on an exception alike
 * — because it holds copies of keychain keys and of the instance databases. One line says so.
 *
 * STOP means: the era was not recorded, a converted row did not open, an old-style (`enc:v1:`)
 * row is left under this key after the era (it would be refused in production), the second
 * boot changed anything, or a row failed to open for a reason other than "another key".
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, rmdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import Database from "better-sqlite3";
import { runKeychainAadBoot } from "../../servers/gateway/boot/keychain-aad.js";
import { keychainKeyPath, loadKeychainKey } from "../../servers/gateway/keychain/key.js";
import { openEntrySecret } from "../../servers/gateway/keychain/store.js";

const LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write(
    "usage: node scripts/ops/keychain-aad-dryrun.mjs --db <label>=<path> [--db …] "
    + "--key-from <crowHome> --home <scratchHome>\n",
  );
  process.exit(2);
}

function parseArgs(argv) {
  const out = { dbs: [], keyFrom: null, home: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--db") {
      const pair = String(argv[++i] ?? "");
      const at = pair.indexOf("=");
      if (at <= 0) usage("--db needs <label>=<path>");
      out.dbs.push({ label: pair.slice(0, at), path: pair.slice(at + 1) });
    } else if (arg === "--key-from") out.keyFrom = argv[++i] ?? null;
    else if (arg === "--home") out.home = argv[++i] ?? null;
    else if (arg === "--help" || arg === "-h") usage();
    else usage(`unexpected argument: ${arg}`);
  }
  if (out.dbs.length === 0) usage("at least one --db <label>=<path> is required");
  if (!out.keyFrom) usage("--key-from is required");
  if (!out.home) usage("--home is required");
  for (const db of out.dbs) {
    if (!LABEL.test(db.label)) usage(`bad label: ${db.label}`);
    if (!existsSync(db.path)) usage(`no such database: ${db.path}`);
  }
  return out;
}

/** better-sqlite3 behind the small async libsql surface the keychain store uses. */
function libsql(raw) {
  return {
    async execute(q) {
      const { sql, args = [] } = typeof q === "string" ? { sql: q } : q;
      const st = raw.prepare(sql);
      if (st.reader) return { rows: st.all(...args) };
      const r = st.run(...args);
      return { rows: [], lastInsertRowid: r.lastInsertRowid, rowsAffected: r.changes };
    },
    async executeMultiple(sql) { raw.exec(sql); },
  };
}

/** Copy the source database with SQLite's own `.backup()` — read-only on the source. */
async function copyDb(sourcePath, destPath) {
  mkdirSync(dirname(destPath), { recursive: true, mode: 0o700 });
  const source = new Database(sourcePath, { readonly: true, fileMustExist: true });
  try {
    await source.backup(destPath);
  } finally {
    source.close();
  }
  try { statSync(destPath); } catch { throw new Error("the copy is not on disk"); }
}

/** Copy the keychain key file into the scratch instance (0600 in a 0700 dir). */
function copyKey(keyFrom, instanceHome) {
  const from = keychainKeyPath(keyFrom);
  if (!existsSync(from)) throw new Error("no keychain key in --key-from");
  const dir = join(instanceHome, "secrets");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const to = join(dir, "keychain.key");
  copyFileSync(from, to);
  chmodSync(to, 0o600);
}

const counts = (raw) => {
  const rows = raw.prepare("SELECT kind, status FROM crow_keychain").all();
  const byKind = {};
  const byStatus = {};
  for (const r of rows) {
    byKind[r.kind] = (byKind[r.kind] || 0) + 1;
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  }
  return { byKind, byStatus, total: rows.length };
};

const fmt = (map) => (Object.keys(map).length === 0 ? "-" : Object.entries(map).sort().map(([k, v]) => `${k}:${v}`).join(","));

async function runLabel({ label, path: sourcePath }, { keyFrom, home }) {
  const instanceHome = join(home, label);
  const destPath = join(instanceHome, "data", "crow.db");
  const result = {
    label, stop: false, reasons: [], rows: 0, byKind: {}, byStatus: {}, v1: 0, foreignKey: 0,
    converted: 0, verified: 0, refused: 0, alarms: 0, secondBootChanges: 0, failedOpen: 0, unreadable: 0,
  };
  if (existsSync(instanceHome)) {
    // A run must start from an un-converted copy: an earlier run's state file would be found
    // and the second "boot" would legitimately be a no-op, which reads as a failure here.
    result.stop = true;
    result.reasons.push("this scratch home already holds this label from an earlier run; use a fresh --home");
    return result;
  }
  try {
    await copyDb(sourcePath, destPath);
    copyKey(keyFrom, instanceHome);
  } catch (err) {
    result.stop = true;
    result.reasons.push(`setup failed (${err?.code || err?.name || "error"})`);
    return result;
  }

  process.env.CROW_HOME = instanceHome;
  const log = () => {};
  const first = await runKeychainAadBoot({ dbPath: destPath, crowHome: instanceHome, mirror: false, log });
  result.converted = first.converted;
  result.v1 = first.v1;
  result.foreignKey = first.foreignKey;
  result.refused = first.refused;
  result.alarms = first.alarms;
  const second = await runKeychainAadBoot({ dbPath: destPath, crowHome: instanceHome, mirror: false, log });
  result.secondBootChanges = second.converted + (second.changed && second.state !== "converted-earlier" ? 1 : 0);
  if (second.state !== "converted-earlier") {
    result.stop = true;
    result.reasons.push(`the second boot did not see the era (${second.state})`);
  }
  if (!["converted", "marked", "marked-empty"].includes(first.state)) {
    result.stop = true;
    result.reasons.push(`the conversion did not complete (${first.state})`);
  }

  let raw = null;
  try {
    raw = new Database(destPath, { fileMustExist: true });
    const c = counts(raw);
    result.rows = c.total;
    result.byKind = c.byKind;
    result.byStatus = c.byStatus;
    const key = loadKeychainKey({ path: join(instanceHome, "secrets", "keychain.key") });
    if (!key) {
      result.stop = true;
      result.reasons.push("the key copy could not be loaded");
      return result;
    }
    const db = libsql(raw);
    const ids = raw.prepare("SELECT id, secret_sealed FROM crow_keychain ORDER BY id").all();
    for (const row of ids) {
      try {
        const value = await openEntrySecret(db, key, row.id);
        if (typeof value === "string") result.verified += 1;
        else result.unreadable += 1; // no value in the row under this key: not a conversion failure
      } catch (err) {
        const code = err?.code;
        if (code === "KEYCHAIN_KEY_MISSING") { result.unreadable += 1; continue; }
        if (code === "KEYCHAIN_LEGACY_FORM") { result.refused += 1; continue; }
        result.failedOpen += 1;
      }
    }
    const v1Left = Number(raw.prepare("SELECT COUNT(*) AS n FROM crow_keychain WHERE substr(secret_sealed, 1, 7) = 'enc:v1:'").get()?.n ?? 0);
    result.v1 = Math.max(result.v1, v1Left);
  } catch (err) {
    result.stop = true;
    result.reasons.push(`the copy could not be inspected (${err?.code || err?.name || "error"})`);
  } finally {
    try { raw?.close(); } catch { /* already closed */ }
  }

  if (result.failedOpen > 0) {
    result.stop = true;
    result.reasons.push(`${result.failedOpen} row(s) did not open after conversion`);
  }
  if (result.refused > 0) {
    result.stop = true;
    result.reasons.push(`${result.refused} old-style row(s) would be refused in production`);
  }
  if (result.secondBootChanges !== 0) {
    result.stop = true;
    result.reasons.push("the second boot changed something");
  }
  return result;
}

const args = parseArgs(process.argv.slice(2));
const scratchHome = resolve(args.home);

/**
 * Clear the scratch instances at exit, whatever the outcome: each holds a copy of the keychain key
 * (and of the database it opens), so they must never outlive the run. Only `<home>/<label>` — a
 * directory named by a VALIDATED label this run was asked for — is removed, so `--home` itself is
 * never a recursive target: it is only rmdir'd, and only when this run left it empty. One line,
 * always (on PASS, on STOP and when the run itself throws).
 */
function clearScratchHome() {
  for (const db of args.dbs) {
    try { rmSync(join(scratchHome, db.label), { recursive: true, force: true }); } catch { /* best effort */ }
  }
  try { rmdirSync(scratchHome); } catch { /* it holds something else: leave it */ }
  process.stdout.write(`scratch home cleared: ${scratchHome}\n`);
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => { clearScratchHome(); process.exit(signal === "SIGINT" ? 130 : 143); });
}

const results = [];
try {
  mkdirSync(scratchHome, { recursive: true, mode: 0o700 });
  for (const db of args.dbs) {
    // eslint-disable-next-line no-await-in-loop -- one labelled copy at a time, by design
    results.push(await runLabel(db, { keyFrom: resolve(args.keyFrom), home: scratchHome }));
  }

  for (const r of results) {
    process.stdout.write(
      `${r.label}: rows ${r.rows} (kind ${fmt(r.byKind)}; status ${fmt(r.byStatus)}); `
      + `v1 ${r.v1}; foreign-key ${r.foreignKey}; converted ${r.converted}; verified ${r.verified}; `
      + `refused ${r.refused}; alarms ${r.alarms}; second-boot changes ${r.secondBootChanges}; `
      + `unreadable ${r.unreadable}; failed-open ${r.failedOpen} — ${r.stop ? "STOP" : "PASS"}\n`,
    );
    for (const reason of r.reasons) process.stdout.write(`  ${r.label}: ${reason}\n`);
  }
  const stopped = results.filter((r) => r.stop);
  process.stdout.write(`${stopped.length === 0 ? "PASS" : "STOP"}: ${results.length - stopped.length}/${results.length} label(s) passed\n`);
  clearScratchHome();
  process.exit(stopped.length === 0 ? 0 : 1);
} catch (err) {
  process.stdout.write(`STOP: the run itself failed (${err?.code || err?.name || "error"})\n`);
  clearScratchHome();
  process.exit(1);
}