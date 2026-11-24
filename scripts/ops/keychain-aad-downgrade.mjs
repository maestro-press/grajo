#!/usr/bin/env node
/**
 * Keychain AAD DOWNGRADE — the operator rollback for a code revert.
 *
 *   node scripts/ops/keychain-aad-downgrade.mjs --yes [--crow-home <dir>] [--db <path>]
 *
 * The keychain now seals every saved password with secret-box v2, BOUND to its row, and its
 * era REFUSES an old-style (`enc:v1:`) value. Code from before that change can still open a
 * v1 value but has no idea what a v2 one is (`openSecret` returns null for it), so going
 * back to an older release means putting the rows back the way it expects. That is this
 * tool, and it is the only thing that writes the era's state away.
 *
 * What it does, in order:
 *
 *   1. refuses without `--yes` (this lowers the protection of every saved password);
 *   2. refuses while this instance's gateway looks like it is running, unless
 *      `--force-while-running` — a live gateway would spawn children from rows being rewritten;
 *   3. takes the SAME verified copy the converter takes
 *      (`<CROW_HOME>/secrets/backups/keychain-aad/crow-pre-aad-<ts>.db`, 0600 in 0700:
 *      quick_check + row count + a digest per row it is about to rewrite);
 *   4. reseals every `enc:v2:` row under THIS instance's key back to v1
 *      (no AAD) in ONE `BEGIN IMMEDIATE` transaction, with a compare-and-swap on the blob it
 *      read and an in-transaction proof that every rewritten row opens to the same plaintext.
 *      A row that does NOT open under this key is skipped and reported (never an abort: one
 *      damaged row must not keep a code revert from finishing). Rows sealed under another key
 *      are left exactly as they are (they are already unreadable here) and counted;
 *   5. only after that: removes the era state file
 *      (`<CROW_HOME>/secrets/keychain-aad-state.json`) and the `keychain_aad_era` DB mirror, so
 *      the previous release accepts v1 values again.
 *
 * Any failure before step 5 changes nothing (the transaction rolls back); a failure after it
 * is impossible in practice (the state file is removed last, and removing it cannot fail).
 * Prints counts only: never a value, a blob, a key id or a driver message. Exit 1 on refusal.
 */
import { readFileSync, readdirSync, readlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { resolveCrowHome, resolveInstanceDataDir } from "../../servers/shared/crow-home.js";
import { openSecret, openSecretBound, sealSecret } from "../../servers/sharing/secret-box.js";
import { keychainAadVerifiedBackup } from "../../servers/gateway/boot/keychain-aad.js";
import { aadSecretsDirFromHome, removeAadMirrorSync, removeAadState } from "../../servers/gateway/keychain/aad-era.js";
import { keychainKeyState } from "../../servers/gateway/keychain/key.js";
import { rowAad } from "../../servers/gateway/keychain/store.js";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: node scripts/ops/keychain-aad-downgrade.mjs --yes [--crow-home <dir>] [--db <path>] [--force-while-running]\n");
  process.exit(2);
}

function parseArgs(argv) {
  const out = { yes: false, force: false, crowHome: null, db: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--yes") out.yes = true;
    else if (arg === "--force-while-running") out.force = true;
    else if (arg === "--crow-home") out.crowHome = argv[++i] ?? null;
    else if (arg === "--db") out.db = argv[++i] ?? null;
    else if (arg === "--help" || arg === "-h") usage();
    else usage(`unexpected argument: ${arg}`);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.yes) {
  process.stderr.write("refused: --yes is required to put saved passwords back in the old sealed form\n");
  process.exit(1);
}

const crowHome = resolve(args.crowHome || (() => { try { return resolveCrowHome(); } catch { return ""; } })() || usage("--crow-home is required when CROW_HOME is unset"));
// The same file the converter resolves (boot/keychain-aad.js defaultDbPath): an explicit --db,
// else CROW_DB_PATH, else `<instance data dir>/crow.db` through resolveInstanceDataDir. Never a
// guessed `<home>/crow.db` or `<home>/data/crow.db`.
const dbPath = args.db
  ? resolve(args.db)
  : (process.env.CROW_DB_PATH
    || join(resolveInstanceDataDir({ ...process.env, CROW_HOME: crowHome }), "crow.db"));

/**
 * Does this home's gateway look like it is running? Linux `/proc` only: a process whose
 * argv names `servers/gateway/index.js` and whose env (or cwd) resolves to this home. Any
 * other platform — and any doubt about reading `/proc` — answers "no" (the operator still has
 * `--force-while-running` and the service manager).
 */
function gatewayLooksRunning(home) {
  let pids;
  try { pids = readdirSync("/proc").filter((n) => /^\d+$/.test(n)); } catch { return false; }
  for (const pid of pids) {
    try {
      const argv = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0");
      if (!argv.some((a) => a.endsWith("servers/gateway/index.js"))) continue;
      let env = "";
      try { env = readFileSync(`/proc/${pid}/environ`, "utf8"); } catch { /* another user's */ }
      const m = env.match(/(?:^|\0)CROW_HOME=([^\0]*)/);
      if (m) {
        if (resolve(m[1]) === home) return true;
        continue;
      }
      try { if (resolve(readlinkSync(`/proc/${pid}/cwd`)) === home) return true; } catch { /* gone */ }
    } catch { /* the process vanished */ }
  }
  return false;
}

if (!args.force && gatewayLooksRunning(crowHome)) {
  process.stderr.write("refused: this instance's gateway looks like it is running; stop it (or pass --force-while-running)\n");
  process.exit(1);
}

const keyState = keychainKeyState({ crowHome });
if (!keyState.key) {
  process.stderr.write(`refused: no usable keychain key at ${keyState.path}\n`);
  process.exit(1);
}
const key = keyState.key;

let db;
try {
  db = new Database(dbPath, { fileMustExist: true });
  db.pragma("busy_timeout = 10000");
  db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
} catch {
  process.stderr.write("refused: the database could not be read\n");
  process.exit(1);
}

let resealed = 0;
let foreignKey = 0;
let skippedOpen = 0;
try {
  const hasTable = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'crow_keychain'").get();
  const rows = hasTable
    ? db.prepare("SELECT id, kind, bundle_id, env_key, connection_uuid, key_id, secret_sealed FROM crow_keychain WHERE substr(secret_sealed, 1, 7) = 'enc:v2:' ORDER BY id").all()
    : [];
  const mine = rows.filter((r) => r.key_id === key.id);
  foreignKey = rows.length - mine.length;

  if (mine.length > 0) {
    const total = hasTable ? Number(db.prepare("SELECT COUNT(*) AS c FROM crow_keychain").get()?.c ?? 0) : 0;
    const backup = await keychainAadVerifiedBackup(db, dbPath, crowHome, {
      now: new Date(),
      rowCount: total,
      rows: mine.map((r) => ({
        id: r.id,
        hash: createHash("sha256").update(String(r.secret_sealed), "utf8").digest("hex"),
      })),
    });
    if (!backup.ok) {
      process.stderr.write("refused: the pre-downgrade backup did not verify; nothing was changed\n");
      process.exit(1);
    }

    const pass = db.transaction(() => {
      const update = db.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE id = ? AND secret_sealed = ?");
      const readBack = db.prepare("SELECT secret_sealed FROM crow_keychain WHERE id = ?");
      const proofs = [];
      for (const row of mine) {
        let plaintext = null;
        try { plaintext = openSecretBound(row.secret_sealed, { seed: key.seed }, rowAad(row, key.id)); } catch { plaintext = null; }
        // A row that does not open is skipped and reported, never an abort: it stays v2 (which an
        // older release cannot read anyway) and the rest of the keychain still goes back to v1.
        if (typeof plaintext !== "string" || plaintext === "") { skippedOpen += 1; continue; }
        const sealed = sealSecret(plaintext, { seed: key.seed });
        if (update.run(sealed, row.id, row.secret_sealed).changes !== 1) { skippedOpen += 1; continue; }
        proofs.push({ id: row.id, plaintext });
      }
      // The proof, inside the transaction: every rewritten row is an enc:v1: blob again and
      // opens (no AAD) to the exact plaintext this pass read. Values are never logged.
      for (const proof of proofs) {
        const got = readBack.get(proof.id);
        if (typeof got?.secret_sealed !== "string" || !got.secret_sealed.startsWith("enc:v1:")) throw new Error("a row is not in the old form");
        if (openSecret(got.secret_sealed, { seed: key.seed }) !== proof.plaintext) throw new Error("a row did not verify");
        proof.plaintext = null;
      }
      return proofs.length;
    });
    resealed = pass.immediate();
  }

  // The era goes away LAST, so a crash before this leaves the v1 rows accepted anyway and a
  // rerun does the remaining work.
  removeAadState(aadSecretsDirFromHome(crowHome));
  removeAadMirrorSync(db);
} catch (err) {
  process.stderr.write(`refused: the downgrade did not verify (${err?.code || err?.name || "error"}); nothing was changed\n`);
  process.exit(1);
} finally {
  try { db.close(); } catch { /* already closed */ }
}

process.stdout.write(
  `outcome: downgraded\nresealed: ${resealed}; rows under another key left alone: ${foreignKey}; `
  + `rows that did not open (left as they are): ${skippedOpen}; era removed: yes\n`,
);
process.exit(0);