/**
 * Pre-listen boot for the oauth_tokens families (§8 PR 2 of the keyed-token-hashes design,
 * §3.2/§3.3): create or load the HMAC key, convert every legacy row of the three families
 * to its `h1.` form, and alarm on old-style rows that appear afterwards.
 *
 * ORDER. `servers/gateway/index.js` calls this after the schema exists and BEFORE listen,
 * so no route — and no OAuth fallback, session reader or refresh exchange — can validate a
 * row the converter has not seen.
 *
 * CONVERSION (§3.2), per family:
 *   1. Snapshot `{rowid, token}` of the rows to convert into
 *      `secrets/token-hmac-rollback-<ts>.json` (0600, atomic, hashes only — the file is
 *      the rollback tool's input).
 *   2. In ONE transaction, rewrite each snapshot row with compare-and-swap
 *      (`UPDATE oauth_tokens SET token = <h1> WHERE token = <legacy> AND <family>`).
 *   3. Commit, then `markConverted` (secrets-side marker + the DB mirror).
 *
 * CRASH RE-RUN (§3.2): if the process dies between 2 and 3, the family has no
 * `converted_at` but its snapshot file is still there — including an EMPTY one, taken when the
 * family held no legacy row (see `pendingSnapshot`). That boot converts ONLY the rows
 * listed in the snapshot that still hold their snapshot value; any other legacy row is a
 * post-snapshot write, so it is NOT converted and raises the alarm. That is what keeps a
 * bot from laundering a write through a crash-and-restart.
 *
 * NOT WRITABLE SECRETS (§2.6 last row): the snapshot write is the gate. If it fails, that
 * family is skipped, logged, and NO era is recorded — legacy stays accepted (and unprotected)
 * rather than every client being signed out.
 *
 * ANY OTHER FAILURE REFUSES LEGACY (§M2). A conversion (or its post-conversion scan) that
 * throws for any OTHER reason must never fail open, and must never take its siblings with it:
 * each family is tried in its own try/catch, a failed family is retried (FAMILY_RETRY_DELAYS_MS)
 * before listen, and if it still fails this PROCESS refuses that family's legacy values
 * (`forceRefuseLegacy`) with one console line — no era is written, so the next boot resumes
 * from that family's snapshot and converts. The deliberate §2.6 skip above is NOT a failure:
 * an unwritable `secrets/` still leaves legacy accepted (and unprotected), unchanged.
 *
 * THE KEY IS NEVER REPLACED HERE. A lost or invalid key logs one loud line naming the file
 * and the recovery command, and the boot CARRIES ON: the gateway still starts (loopback
 * health, `/blog`, the Fix-it surface), while every validator refuses through `token-mac`'s
 * own key-lost refusal. No new user-visible text: this file only writes console lines and
 * audit rows.
 */
import {
  closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { TokenMacKeyError, ensureKey, legacyAlarm, macFromLegacy, markConverted, noteEraEvidence, tokenMacKeyPath } from "../../shared/token-mac.js";
import { ensureSecretsDir } from "../../shared/peer-credentials.js";
import { writeSetting } from "../dashboard/settings/registry.js";
import { auditLog } from "../../db.js";
import { FAMILY_PREDICATE, TOKEN_STORE_FAMILIES, forceRefuseLegacy, isLegacyStored, tokenFamilyConverted } from "../token-store.js";
import { adoptMirrorOnlyEra, hostEraRecorded } from "./token-hmac-era-adopt.js";

/** Snapshot file name prefix inside `secrets/` (§3.2 step 1). */
export const ROLLBACK_PREFIX = "token-hmac-rollback-";
const SNAPSHOT_VERSION = 1;
/** `token_hmac_era:` — the mirror prefix §2.5 writes; a reset marks these, it never clears them. */
export const ERA_MIRROR_PREFIX = "token_hmac_era:";
/**
 * Backoff before each of the three retries of a failed family conversion (§M2). The family is
 * retried in place, before listen, so a transient database failure cannot leave a family
 * accepting legacy values for the rest of the process's life.
 */
export const FAMILY_RETRY_DELAYS_MS = Object.freeze([250, 1000, 2000]);

function secretsDir() {
  return dirname(tokenMacKeyPath());
}

/** `2026-11-23T16:41:02.123Z` → a file-name-safe stamp. */
function stamp(at = new Date()) {
  return at.toISOString().replace(/[:.]/g, "-");
}

/**
 * Write the snapshot atomically and owner-only: temp file 0600, fsync, rename, fsync the
 * directory (the same crash-atomic pattern the key and the state file use). Throws on an
 * unwritable `secrets/` — the caller treats that as "skip this family".
 */
function writeSnapshot(name, body) {
  const dir = secretsDir();
  ensureSecretsDir(dir);
  const final = join(dir, name);
  const tmp = `${final}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, final);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  try {
    const dfd = openSync(dir, "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  return final;
}

/**
 * The newest snapshot file for a family that has NO `converted_at` — a conversion a crash
 * interrupted. `null` when there is none. A file whose JSON is unreadable is ignored (it is
 * not one of ours); the family then converts fresh, and any row it fails to cover alarms.
 *
 * AN EMPTY SNAPSHOT IS STILL A PENDING ONE. `rows: []` means the snapshot was taken when the
 * family held no legacy row — the conversion committed (nothing) and the process died before
 * `markConverted`. Skipping such a file would let this boot convert FRESH, laundering a legacy
 * row something wrote after the crash into a credential its writer knows the token of. Any
 * snapshot naming this family and this key therefore counts as pending: the rerun converts only
 * its (zero) rows, alarms every other old-style row, and marks the family.
 */
function pendingSnapshot(family, keyId) {
  const dir = secretsDir();
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  let best = null;
  for (const name of names) {
    if (!name.startsWith(ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== SNAPSHOT_VERSION || body.family !== family || !Array.isArray(body.rows)) continue;
    // A snapshot from an EARLIER key (an operator reset, a key rotation) can never be
    // resumed: its values belong to a key this box no longer has, so converting from it
    // would mint verifiers nobody can produce.
    if (keyId && body.key_id !== keyId) continue;
    const rows = body.rows
      .map((r) => ({ rowid: r?.rowid ?? null, token: typeof r?.token === "string" ? r.token : "" }))
      .filter((r) => isLegacyStored(r.token));
    if (!best || mtimeMs > best.mtimeMs) best = { name, rows, mtimeMs };
  }
  return best;
}

/** Any legacy (bare sha256) row left in a family, as `{rowid, token}`. */
async function legacyRows(db, family) {
  const predicate = FAMILY_PREDICATE[family];
  const { rows } = await db.execute({
    sql: `SELECT rowid AS rowid, token FROM oauth_tokens WHERE (${predicate}) AND token NOT LIKE 'h1.%'`,
    args: [],
  });
  return rows.map((r) => ({ rowid: r.rowid ?? null, token: String(r.token ?? "") }));
}

/**
 * Convert one family (fresh, or resumed from a pending snapshot).
 *
 * `runTransaction` and `writeSnapshot` are TEST seams (a test injects a throwing transaction to pin
 * the §M2 failure path, or a throwing snapshot writer to pin the deliberate §2.6 skip); production
 * passes neither and gets `db.runTransaction` and the real atomic snapshot writer.
 *
 * @returns {Promise<{family: string, state: string, count?: number, rollbackFile?: string,
 *          alarms?: number, reason?: string}>}
 */
async function convertFamily(db, family, { key, audit, now, runTransaction, writeSnapshot: writeSnapshotFor }) {
  const inTransaction = typeof runTransaction === "function"
    ? runTransaction
    : (runner) => db.runTransaction(runner);
  const snapshot = typeof writeSnapshotFor === "function" ? writeSnapshotFor : writeSnapshot;
  const predicate = FAMILY_PREDICATE[family];
  const pending = pendingSnapshot(family, key.id);
  let snapshotRows;
  let rollbackName;
  if (pending) {
    snapshotRows = pending.rows;
    rollbackName = pending.name;
    console.warn(
      `[token-hmac] resuming an interrupted conversion of ${family} from secrets/${pending.name}: `
      + "only the rows in that snapshot are converted; any other old-style row stays and is reported.",
    );
  } else {
    const rows = await legacyRows(db, family);
    snapshotRows = rows.filter((r) => isLegacyStored(r.token));
    rollbackName = `${ROLLBACK_PREFIX}${stamp(now)}-${family.replace(/[^a-z0-9]+/gi, "-")}.json`;
    try {
      snapshot(rollbackName, {
        v: SNAPSHOT_VERSION,
        family,
        key_id: key.id,
        created_at: (now || new Date()).toISOString(),
        rows: snapshotRows,
      });
    } catch (err) {
      return { family, state: "skipped", reason: `secrets/ is not writable (${err.code || err.message})` };
    }
  }

  const inSnapshot = new Set(snapshotRows.map((r) => r.token));
  let count = 0;
  const copies = [];
  const convertedHere = new Set();
  await inTransaction((run) => {
    for (const entry of snapshotRows) {
      const h1 = macFromLegacy(family, entry.token);
      // M1: `token` is the PRIMARY KEY, so an `h1.` value that already sits on another row (a copy a
      // bot made, or the twin of an uppercase/lowercase legacy pair converted a moment ago) would
      // abort this whole transaction on every boot. Only a row that still holds its snapshot value
      // is converted, and only then can it collide; the other row is a copy, so it is revoked
      // (oauth: deleted, which is how a grant is revoked) and reported.
      const still = run({
        sql: `SELECT rowid AS rowid FROM oauth_tokens WHERE token = ? AND (${predicate})`,
        args: [entry.token],
      });
      if (!still?.rows?.length) continue;
      const holder = run({ sql: "SELECT rowid AS rowid FROM oauth_tokens WHERE token = ?", args: [h1] })?.rows?.[0];
      if (holder) {
        // A holder that is not a row converted a moment ago is a copy: it goes. For a TWIN (an
        // uppercase/lowercase pair) the LOWERCASE row is the genuine one — writers only ever store
        // lowercase — so an uppercase entry that finds its twin already converted is the copy itself.
        const holderIsTwin = convertedHere.has(h1);
        if (holderIsTwin && entry.token !== entry.token.toLowerCase()) {
          run({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [entry.token] });
          copies.push(String(still.rows[0].rowid));
          continue;
        }
        run({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [h1] });
        copies.push(String(holder.rowid));
        if (convertedHere.delete(h1)) count -= 1; // a deleted row is not a converted one
      }
      const res = run({
        sql: `UPDATE oauth_tokens SET token = ? WHERE token = ? AND (${predicate})`,
        args: [h1, entry.token],
      });
      if ((Number(res?.rowsAffected) || 0) > 0) {
        count += 1;
        convertedHere.add(h1);
      }
    }
  });

  // A row not in the snapshot is a post-snapshot write: NOT converted (§3.2).
  let alarms = 0;
  for (const rowRef of copies) {
    legacyAlarm(family, rowRef, { audit });
    alarms += 1;
  }
  for (const row of await legacyRows(db, family)) {
    if (inSnapshot.has(row.token)) continue;
    legacyAlarm(family, row.rowid, { audit });
    alarms += 1;
  }

  const mark = await markConverted(family, {
    count,
    rollbackFile: rollbackName,
    writeSetting: (k, v, o) => writeSetting(db, k, v, o),
    at: (now || new Date()).toISOString(),
  });
  return { family, state: "converted", count, rollbackFile: rollbackName, alarms, changed: mark.changed };
}

/** The post-conversion boot scan of §3.3: any old-style row alarms, nobody converts it. */
async function scanConvertedFamily(db, family, { audit }) {
  let alarms = 0;
  for (const row of await legacyRows(db, family)) {
    legacyAlarm(family, row.rowid, { audit });
    alarms += 1;
  }
  return { family, state: "converted", scan: true, alarms };
}

/**
 * Run the boot: evidence → key → per-family convert or scan.
 *
 * Each family is INDEPENDENT: its own try/catch, its own retries, and — if it still fails — a
 * process-local refusal of its legacy values (§M2). One broken family never skips its siblings
 * and never fails open.
 *
 * @param {{ db: object, now?: Date, audit?: Function, retryDelaysMs?: number[],
 *           sleep?: (ms: number) => Promise<void>,
 *           runTransaction?: (family: string, runner: Function) => any,
 *           writeSnapshot?: (name: string, body: object) => string }} opts
 *        `db` is the gateway's crow.db client; `audit` defaults to `auditLog` on that client.
 *        `retryDelaysMs`, `sleep`, `runTransaction` and `writeSnapshot` are TEST seams for the
 *        §M2 failure path and the §2.6 skip; production passes none of them
 *        (FAMILY_RETRY_DELAYS_MS, a real timer, db.runTransaction, the atomic snapshot writer).
 * @returns {Promise<{key: "ok"|"lost"|"invalid", keyPath: string, families: object[], alarms: number}>}
 *          Never throws for a key problem: the gateway must still start.
 */
export async function runTokenHmacBoot({
  db, now = new Date(), audit, retryDelaysMs, sleep, runTransaction, writeSnapshot, adoptEra = adoptMirrorOnlyEra,
} = {}) {
  if (!db) throw new TypeError("runTokenHmacBoot needs a crow.db client");
  const auditFn = typeof audit === "function" ? audit : (eventType, details) => auditLog(db, eventType, { details });
  const keyPath = tokenMacKeyPath();
  const retryDelays = Array.isArray(retryDelaysMs) ? retryDelaysMs : FAMILY_RETRY_DELAYS_MS;
  const wait = typeof sleep === "function" ? sleep : (ms) => new Promise((done) => { setTimeout(done, ms); });
  const transactionFor = typeof runTransaction === "function" ? runTransaction : null;

  // H1: an era recorded ONLY in the (bot-writable) database is adopted into the host state file
  // before anything decides between converting and scanning.
  for (const family of TOKEN_STORE_FAMILIES) {
    // eslint-disable-next-line no-await-in-loop -- three families, once at boot
    await adoptEra(family, {
      db, audit: auditFn, now, hasPendingSnapshot: (keyId) => Boolean(pendingSnapshot(family, keyId)),
    });
  }

  // The evidence flags are REQUIRED by ensureKey({allowCreate:true}) — an explicit scan.
  let mirrorConverted = false;
  for (const family of TOKEN_STORE_FAMILIES) {
    // eslint-disable-next-line no-await-in-loop -- three families, once at boot
    if (await tokenFamilyConverted(family, db)) {
      mirrorConverted = true;
      break;
    }
  }
  let h1ValuesExist = false;
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM oauth_tokens WHERE token LIKE 'h1.%' LIMIT 1",
      args: [],
    });
    h1ValuesExist = rows.some((row) => Number(row?.present) === 1);
  } catch {
    h1ValuesExist = true; // cannot tell → never "this box is new"
  }
  noteEraEvidence({ mirrorConverted, h1ValuesExist });

  let key;
  try {
    key = ensureKey({ allowCreate: true, mirrorConverted, h1ValuesExist });
  } catch (err) {
    if (err instanceof TokenMacKeyError) {
      console.error(
        `[token-hmac] the token-hmac key is ${err.state === "lost" ? "lost" : "unusable"}: ${keyPath}. `
        + "Every OAuth token and dashboard session is being refused; the gateway is still running. "
        + "Recreate it deliberately with `node scripts/token-hmac.mjs --reset` (operator shell) — "
        + "that signs everyone out and revokes every OAuth grant.",
      );
      return {
        key: err.state === "lost" ? "lost" : "invalid",
        keyPath,
        families: [],
        alarms: 0,
      };
    }
    throw err;
  }

  const families = [];
  let alarms = 0;
  for (const family of TOKEN_STORE_FAMILIES) {
    // §M2: this family's failure is ITS OWN. A throw here is retried in place (before listen); a
    // family that still fails refuses legacy values for the rest of this process and writes NO
    // era, so the next boot resumes from its snapshot and converts.
    let result = null;
    let failure = null;
    for (let attempt = 0; attempt <= retryDelays.length; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop -- one family at a time, by design
        // The DECISION is the host state file alone (adoptMirrorOnlyEra above); the validators keep
        // the fail-closed state-OR-mirror check.
        const converted = hostEraRecorded(family);
        // eslint-disable-next-line no-await-in-loop
        result = converted
          ? await scanConvertedFamily(db, family, { audit: auditFn })
          : await convertFamily(db, family, {
            key,
            audit: auditFn,
            now,
            runTransaction: transactionFor ? (runner) => transactionFor(family, runner) : undefined,
            writeSnapshot,
          });
        failure = null;
        break;
      } catch (err) {
        failure = err;
        if (attempt < retryDelays.length) {
          // eslint-disable-next-line no-await-in-loop -- the retry must not overlap the next try
          await wait(Number(retryDelays[attempt]) || 0);
        }
      }
    }
    if (failure) {
      forceRefuseLegacy(family);
      console.error(
        `[token-hmac] the ${family} conversion failed (${failure?.message || failure}); old-style values for `
        + "that family are REFUSED for the rest of this process and nothing was recorded, so the next boot "
        + "resumes the conversion from its snapshot.",
      );
      families.push({ family, state: "failed", reason: String(failure?.message || failure) });
      continue;
    }
    if (result.state === "converted" && result.count) {
      console.log(
        `[token-hmac] converted ${family}: ${result.count} row(s), snapshot secrets/${result.rollbackFile}`,
      );
    } else if (result.state === "skipped") {
      console.warn(
        `[token-hmac] skipped the ${family} conversion: ${result.reason}; old-style values stay accepted `
        + "(unprotected) until this is fixed.",
      );
    }
    if (result.alarms) {
      console.warn(`[token-hmac] ${family}: ${result.alarms} old-style row(s) found after conversion — they were refused, not converted.`);
    }
    alarms += result.alarms || 0;
    families.push(result);
  }

  return { key: "ok", keyPath, families, alarms };
}