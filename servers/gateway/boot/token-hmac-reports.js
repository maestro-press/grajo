/**
 * Pre-listen boot for the `report:link` family (§8 PR 5a of the keyed-token-hashes design):
 * convert every legacy (bare sha256, either hex case) `report_link_tokens.token_hash` to its `h1.`
 * form and alarm on old-style values that appear afterwards.
 *
 * Same shape as `token-hmac-peers.js`:
 *   1. Snapshot `{id, legacy}` of EVERY row holding a bare sha256 (expired and revoked rows too:
 *      they convert and stay refused by their own columns) into
 *      `secrets/report-token-hmac-rollback-<stamp>.json` (0600, atomic, hashes only).
 *   2. ONE transaction rewrites each snapshot row with compare-and-swap
 *      (`UPDATE … SET token_hash = <h1> WHERE id = ? AND token_hash = <legacy>`).
 *   3. `markConverted` (state file + `token_hmac_era:report:link` mirror).
 * CRASH RE-RUN: a snapshot (EVEN AN EMPTY ONE) without `converted_at` is pending; that boot
 * converts only its rows and alarms on every other legacy row, so a crash cannot launder a
 * post-snapshot write. A store with no `report_link_tokens` table is marked converted with 0 rows.
 * ANY OTHER FAILURE refuses legacy for the rest of this process (`forceRefuseReportLinkLegacy`),
 * records no era, and the next boot resumes. A lost or invalid key logs one loud line and the boot
 * carries on: every link then answers `unknown`. Console lines and audit rows only.
 */
import {
  closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import {
  TokenMacKeyError, ensureKey, legacyAlarm, macFromLegacy, markConverted, noteEraEvidence, tokenMacKeyPath,
} from "../../shared/token-mac.js";
import { ensureSecretsDir } from "../../shared/peer-credentials.js";
import { writeSetting } from "../dashboard/settings/registry.js";
import { auditLog } from "../../db.js";
import { adoptMirrorOnlyEra, hostEraRecorded } from "./token-hmac-era-adopt.js";
import {
  REPORT_LINK_FAMILY, forceRefuseReportLinkLegacy, h1ValuesExist, isLegacyStored, reportLinkFamilyConverted,
} from "../reports/link-token.js";

/** Its own prefix: no other era's rollback tool may read or block on these files. */
export const REPORT_LINK_ROLLBACK_PREFIX = "report-token-hmac-rollback-";
const SNAPSHOT_VERSION = 1;

const secretsDir = () => dirname(tokenMacKeyPath());
const stamp = (at = new Date()) => at.toISOString().replace(/[:.]/g, "-");

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

/** The newest snapshot (empty ones count) for this family and key, or null. */
function pendingSnapshot(keyId) {
  const dir = secretsDir();
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  let best = null;
  for (const name of names) {
    if (!name.startsWith(REPORT_LINK_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== SNAPSHOT_VERSION || body.family !== REPORT_LINK_FAMILY || !Array.isArray(body.rows)) continue;
    if (keyId && body.key_id !== keyId) continue;
    const rows = body.rows
      .map((r) => ({ id: typeof r?.id === "string" ? r.id : "", legacy: typeof r?.legacy === "string" ? r.legacy.toLowerCase() : "" }))
      .filter((r) => r.id && isLegacyStored(r.legacy));
    if (!best || mtimeMs > best.mtimeMs) best = { name, rows, mtimeMs };
  }
  return best;
}

/** Every row holding a bare sha256 as `{id, legacy}`; null when the table does not exist. */
async function legacyRows(db) {
  try {
    const { rows } = await db.execute({ sql: "SELECT id AS id, token_hash AS legacy FROM report_link_tokens", args: [] });
    return rows
      .map((r) => ({ id: String(r.id ?? ""), legacy: String(r.legacy ?? "") }))
      .filter((r) => r.id && isLegacyStored(r.legacy));
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

async function markFamily(db, { count, rollbackFile, now }) {
  return markConverted(REPORT_LINK_FAMILY, {
    count,
    rollbackFile,
    at: (now || new Date()).toISOString(),
    writeSetting: (k, v, o) => writeSetting(db, k, v, o),
  });
}

async function convertFamily(db, { key, audit, now, runTransaction, writeSnapshot: writeSnapshotFor }) {
  const inTransaction = typeof runTransaction === "function" ? runTransaction : (runner) => db.runTransaction(runner);
  const snapshot = typeof writeSnapshotFor === "function" ? writeSnapshotFor : writeSnapshot;
  const pending = pendingSnapshot(key.id);
  let snapshotRows;
  let rollbackName;
  if (pending) {
    snapshotRows = pending.rows;
    rollbackName = pending.name;
    console.warn(
      `[token-hmac] resuming an interrupted conversion of ${REPORT_LINK_FAMILY} from secrets/${pending.name}: `
      + "only the rows in that snapshot are converted; any other old-style row stays and is reported.",
    );
  } else {
    const found = await legacyRows(db);
    if (found === null) {
      // No table on this store: nothing to convert; the era is still recorded.
      const mark = await markFamily(db, { count: 0, rollbackFile: null, now });
      return { family: REPORT_LINK_FAMILY, state: "converted", count: 0, rollbackFile: null, alarms: 0, changed: mark.changed };
    }
    snapshotRows = found;
    rollbackName = `${REPORT_LINK_ROLLBACK_PREFIX}${stamp(now)}.json`;
    try {
      snapshot(rollbackName, {
        v: SNAPSHOT_VERSION,
        family: REPORT_LINK_FAMILY,
        key_id: key.id,
        created_at: (now || new Date()).toISOString(),
        rows: snapshotRows,
      });
    } catch (err) {
      return { family: REPORT_LINK_FAMILY, state: "skipped", reason: `secrets/ is not writable (${err.code || err.message})` };
    }
  }

  const inSnapshot = new Set(snapshotRows.map((r) => `${r.id}\u0000${r.legacy}`));
  const snapshotIds = new Set(snapshotRows.map((r) => r.id));
  const nowMs = (now || new Date()).getTime();
  let count = 0;
  // Rows whose keyed value sat on ANOTHER row when this one was converted (M1): copies, or the
  // twin of an uppercase/lowercase legacy pair. They are revoked and their value is freed, so the
  // UNIQUE column can never abort the transaction (and the era never goes unrecorded).
  const copies = [];
  const convertedIds = new Set();
  // A tombstone is never a credential (not 64-hex, not `h1.`). Its suffix is random, so a bot cannot
  // pre-insert the value a tombstone UPDATE will write and make that UPDATE hit UNIQUE (M-A); and any
  // row that already holds the chosen value is itself revoked first and reported.
  const tombstoneValue = (id) => `revoked:${id}:${randomBytes(8).toString("hex")}`;
  const revokeTo = (run, id, value) => run({
    sql: "UPDATE report_link_tokens SET revoked_at = COALESCE(revoked_at, ?), token_hash = ? WHERE id = ?",
    args: [nowMs, value, id],
  });
  const tombstone = (run, id) => {
    const value = tombstoneValue(id);
    const clash = run({
      sql: "SELECT id AS id FROM report_link_tokens WHERE token_hash = ? AND id != ?", args: [value, id],
    })?.rows?.[0];
    if (clash) {
      revokeTo(run, String(clash.id), tombstoneValue(String(clash.id)));
      copies.push(String(clash.id));
    }
    revokeTo(run, id, value);
    copies.push(id);
  };
  await inTransaction((run) => {
    for (const entry of snapshotRows) {
      const h1 = macFromLegacy(REPORT_LINK_FAMILY, entry.legacy);
      // Only a row that still holds its snapshot value is converted (the CAS), and only then can its
      // target collide.
      const own = run({
        sql: "SELECT revoked_at AS revoked FROM report_link_tokens WHERE id = ? AND token_hash = ?",
        args: [entry.id, entry.legacy],
      });
      if (!own?.rows?.length) continue;
      const holder = run({
        sql: "SELECT id AS id, revoked_at AS revoked FROM report_link_tokens WHERE token_hash = ? AND id != ?",
        args: [h1, entry.id],
      })?.rows?.[0];
      if (holder) {
        // A copy (a holder that is NOT a snapshot row) is always the victim. For a TWIN (the holder is
        // itself a snapshot row) the LOWERCASE row is the genuine one: writers only ever store
        // lowercase, so when this row's legacy value is not lowercase it is the copy; otherwise the
        // holder is. (L-C: the survivor never depends on rowid order or on which row is live.)
        const holderIsTwin = snapshotIds.has(String(holder.id));
        const victim = holderIsTwin && entry.legacy !== entry.legacy.toLowerCase() ? entry.id : String(holder.id);
        tombstone(run, victim);
        if (convertedIds.delete(victim)) count -= 1; // a tombstoned row is not a converted one
        if (victim === entry.id) continue;
      }
      const res = run({
        sql: "UPDATE report_link_tokens SET token_hash = ? WHERE id = ? AND token_hash = ?",
        args: [h1, entry.id, entry.legacy],
      });
      if ((Number(res?.rowsAffected) || 0) > 0) {
        count += 1;
        convertedIds.add(entry.id);
      }
    }
  });

  let alarms = 0;
  for (const id of copies) {
    legacyAlarm(REPORT_LINK_FAMILY, id, { audit });
    alarms += 1;
  }
  for (const row of (await legacyRows(db)) ?? []) {
    if (inSnapshot.has(`${row.id}\u0000${row.legacy}`)) continue;
    legacyAlarm(REPORT_LINK_FAMILY, row.id, { audit });
    alarms += 1;
  }

  const mark = await markFamily(db, { count, rollbackFile: rollbackName, now });
  return { family: REPORT_LINK_FAMILY, state: "converted", count, rollbackFile: rollbackName, alarms, copies: copies.length, changed: mark.changed };
}

async function scanConvertedFamily(db, { audit }) {
  let alarms = 0;
  for (const row of (await legacyRows(db)) ?? []) {
    legacyAlarm(REPORT_LINK_FAMILY, row.id, { audit });
    alarms += 1;
  }
  return { family: REPORT_LINK_FAMILY, state: "converted", scan: true, alarms };
}

/**
 * Run the boot: evidence → key → convert or scan.
 *
 * `runTransaction` and `writeSnapshot` are TEST seams. Never throws for a key problem.
 *
 * @returns {Promise<{key: "ok"|"lost"|"invalid", keyPath: string, family: object|null,
 *          converted: number, alarms: number}>}
 */
export async function runReportLinkTokenHmacBoot({
  db, now = new Date(), audit, runTransaction, writeSnapshot, adoptEra = adoptMirrorOnlyEra,
} = {}) {
  if (!db) throw new TypeError("runReportLinkTokenHmacBoot needs a crow.db client");
  const auditFn = typeof audit === "function" ? audit : (eventType, details) => auditLog(db, eventType, { details });
  const keyPath = tokenMacKeyPath();

  // H1: an era recorded ONLY in the (bot-writable) database is adopted into the host state file
  // before anything decides between converting and scanning.
  await adoptEra(REPORT_LINK_FAMILY, {
    db, audit: auditFn, now, hasPendingSnapshot: (keyId) => Boolean(pendingSnapshot(keyId)),
  });

  let mirrorConverted = false;
  try {
    mirrorConverted = await reportLinkFamilyConverted(db);
  } catch {
    mirrorConverted = true;
  }
  let h1 = false;
  try {
    h1 = await h1ValuesExist(db);
  } catch {
    h1 = true;
  }
  noteEraEvidence({ mirrorConverted, h1ValuesExist: h1 });

  let key;
  try {
    key = ensureKey({ allowCreate: true, mirrorConverted, h1ValuesExist: h1 });
  } catch (err) {
    if (err instanceof TokenMacKeyError) {
      console.error(
        `[token-hmac] the report-link key is ${err.state === "lost" ? "lost" : "unusable"}: ${keyPath}. `
        + "Every report link is being refused; the gateway is still running. Recreate it deliberately "
        + "with `node scripts/token-hmac.mjs --reset` (operator shell) — recipients get new links on the "
        + "next scheduled run.",
      );
      return { key: err.state === "lost" ? "lost" : "invalid", keyPath, family: null, converted: 0, alarms: 0 };
    }
    throw err;
  }

  let result;
  try {
    // The DECISION is the host state file alone; the validators keep the fail-closed check.
    const isConverted = hostEraRecorded(REPORT_LINK_FAMILY);
    result = isConverted
      ? await scanConvertedFamily(db, { audit: auditFn })
      : await convertFamily(db, { key, audit: auditFn, now, runTransaction, writeSnapshot });
  } catch (err) {
    forceRefuseReportLinkLegacy();
    console.error(
      `[token-hmac] the ${REPORT_LINK_FAMILY} conversion failed (${err?.message || err}); old-style values for that `
      + "family are REFUSED for the rest of this process and nothing was recorded, so the next boot "
      + "resumes the conversion from its snapshot.",
    );
    return {
      key: "ok", keyPath, family: { family: REPORT_LINK_FAMILY, state: "failed", reason: String(err?.message || err) },
      converted: 0, alarms: 0,
    };
  }

  if (result.state === "converted" && result.count) {
    console.log(`[token-hmac] converted ${REPORT_LINK_FAMILY}: ${result.count} row(s), snapshot secrets/${result.rollbackFile}`);
  } else if (result.state === "skipped") {
    console.warn(
      `[token-hmac] skipped the ${REPORT_LINK_FAMILY} conversion: ${result.reason}; old-style values stay `
      + "accepted (unprotected) until this is fixed.",
    );
  }
  if (result.alarms) {
    console.warn(
      `[token-hmac] ${REPORT_LINK_FAMILY}: ${result.alarms} old-style row(s) found after conversion — they were `
      + "refused, not converted.",
    );
  }
  return { key: "ok", keyPath, family: result, converted: result.count || 0, alarms: result.alarms || 0 };
}
