/**
 * Pre-listen boot for the `peer:inbound` family (§1b / §3.2 / §3.3 / §8 PR 4 of the
 * keyed-token-hashes design): convert every legacy (bare sha256) value in
 * `crow_instances.auth_token_hash` to its `h1.` form, record the legacy value the re-pair proof
 * needs, and alarm on old-style values that appear afterwards.
 *
 * ORDER. `servers/gateway/index.js` runs this after the `oauth_tokens` and settings boots and
 * long before listen, so `validateInstanceToken`, the cross-host signed-call middleware and the
 * enroll route only ever see values the converter has visited — the accepted-legacy window is
 * zero, not "until the next restart".
 *
 * CONVERSION (§3.2):
 *   1. Snapshot `{id, token}` of every row holding a bare sha256 into
 *      `secrets/peer-token-hmac-rollback-<stamp>.json` (0600, atomic, hashes only).
 *   2. In ONE transaction, rewrite each snapshot row with compare-and-swap
 *      (`UPDATE … SET auth_token_hash = <h1> WHERE id = <id> AND auth_token_hash = <legacy>`).
 *      A NULL (revoked) row is untouched: it is not in the snapshot at all.
 *   3. Commit, then record `inbound_bearer_sha256` in `secrets/peer-tokens.json` for every
 *      converted peer (design D4 — the value being converted IS that hash, and after the
 *      conversion it is the only place the re-pair proof can still come from), then
 *      `markConverted` (secrets-side marker + the `token_hmac_era:<family>` DB mirror).
 *
 * CRASH RE-RUN (§3.2): if the process dies between 2 and 3, the family has no `converted_at`
 * but its snapshot file is still there — including an EMPTY one, taken when the store held no
 * legacy row (see `pendingSnapshot`). That boot converts ONLY the rows listed in the snapshot
 * that still hold their snapshot value; any other legacy row is a post-snapshot write, so it is
 * NOT converted and raises the alarm. That is what keeps a bot from laundering a write through
 * a crash-and-restart.
 *
 * A CONVERTED ROW WITH NO CREDENTIAL RECORD IS REPORTED, NEVER REFUSED (L2): the verifier does
 * not need `secrets/peer-tokens.json`, so the conversion proceeds; only the D4 re-pair record
 * is impossible. One boot line carries the count.
 *
 * NOT WRITABLE SECRETS (§2.6 last row): the snapshot write is the gate. If it fails the family
 * is skipped, logged, and NO era is recorded — legacy stays accepted (and unprotected) rather
 * than every peer being locked out.
 *
 * ANY OTHER FAILURE REFUSES LEGACY (§M2). A conversion (or its post-conversion scan) that throws
 * must never fail open: the family is refused for the rest of THIS process
 * (`forceRefusePeerLegacy`) with one console line, and no era is written, so the next boot
 * resumes from the snapshot and converts.
 *
 * THE KEY IS NEVER REPLACED HERE. A lost or invalid key logs one loud line naming the file and
 * the recovery command, and the boot CARRIES ON: the gateway still starts, while every peer
 * bearer is refused through `token-mac`'s own key-lost refusal. No new user-visible text: this
 * file only writes console lines and audit rows.
 */
import {
  closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  TokenMacKeyError, ensureKey, legacyAlarm, macFromLegacy, markConverted, noteEraEvidence, tokenMacKeyPath,
} from "../../shared/token-mac.js";
import { ensureSecretsDir, getPeerCreds, setInboundBearerSha256Many } from "../../shared/peer-credentials.js";
import { writeSetting } from "../dashboard/settings/registry.js";
import { auditLog } from "../../db.js";
import {
  PEER_INBOUND_FAMILY, forceRefusePeerLegacy, h1ValuesExist, isLegacyStored, peerFamilyConverted,
} from "../peer-inbound-token.js";

/**
 * Snapshot file prefix inside `secrets/`. DELIBERATELY NOT `token-hmac-rollback-` (the
 * `oauth_tokens` converter's prefix) nor `settings-token-hmac-rollback-`: each era rolls back
 * on its own, and the `oauth_tokens` rollback refuses any snapshot naming a family it does not
 * restore — a peer snapshot under its prefix would block every rollback of that era.
 */
export const PEER_ROLLBACK_PREFIX = "peer-token-hmac-rollback-";
const SNAPSHOT_VERSION = 1;

function secretsDir() {
  return dirname(tokenMacKeyPath());
}

/** `2026-11-23T16:41:02.123Z` → a file-name-safe stamp. */
function stamp(at = new Date()) {
  return at.toISOString().replace(/[:.]/g, "-");
}

/** Write the snapshot atomically and owner-only (temp 0600 + fsync + rename + fsync dir). */
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
 * The newest peer snapshot for a conversion a crash interrupted, or null. Only its own prefix
 * is scanned, so the two other eras' files are never read as ours (and vice versa). A snapshot
 * written under another key is ignored: its values belong to a key this box no longer holds.
 *
 * AN EMPTY SNAPSHOT IS STILL A PENDING ONE. `rows: []` means the snapshot was taken when this
 * store held no legacy row at all — the conversion committed (nothing) and the process died
 * before `markConverted`. Skipping such a file would let that boot start a FRESH conversion and
 * launder a legacy row something wrote in between (past the crash and this restart) into a
 * credential the writer knows the bearer of. So any snapshot naming this family and this key
 * counts as pending: the rerun converts only its (zero) rows, refuses-and-alarms every other
 * legacy value, and marks the family.
 */
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
    if (!name.startsWith(PEER_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== SNAPSHOT_VERSION || body.family !== PEER_INBOUND_FAMILY || !Array.isArray(body.rows)) continue;
    if (keyId && body.key_id !== keyId) continue;
    const rows = body.rows
      .map((r) => ({ id: typeof r?.id === "string" ? r.id : "", token: typeof r?.token === "string" ? r.token.toLowerCase() : "" }))
      .filter((r) => r.id && isLegacyStored(r.token));
    if (!best || mtimeMs > best.mtimeMs) best = { name, rows, mtimeMs };
  }
  return best;
}

/** Every row holding a stored value, as `{id, token}` (either form — the caller filters). */
async function storedRows(db) {
  const { rows } = await db.execute({
    sql: "SELECT id AS id, auth_token_hash AS token FROM crow_instances WHERE auth_token_hash IS NOT NULL",
    args: [],
  });
  return rows.map((r) => ({ id: String(r.id ?? ""), token: String(r.token ?? "") })).filter((r) => r.id);
}

/** The legacy (bare sha256) rows only — what a fresh conversion rewrites. */
async function legacyRows(db) {
  return (await storedRows(db)).filter((r) => isLegacyStored(r.token));
}

/**
 * Record `inbound_bearer_sha256` for the peers this run converted (design D4).
 *
 * A row is recorded when its CURRENT stored value is either the snapshot's legacy value (the
 * CAS missed — a concurrent write, or an earlier interrupted run) or the `h1.` value computed
 * from it. Anything else was rewritten by something other than this conversion, so its legacy
 * hash is no longer the peer's bearer and recording it could only make a re-pair proof fail
 * (fail closed, never open) — it is skipped rather than guessed.
 *
 * @returns {Promise<string[]>} the peer ids whose store entry gained the record
 */
async function recordInboundHashes(db, snapshotRows) {
  const records = [];
  for (const entry of snapshotRows) {
    // eslint-disable-next-line no-await-in-loop -- at most a handful of peers, once at boot
    const { rows } = await db.execute({
      sql: "SELECT auth_token_hash AS token FROM crow_instances WHERE id = ?",
      args: [entry.id],
    });
    const stored = String(rows?.[0]?.token ?? "");
    if (stored !== entry.token && stored !== macFromLegacy(PEER_INBOUND_FAMILY, entry.token)) continue;
    records.push({ id: entry.id, sha256: entry.token });
  }
  if (records.length === 0) return [];
  try {
    return setInboundBearerSha256Many(records);
  } catch (err) {
    // The verifiers are already keyed and the era is about to be marked; a store we cannot write
    // costs the re-pair PROOF (which then falls back to the operator allowance), never the
    // bearer. Say so, never block the boot on it.
    console.warn(
      `[token-hmac] the ${PEER_INBOUND_FAMILY} conversion could not record inbound_bearer_sha256 for `
      + `${records.length} peer(s) in secrets/peer-tokens.json (${err?.message || err}); a re-pair proof for `
      + "them will need `crow instance pair --allow-re-pair <id>` until the store is writable.",
    );
    return [];
  }
}

/**
 * How many of these peers have NO usable credential record in `secrets/peer-tokens.json` — no
 * entry at all, or an entry without a `signing_key`.
 *
 * Nothing here refuses: the verification of a peer bearer needs neither, so the conversion still
 * runs (the `h1.` value is minted from the stored hash, no credential needed). What is lost is
 * the D4 RECORD (`inbound_bearer_sha256`) and the re-pair PROOF: a proof is keyed by that hash
 * plus the pair's signing key, so a pair with no store entry has to be re-paired through the
 * peer operator's `--allow-re-pair` allowance. That is worth one line at boot and one count in
 * the dry run — never a refusal, never an id.
 */
function countWithoutCredential(ids) {
  let n = 0;
  for (const id of ids) {
    let entry = null;
    try { entry = getPeerCreds(id); } catch { entry = null; }
    const usable = entry && typeof entry === "object" && !Array.isArray(entry)
      && typeof entry.signing_key === "string" && entry.signing_key !== "";
    if (!usable) n += 1;
  }
  return n;
}

/**
 * Convert the family: snapshot, one CAS transaction, the D4 records, then the era marker.
 *
 * `runTransaction` and `writeSnapshot` are TEST seams; production passes neither.
 */
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
      `[token-hmac] resuming an interrupted conversion of ${PEER_INBOUND_FAMILY} from secrets/${pending.name}: `
      + "only the rows in that snapshot are converted; any other old-style row stays and is reported.",
    );
  } else {
    snapshotRows = await legacyRows(db);
    rollbackName = `${PEER_ROLLBACK_PREFIX}${stamp(now)}.json`;
    try {
      snapshot(rollbackName, {
        v: SNAPSHOT_VERSION,
        family: PEER_INBOUND_FAMILY,
        key_id: key.id,
        created_at: (now || new Date()).toISOString(),
        rows: snapshotRows,
      });
    } catch (err) {
      return { family: PEER_INBOUND_FAMILY, state: "skipped", reason: `secrets/ is not writable (${err.code || err.message})` };
    }
  }

  const inSnapshot = new Set(snapshotRows.map((r) => `${r.id}\u0000${r.token}`));
  let count = 0;
  await inTransaction((run) => {
    for (const entry of snapshotRows) {
      const h1 = macFromLegacy(PEER_INBOUND_FAMILY, entry.token);
      // `status != 'revoked'` is belt and braces on top of the CAS: a revoked row's value is
      // NULL, so it is never in the snapshot, and this conversion must never be what revives one.
      const res = run({
        sql: "UPDATE crow_instances SET auth_token_hash = ? WHERE id = ? AND auth_token_hash = ? AND status != 'revoked'",
        args: [h1, entry.id, entry.token],
      });
      if ((Number(res?.rowsAffected) || 0) > 0) count += 1;
    }
  });

  // A row not in the snapshot is a post-snapshot write: NOT converted (§3.2).
  let alarms = 0;
  for (const row of await legacyRows(db)) {
    if (inSnapshot.has(`${row.id}\u0000${row.token}`)) continue;
    legacyAlarm(PEER_INBOUND_FAMILY, row.id, { audit });
    alarms += 1;
  }

  // D4: the re-pair proof is keyed by sha256(our current bearer) + the shared signing key, and
  // the stored verifier is a MAC now — so the legacy value is recorded beside the signing key.
  const recorded = snapshotRows.length ? await recordInboundHashes(db, snapshotRows) : [];

  const noCredential = countWithoutCredential(snapshotRows.map((r) => r.id));

  const mark = await markConverted(PEER_INBOUND_FAMILY, {
    count,
    rollbackFile: rollbackName,
    at: (now || new Date()).toISOString(),
    writeSetting: (k, v, o) => writeSetting(db, k, v, o),
  });
  return {
    family: PEER_INBOUND_FAMILY,
    state: "converted",
    count,
    rollbackFile: rollbackName,
    alarms,
    records: recorded.length,
    noCredential,
    changed: mark.changed,
  };
}

/** The post-conversion boot scan of §3.3: any old-style row alarms, nobody converts it. */
async function scanConvertedFamily(db, { audit }) {
  let alarms = 0;
  for (const row of await legacyRows(db)) {
    legacyAlarm(PEER_INBOUND_FAMILY, row.id, { audit });
    alarms += 1;
  }
  return { family: PEER_INBOUND_FAMILY, state: "converted", scan: true, alarms, records: 0 };
}

/**
 * Run the boot: evidence → key → convert or scan.
 *
 * @param {{ db: object, now?: Date, audit?: Function,
 *           runTransaction?: (runner: Function) => any,
 *           writeSnapshot?: (name: string, body: object) => string }} opts
 *        `db` is the gateway's crow.db client; `audit` defaults to `auditLog` on that client.
 *        `runTransaction` and `writeSnapshot` are TEST seams for the §M2 failure path and the
 *        §2.6 skip; production passes neither.
 * @returns {Promise<{key: "ok"|"lost"|"invalid", keyPath: string, family: object|null,
 *          converted: number, alarms: number, records: number, noCredential: number}>} Never
 *          throws for a key problem: the gateway must still start. `noCredential` counts the
 *          converted peers with no usable `secrets/peer-tokens.json` entry (reported, never
 *          refused).
 */
export async function runPeerTokenHmacBoot({ db, now = new Date(), audit, runTransaction, writeSnapshot } = {}) {
  if (!db) throw new TypeError("runPeerTokenHmacBoot needs a crow.db client");
  const auditFn = typeof audit === "function" ? audit : (eventType, details) => auditLog(db, eventType, { details });
  const keyPath = tokenMacKeyPath();

  // The evidence flags are REQUIRED by ensureKey({allowCreate:true}) — an explicit scan.
  let mirrorConverted = false;
  try {
    mirrorConverted = await peerFamilyConverted(db);
  } catch {
    mirrorConverted = true; // cannot tell → never "this box is new"
  }
  let h1 = false;
  try {
    h1 = await h1ValuesExist(db);
  } catch {
    h1 = true; // cannot tell → never "this box is new"
  }
  noteEraEvidence({ mirrorConverted, h1ValuesExist: h1 });

  let key;
  try {
    key = ensureKey({ allowCreate: true, mirrorConverted, h1ValuesExist: h1 });
  } catch (err) {
    if (err instanceof TokenMacKeyError) {
      console.error(
        `[token-hmac] the peer-token key is ${err.state === "lost" ? "lost" : "unusable"}: ${keyPath}. `
        + "Every paired-instance bearer is being refused; the gateway is still running. Recreate it "
        + "deliberately with `node scripts/token-hmac.mjs --reset` (operator shell) — every peer then "
        + "has to re-pair.",
      );
      return {
        key: err.state === "lost" ? "lost" : "invalid",
        keyPath,
        family: null,
        converted: 0,
        alarms: 0,
        records: 0,
        noCredential: 0,
      };
    }
    throw err;
  }

  let result;
  try {
    const isConverted = await peerFamilyConverted(db);
    result = isConverted
      ? await scanConvertedFamily(db, { audit: auditFn })
      : await convertFamily(db, {
        key, audit: auditFn, now, runTransaction, writeSnapshot,
      });
  } catch (err) {
    forceRefusePeerLegacy();
    console.error(
      `[token-hmac] the ${PEER_INBOUND_FAMILY} conversion failed (${err?.message || err}); old-style values for that `
      + "family are REFUSED for the rest of this process and nothing was recorded, so the next boot "
      + "resumes the conversion from its snapshot.",
    );
    return {
      key: "ok", keyPath, family: { family: PEER_INBOUND_FAMILY, state: "failed", reason: String(err?.message || err) },
      converted: 0, alarms: 0, records: 0, noCredential: 0,
    };
  }

  if (result.state === "converted" && result.count) {
    console.log(
      `[token-hmac] converted ${PEER_INBOUND_FAMILY}: ${result.count} row(s), snapshot secrets/${result.rollbackFile}`
      + `${result.records ? `, ${result.records} peer credential record(s) gained inbound_bearer_sha256` : ""}`,
    );
  } else if (result.state === "skipped") {
    console.warn(
      `[token-hmac] skipped the ${PEER_INBOUND_FAMILY} conversion: ${result.reason}; old-style values stay `
      + "accepted (unprotected) until this is fixed.",
    );
  }
  if (result.alarms) {
    console.warn(
      `[token-hmac] ${PEER_INBOUND_FAMILY}: ${result.alarms} old-style row(s) found after conversion — they were `
      + "refused, not converted.",
    );
  }
  // Reported, never refused: the conversion of such a row is fine (it needs no credential), but
  // its re-pair proof cannot be keyed — one count, no ids and no values.
  if (result.noCredential) {
    console.warn(
      `[token-hmac] ${PEER_INBOUND_FAMILY}: ${result.noCredential} converted row(s) have no credential record `
      + "in secrets/peer-tokens.json (no signing key), so no re-pair proof can be keyed for them; re-pairing "
      + "them needs the peer operator's --allow-re-pair allowance.",
    );
  }
  return {
    key: "ok",
    keyPath,
    family: result,
    converted: result.count || 0,
    alarms: result.alarms || 0,
    records: result.records || 0,
    noCredential: result.noCredential || 0,
  };
}
