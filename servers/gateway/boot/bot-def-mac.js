/**
 * Pre-listen boot for the `bot:def` family: create or load the keyed-hash key, seal every
 * existing bot definition with its MAC + generation, and mark the era.
 *
 * ORDER. `servers/gateway/index.js` calls this beside the other token-mac boots, after the schema
 * exists and BEFORE listen, so no spawn path (the bridge loads a definition per turn) and no
 * authority read can trust a row the converter has not seen.
 *
 * THE ERA RECORD IS HOST STATE. `<CROW_HOME>/secrets/bot-def-era.json` (`{state: "converted" | "failed" |
 * "skipped", at, reason?}`, 0600, atomic) is written on EVERY outcome of this boot, including a fresh
 * install with no rows, and is the ONLY thing every verifier (the gateway's, the bridge's) reads to
 * decide the era: a missing record, "failed" and "skipped" all REFUSE unsealed rows; sealed rows
 * verify normally. "Already converted" means that record says so — the DB mirror
 * (`token_hmac_era:bot:def`) or the token-mac marker alone never skip the conversion (a contained bot
 * can plant the mirror), and once the record says converted it never goes back. DEPLOY ORDER: gateway
 * first (it writes the record), then the bridge. If secrets/ cannot be written at all the boot logs
 * one error, the gateway stays up and unsealed rows stay refused.
 *
 * FIRST BOOT BLESSES ROWS AS THEY STAND. The conversion seals every row it finds, whoever wrote it,
 * so a row a bot raised before this release's first boot is blessed with it. The converter logs ONE
 * authority summary line per bot (id, enabled, project, tool count — no secrets) on that boot so the
 * operator can review what was blessed; `scripts/cli/bot-def-reapprove.mjs --show` diffs against the
 * approved copy afterwards.
 *
 * A row that cannot be canonicalised (nested past the bounds in `canonicalJson`) is left unsealed,
 * refused, listed once in a warning, and does not stop the era from being recorded.
 *
 * CANONICAL TEXT. Each sealed row's `definition` is rewritten to its canonical serialization in the
 * same statement (content-preserving: the parsed VALUE is what the MAC covers), so every row this
 * converter blesses satisfies the rule verification applies afterwards — the stored text is
 * exactly the canonical form of the one document it holds, which removes duplicate keys and any
 * `JSON.parse`-vs-`json_extract` disagreement.
 *
 * UNEXPECTED TRIGGERS. A trigger on `pi_bot_defs` that Crow did not install — or one whose body
 * changed — is named in one loud line on every boot (never dropped automatically): it can rewrite a
 * row after a writer signed it. The expected set, and the name-plus-normalised-SQL comparison, come
 * from `servers/shared/trigger-catalog.js`; it is the same rule `writeBotDef` refuses a write on.
 *
 * CONVERSION, one shot and never a second one:
 *   1. Snapshot every row as `{bot_id, sha256(canonicalBotDef(row, generation 1))}` into
 *      `secrets/bot-def-rollback-<stamp>.json` (0600, atomic) — HASHES only, exactly like the
 *      `oauth_tokens` converter: a definition may hold a gateway token or `spawn_env`, and the
 *      rollback file is not the place for it.
 *   2. In ONE transaction, for each snapshot row that STILL holds the snapshot's content and has
 *      no generation yet: `def_generation = 1`, `def_mac = mac`. The content check (re-computed
 *      inside the transaction) is the anti-laundering rule — a row edited after the snapshot, or
 *      created after it (not in the snapshot at all), is NOT blessed.
 *   3. Commit, then write the generations file (generation 1 for every sealed row), then
 *      `markConverted` (secrets-side marker + the `token_hmac_era:bot:def` DB mirror).
 *
 * CRASH RE-RUN. A crash between 2 and 3 leaves no era marker but a snapshot file. That boot
 * resumes from the snapshot and converts ONLY the rows it lists that still hold its hashes; any
 * other row is a post-snapshot write, so it keeps no MAC and is refused (with an alarm line) once
 * the era is marked. Converting is deterministic (same content, same key, generation 1), so a
 * re-run after a successful commit rewrites nothing new.
 *
 * NOT WRITABLE `secrets/` (§2.6 last row, the same rule as the other converters): if the snapshot
 * cannot be written, the conversion is SKIPPED, logged, and NO era is recorded — unsealed rows stay
 * REFUSED (no sealing is possible until secrets/ is writable). ANY OTHER FAILURE also refuses unsealed
 * definitions for the rest of this process (`forceRefuseBotDefUnsealed`) and writes no era, so the
 * next boot resumes.
 *
 * THE KEY IS NEVER REPLACED HERE. A lost or invalid key logs one loud line (naming the file and
 * `node scripts/token-hmac.mjs --reset`) and the boot CARRIES ON: the gateway still starts, while
 * every definition is refused by `verifyBotDef`'s own key refusal, so no bot spawns.
 */
import {
  closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import {
  TokenMacKeyError, ensureKey, legacyAlarm, markConverted, noteEraEvidence, readState, tokenMacKeyPath,
} from "../../shared/token-mac.js";
import {
  BOT_DEF_FAMILY, botDefFamilyConverted, botDefKeyAlarm, botDefRowMacVerifies, canonicalBotDef,
  canonicalDefinitionText, forceRefuseBotDefUnsealed, macBotDef, readBotDefEraState, readBotDefGenerations, reconcileBotDefPending,
  seedBotDefGenerations, writeBotDefEraState,
} from "../../shared/bot-def-mac.js";
import { ensureSecretsDir } from "../../shared/secrets-dir.js";
import { writeApprovedBotDef } from "../../shared/bot-def-approved.js";
import {
  expectedTriggersOnTables, readTriggerRows, reachableTriggerTables, sameTableName, unexpectedTriggers,
} from "../../shared/trigger-catalog.js";
// Side effect, on purpose: importing the store installs the bot-loadable WRITE seam
// (servers/shared/bot-def-seal.js) into this process. The boot converter is what every gateway
// imports before listen, so a bundle panel or a bot-loadable module that writes a definition
// through the seam always finds it installed.
import "../../shared/bot-def-store.js";
import { writeSetting } from "../dashboard/settings/registry.js";
import { auditLog } from "../../db.js";

/**
 * Snapshot prefix inside `secrets/`. Deliberately its own: the `oauth_tokens` rollback tool
 * refuses a snapshot naming a family it does not restore, so the two eras roll back separately.
 */
export const BOT_DEF_ROLLBACK_PREFIX = "bot-def-rollback-";
const SNAPSHOT_VERSION = 1;

function secretsDir() {
  return dirname(tokenMacKeyPath());
}

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
 * Record the boot's outcome in the host era record. Never throws: when secrets/ cannot be written the
 * boot says so once and carries on (unsealed rows stay refused, there being no record).
 */
function recordEra(state, reason) {
  try {
    writeBotDefEraState(state, { reason });
  } catch (err) {
    console.error(
      `[bot-def] the era record could not be written (${err?.code || err?.message || err}); unsealed bot `
      + "definitions stay REFUSED until secrets/ is writable and the gateway boots again.",
    );
  }
}

/** One per-bot authority summary line (L1): what the first boot blessed. No definition content. */
function authoritySummary(rows) {
  for (const row of rows) {
    let tools = 0;
    try {
      const d = JSON.parse(row.definition || "{}");
      const c = d?.tools?.crow_mcp;
      tools = Array.isArray(c) ? c.length : (c && typeof c === "object" ? Object.keys(c).length : 0);
    } catch { tools = 0; }
    console.log(
      `[bot-def] first boot blessed ${String(row.bot_id)}: enabled=${Number(row.enabled) === 1 ? 1 : 0}, `
      + `project_id=${row.project_id ?? "none"}, crow tools=${tools}`,
    );
  }
}

/**
 * The converter's rollback snapshots in secrets/: `{any, corrupt}` — whether a valid snapshot of this
 * family exists, and whether one is present but unreadable (or the directory cannot be listed).
 */
function rollbackSnapshotEvidence() {
  const dir = secretsDir();
  let names;
  try {
    names = readdirSync(dir);
  } catch (err) {
    return err?.code === "ENOENT" ? { any: false, corrupt: false } : { any: false, corrupt: true };
  }
  let any = false;
  for (const name of names) {
    if (!name.startsWith(BOT_DEF_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    try {
      const body = JSON.parse(readFileSync(join(dir, name), "utf8"));
      if (body && body.v === SNAPSHOT_VERSION && body.family === BOT_DEF_FAMILY && Array.isArray(body.rows)) any = true;
      else return { any, corrupt: true };
    } catch { return { any, corrupt: true }; }
  }
  return { any, corrupt: false };
}

/**
 * HOST-SIDE evidence that this box converted before, for when the era record itself is missing: the
 * token-mac secrets-side family marker; or the generations file TOGETHER WITH the converter's rollback
 * snapshot (the generations file alone is not evidence: an operator running import-bot-def or
 * init-pi-bots before the first gateway restart creates it); or either of those files present but
 * unreadable or corrupt. Never the DB mirror (a contained bot can plant it). "Could not tell" must
 * never re-open the trust-on-first-use sealing.
 */
function convertedBeforeEvidence() {
  try {
    const st = readState();
    if (st.corrupt || st.families?.[BOT_DEF_FAMILY]?.converted_at) return true;
  } catch { return true; }
  let generationsUsed = false;
  try {
    const g = readBotDefGenerations();
    if (g.corrupt) return true;
    generationsUsed = Object.keys(g.bots || {}).length > 0;
  } catch { return true; }
  const snap = rollbackSnapshotEvidence();
  if (snap.corrupt) return true;
  return generationsUsed && snap.any;
}

/** `sha256(canonicalBotDef(row, generation 1))` — the snapshot's proof of a row's content. */
function rowDigest(row) {
  return createHash("sha256").update(canonicalBotDef({ ...row, def_generation: 1 })).digest("hex");
}

/**
 * The newest snapshot for this family that no era covers — a conversion a crash interrupted — or
 * null. A snapshot written under another key is ignored: its rows belong to a key this box no
 * longer holds.
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
    if (!name.startsWith(BOT_DEF_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== SNAPSHOT_VERSION || body.family !== BOT_DEF_FAMILY || !Array.isArray(body.rows)) continue;
    if (keyId && body.key_id !== keyId) continue;
    const rows = body.rows
      .map((r) => ({ bot_id: typeof r?.bot_id === "string" ? r.bot_id : "", sha256: typeof r?.sha256 === "string" ? r.sha256 : "" }))
      .filter((r) => r.bot_id && /^[0-9a-f]{64}$/.test(r.sha256));
    if (rows.length === 0) continue;
    if (!best || mtimeMs > best.mtimeMs) best = { name, rows, mtimeMs, key_id: body.key_id };
  }
  return best;
}

/** Every row the converter considers, in the shape `canonicalBotDef` takes. */
async function allRows(db, withMac = false) {
  const { rows } = await db.execute({
    sql: `SELECT bot_id, display_name, definition, enabled, project_id, def_generation${withMac ? ", def_mac" : ""} FROM pi_bot_defs`,
    args: [],
  });
  return rows || [];
}

/**
 * ONE loud line naming any trigger on a table a `pi_bot_defs` write REACHES — `pi_bot_defs` itself and
 * every table Crow's own trigger bodies write from there (`item_versions`, via the history capture
 * triggers) — that Crow did not install, or whose body is no longer the body Crow installs
 * (`servers/shared/trigger-catalog.js` compares name AND normalised SQL — the same rule `writeBotDef`
 * refuses a write on, items I2 and J2).
 *
 * A trigger there can rewrite a row AFTER a writer signed it (or re-sign nothing at all, or swallow
 * the write and stash its parameters), or abort the statement after the row change was made, which is
 * exactly the tamper the MAC exists to catch — but a trigger forged by a contained bot (a bot HAS
 * crow.db read-write) is worth naming to the operator on every boot. It is never dropped
 * automatically: dropping somebody's trigger on every boot is the wrong direction for a table this
 * important, and an operator may have put a legitimate one there.
 */
async function warnUnknownTriggers(db) {
  try {
    const { rows } = await readTriggerRows(db);
    // The same reachable set and the same case-insensitive table comparison the store refuses on.
    const tables = reachableTriggerTables("pi_bot_defs");
    const onTables = (rows || []).filter((row) => [...tables].some((t) => sameTableName(row?.tbl_name ?? "", t)));
    const unexpected = unexpectedTriggers(onTables, expectedTriggersOnTables(tables));
    if (unexpected.length) {
      const names = unexpected.map((t) => t.name);
      const changed = unexpected.filter((t) => t.reason === "body-changed").map((t) => t.name);
      const where = [...new Set(unexpected.map((t) => t.table).filter(Boolean))].join(", ") || "pi_bot_defs";
      console.warn(
        `[bot-def] ${names.length} trigger(s) on ${where} were not installed by Crow as they now stand: `
        + `${names.join(", ")}${changed.length ? ` (body changed: ${changed.join(", ")})` : ""}. A trigger there can `
        + "rewrite a bot definition after it was signed (and `writeBotDef` refuses to write while one is "
        + "there); they were left in place — inspect them and drop them by hand if Crow did not put them there.",
      );
      return names;
    }
    return [];
  } catch {
    return [];
  }
}

/**
 * Run the boot.
 *
 * @param {{db: object, now?: Date, audit?: Function,
 *          writeSnapshot?: (name: string, body: object) => string,
 *          runTransaction?: (runner: Function) => any}} opts
 *        `db` is the gateway's crow.db client. `writeSnapshot` and `runTransaction` are TEST seams
 *        (the §2.6 skip and the failure path); production passes neither.
 * @returns {Promise<{key: "ok"|"lost"|"invalid", keyPath: string, state: string,
 *          count: number, refused: number, alarms: number, rollbackFile?: string, reason?: string}>}
 *          Never throws for a key problem: the gateway must still start.
 */
export async function runBotDefMacBoot({
  db, now = new Date(), audit, writeSnapshot: writeSnapshotSeam, runTransaction,
} = {}) {
  if (!db) throw new TypeError("runBotDefMacBoot needs a crow.db client");
  const auditFn = typeof audit === "function" ? audit : (eventType, details) => auditLog(db, eventType, { details });
  const snapshot = typeof writeSnapshotSeam === "function" ? writeSnapshotSeam : writeSnapshot;
  const keyPath = tokenMacKeyPath();
  const inTransaction = typeof runTransaction === "function" ? runTransaction : (runner) => db.runTransaction(runner);
  const out = { key: "ok", keyPath, state: "converted", count: 0, refused: 0, alarms: 0 };

  // The evidence flags `ensureKey({allowCreate:true})` demands. A bot definition MAC is era
  // evidence in exactly the same sense a token verifier is: a row already carrying one means this
  // box has been converted, so a missing key is LOST, never "new".
  let mirrorConverted = false;
  try { mirrorConverted = await botDefFamilyConverted({ readSetting: (k) => readSettingFor(db, k) }); } catch { mirrorConverted = true; }
  let h1ValuesExist = false;
  try {
    const { rows } = await db.execute({ sql: "SELECT 1 AS present FROM pi_bot_defs WHERE def_mac IS NOT NULL LIMIT 1", args: [] });
    h1ValuesExist = rows.some((row) => Number(row?.present) === 1);
  } catch {
    h1ValuesExist = true;
  }
  noteEraEvidence({ mirrorConverted, h1ValuesExist });

  let key;
  try {
    key = ensureKey({ allowCreate: true, mirrorConverted, h1ValuesExist });
  } catch (err) {
    if (!(err instanceof TokenMacKeyError)) throw err;
    botDefKeyAlarm(keyPath, err.state === "lost" ? "lost" : "invalid");
    recordEra("failed", `key-${err.state === "lost" ? "lost" : "invalid"}`);
    return { ...out, key: err.state === "lost" ? "lost" : "invalid", state: "key-problem" };
  }

  // THE HOST RECORD decides "already converted" — never the DB mirror or the token-mac marker, which a
  // contained bot can plant (or, for the mirror, delete). A mirror with no record converts.
  let converted = readBotDefEraState().state === "converted";
  if (!converted && convertedBeforeEvidence()) {
    // The record was lost but the host's own files show a conversion happened: never re-run the
    // first-time sealing (it would bless rows a bot changed since). Restore the record and only
    // scan/verify; unsealed rows stay refused for the owner's reapprove CLI.
    console.warn("[bot-def] era state missing but this box converted before; not re-sealing");
    recordEra("converted");
    converted = true;
  } else if (!converted && mirrorConverted) {
    console.warn("[bot-def] era mirror present without host state; converting");
  }
  // L1: name any trigger Crow did not put on pi_bot_defs (a contained bot can create one). Logged
  // on every boot, on both paths, because it is evidence about the table itself.
  const unexpectedTriggers = await warnUnknownTriggers(db);
  if (converted) {
    // Nothing to convert. A row without a MAC on a converted box is REFUSED by verification (and
    // alarmed there), so this only has to say how many such rows there are.
    // M1: settle or abandon every stale `pending` mark before the gateway listens (no writer is in
    // flight yet), so a tuple a crashed writer signed cannot stay acceptable.
    try {
      reconcileBotDefPending(await allRows(db, true), { abandon: true });
    } catch (err) {
      console.warn(`[bot-def] the pending-generation reconcile failed (${err?.message || err}); left as it was.`);
    }
    let unsealed = [];
    try {
      ({ rows: unsealed } = await db.execute({ sql: "SELECT bot_id FROM pi_bot_defs WHERE def_mac IS NULL", args: [] }));
    } catch { unsealed = []; }
    if (unsealed.length) {
      for (const row of unsealed) legacyAlarm(BOT_DEF_FAMILY, row?.bot_id ?? null, { audit: auditFn });
      out.alarms = unsealed.length;
      console.warn(
        `[bot-def] ${unsealed.length} bot definition(s) carry no MAC on a converted instance; they are refused `
        + "(no bot spawns) until they are written again from Bot Builder.",
      );
    }
    return { ...out, state: "converted", scan: true, unexpectedTriggers };
  }

  // ─── the snapshot ─────────────────────────────────────────────────────────
  // Everything from here to the seal runs after the key exists and before any era is written, so
  // an unexpected throw (a contained bot dropped a seal column, a corrupt pending snapshot) must
  // fail CLOSED for this process, never leave unsealed rows accepted.
  let snapshotRows;
  let rollbackName;
  const badRows = [];
  try {
    const rows = await allRows(db);
    const pending = pendingSnapshot(key.id);
    if (pending) {
      snapshotRows = pending.rows;
      rollbackName = pending.name;
      console.warn(
        `[bot-def] resuming an interrupted conversion from secrets/${pending.name}: only the rows that `
        + "snapshot lists are sealed; any other definition stays unsealed and is refused.",
      );
    } else {
      snapshotRows = [];
      for (const row of rows) {
        // A row that cannot be canonicalised (too deeply nested) is left out: unsealed, refused.
        try {
          snapshotRows.push({ bot_id: String(row.bot_id), sha256: rowDigest(row) });
        } catch {
          badRows.push(String(row.bot_id));
        }
      }
    }
  } catch (err) {
    forceRefuseBotDefUnsealed();
    console.error(
      `[bot-def] the conversion could not read the definitions (${err?.message || err}); unsealed bot `
      + "definitions are REFUSED for the rest of this process and nothing was recorded, so the next boot retries.",
    );
    recordEra("failed", "unreadable-definitions");
    return { ...out, state: "failed", reason: String(err?.message || err) };
  }
  if (!rollbackName) {
    rollbackName = `${BOT_DEF_ROLLBACK_PREFIX}${stamp(now)}.json`;
    try {
      snapshot(rollbackName, {
        v: SNAPSHOT_VERSION,
        family: BOT_DEF_FAMILY,
        key_id: key.id,
        created_at: (now || new Date()).toISOString(),
        // Hashes only: a definition can carry a gateway token or spawn_env (see the header).
        rows: snapshotRows,
      });
    } catch (err) {
      console.warn(
        `[bot-def] skipped the conversion: secrets/ is not writable (${err.code || err.message}); bot `
        + "definitions stay REFUSED (unsealed) until this is fixed.",
      );
      recordEra("skipped", "secrets-not-writable");
      return { ...out, state: "skipped", reason: `secrets/ is not writable (${err.code || err.message})` };
    }
  }

  // ─── the seal, ONE transaction ────────────────────────────────────────────
  const sealed = new Set();
  // What each sealed row holds, for the APPROVED COPY written after the commit (round D, item F2):
  // the converter is a write like any other, so the content it blesses is what --show diffs against.
  const sealedRows = [];
  let refused = 0;
  try {
    await inTransaction((run) => {
      for (const entry of snapshotRows) {
        const row = run({
          sql: "SELECT bot_id, display_name, definition, enabled, project_id, def_generation, def_mac FROM pi_bot_defs WHERE bot_id = ?",
          args: [entry.bot_id],
        }).rows?.[0] || null;
        if (!row) continue; // deleted since the snapshot
        try {
          // L2: a row counts as already sealed (a re-run) only when it is in the snapshot AND its MAC
          // verifies; a planted `def_generation` alone leaves it unsealed and refused.
          if (row.def_generation != null) {
            if (botDefRowMacVerifies(row)) sealed.add(entry.bot_id);
            else refused += 1;
            continue;
          }
          if (rowDigest(row) !== entry.sha256) { refused += 1; continue; } // edited after the snapshot
          // The stored text is rewritten to its CANONICAL form in the same statement that seals it:
          // the value is unchanged (so the digest and the MAC still describe it), and from now on
          // verification can require the column to be exactly the canonical serialization (M2:
          // duplicate keys and JSON.parse-vs-json_extract disagreement are refused).
          const definition = canonicalDefinitionText(row.definition === undefined ? null : row.definition);
          const mac = macBotDef({ ...row, definition, def_generation: 1 });
          // The CAS is on the ABSENCE of a generation: a row this converter already sealed (a re-run
          // after a crash before the marker) is left exactly as it is.
          run({
            sql: "UPDATE pi_bot_defs SET def_generation = 1, def_mac = ?, definition = ? WHERE bot_id = ? AND def_generation IS NULL",
            args: [mac, definition, entry.bot_id],
          });
          sealed.add(entry.bot_id);
          sealedRows.push({
            bot_id: entry.bot_id, definition, enabled: row.enabled, project_id: row.project_id ?? null, generation: 1,
          });
        } catch (err) {
          // A bad row (too complex to canonicalise) is skipped: unsealed, refused, named once below.
          if (err?.code === "DEFINITION_TOO_COMPLEX" || err?.name === "DefinitionTooComplexError") {
            badRows.push(entry.bot_id);
            continue;
          }
          throw err;
        }
      }
    });
  } catch (err) {
    forceRefuseBotDefUnsealed();
    console.error(
      `[bot-def] the conversion failed (${err?.message || err}); unsealed bot definitions are REFUSED for the `
      + "rest of this process and the era stays unconverted, so the next boot resumes from the snapshot.",
    );
    recordEra("failed", "conversion-failed");
    return { ...out, state: "failed", reason: String(err?.message || err) };
  }

  // ─── the generations file, then the era ───────────────────────────────────
  try {
    seedBotDefGenerations([...sealed]);
  } catch (err) {
    forceRefuseBotDefUnsealed();
    console.error(
      `[bot-def] the generation counter could not be written (${err?.message || err}); unsealed definitions `
      + "are REFUSED for the rest of this process and the era was not marked, so the next boot retries.",
    );
    recordEra("failed", "generations-not-written");
    return { ...out, state: "failed", reason: String(err?.message || err) };
  }
  const mark = await markConverted(BOT_DEF_FAMILY, {
    count: sealed.size,
    rollbackFile: rollbackName,
    at: (now || new Date()).toISOString(),
    writeSetting: (k, v, o) => writeSetting(db, k, v, o),
  }).catch((err) => {
    forceRefuseBotDefUnsealed();
    console.error(`[bot-def] the era could not be marked (${err?.message || err}); the next boot re-runs the conversion.`);
    return null;
  });
  if (!mark) {
    recordEra("failed", "era-not-marked");
    return { ...out, state: "failed", count: sealed.size };
  }
  // The authoritative record, written last: from here every verifier (the bridge too) refuses an
  // unsealed row for good, and the next boot sees "already converted".
  recordEra("converted");

  if (badRows.length) {
    console.warn(
      `[bot-def] ${badRows.length} bot definition(s) are too complex to seal (${[...new Set(badRows)].join(", ")}): `
      + "left unsealed and refused (definition-too-complex); the instance is converted regardless.",
    );
  }
  if (sealed.size) {
    authoritySummary(sealedRows);
    // F2: the approved copy of every row this conversion sealed. A copy that cannot be written logs
    // its own ONE line and never fails the boot (servers/shared/bot-def-approved.js).
    for (const content of sealedRows) writeApprovedBotDef(content);
    console.log(`[bot-def] sealed ${sealed.size} bot definition(s), snapshot secrets/${rollbackName}`);
  }
  if (refused) {
    legacyAlarm(BOT_DEF_FAMILY, "edited-after-snapshot", { audit: auditFn });
    out.alarms = refused;
    console.warn(
      `[bot-def] ${refused} definition(s) changed between the snapshot and the conversion: they were NOT `
      + "sealed, so they are refused until they are written again from Bot Builder.",
    );
  }
  return { ...out, state: "converted", count: sealed.size, refused, rollbackFile: rollbackName, changed: mark.changed, unexpectedTriggers };
}

/** `readSetting`, imported lazily so the converter stays cheap on a CLI path that never needs it. */
async function readSettingFor(db, key) {
  const { readSetting } = await import("../dashboard/settings/registry.js");
  return readSetting(db, key);
}