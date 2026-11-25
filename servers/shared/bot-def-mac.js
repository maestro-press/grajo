/**
 * Tamper-evident bot DEFINITIONS (`pi_bot_defs`), under the keyed-hash module's key.
 *
 * WHY. A contained bot has `crow.db` bound read-write, and crow.db holds every bot definition —
 * its own included. A definition is AUTHORITY: `tools.crow_mcp` decides which Crow tools the bot
 * may call, `permission_policy` decides whether it may write outside its world, `write_paths`
 * widens its reach, `project_id` picks the project it acts in, and `tools.remote_mcp` points it at
 * another server. So a bot that edits its own row raises its own policy, and the raise takes
 * effect at its NEXT spawn. Nothing about the row can tell an owner's edit from the bot's.
 *
 * THE MECHANISM. Every row carries a MAC over the WHOLE definition under
 * `<CROW_HOME>/secrets/token-hmac.key` — the one key a bot cannot read (it is 0600 in a 0700
 * directory, and `tests/bot-seed-import-guard.test.js` keeps `servers/shared/token-mac.js` off
 * every bot-reachable load path). The MAC is
 * `macToken("bot:def", canonicalBotDef(row))`, i.e. an `h1.`-form keyed hash from
 * `servers/shared/token-mac.js`, so a bot can neither compute one nor copy one from another row
 * (the canonical form carries the row's own `bot_id`, and the family is in the MAC's domain).
 *
 * WHAT IS COVERED — EVERYTHING. The MAC input is the whole definition object plus the four row
 * columns that decide authority, not a field list: a field this file has never heard of is still
 * inside the MAC, so a new definition key needs no change here to be protected. (`bot_id`,
 * `enabled` as 0/1, `project_id` as null-or-number, and `generation` are inside it too, so a row
 * cannot be moved to another bot, switched on, re-filed, or rolled back without a key.)
 *
 * REPLAY. A keyed MAC alone does not stop a replay: a bot can copy its own row's earlier
 * `(definition, def_mac)` pair back after the owner tightens it. So each bot has a monotonic
 * GENERATION, counted OUTSIDE crow.db — `<CROW_HOME>/secrets/bot-def-generations.json`, 0600 in
 * the 0700 `secrets/` directory beside the key, which is the directory the key file itself lives
 * in (taken from `tokenMacKeyPath()`'s own dirname — never `dirname(dirname())`, because the key
 * path may be a `/proc/self/fd/N/…` anchored seam). The generation is inside the MAC, so an old
 * pair replayed at its old generation is refused as "generation-behind".
 *
 * TWO NUMBERS PER BOT, AND THE HIGH-WATER NEVER GOES BACK (I1). The entry holds the ACCEPTED
 * generation (`generation` — the one the last sealed row carries) and the PLANNING HIGH-WATER
 * (`planned` — the highest generation any writer has ever planned), plus `pending`, the one
 * generation whose write may still be in flight. They are deliberately separate: a bot can install a
 * BEFORE UPDATE trigger on `pi_bot_defs` that stashes `NEW.definition/new.def_mac/new.def_generation`
 * and RAISE(IGNORE)s, which makes the owner's write land 0 rows; if a failed write wound the counter
 * back, the OWNER's next write would plan the SAME generation again, sign it, and the stashed tuple
 * would then be a valid, replayable pair signed at the accepted generation (undone disable). So a
 * planned generation is written and fsynced BEFORE the row statement and is never lowered, by a
 * failed statement, a 0-row compare-and-swap, or an exception.
 *
 * THE WRITE ORDER (the crash-safe scheme; `servers/shared/bot-def-store.js` is its only user):
 *   1. under the file's cross-process lock, plan `generation = high-water + 1`: write
 *      `{generation: accepted, planned: generation, pending: generation}` (atomic: 0600 temp +
 *      fsync + rename + fsync dir), BEFORE the row statement;
 *   2. ONE INSERT/UPDATE setting definition + def_mac + def_generation (and the other columns);
 *   3. on success, settle the entry (`generation: generation, pending: null`, the high-water keeps
 *      its value); on a failed write (an exception, or a compare-and-swap that matched 0 rows) clear
 *      only `pending` — `planned` keeps the abandoned generation, so the next write plans a HIGHER
 *      one and the abandoned, already-signed tuple can never verify.
 * A crash between 1 and 2 leaves the row at the accepted generation with the file saying
 * `{generation: accepted, planned: next, pending: next}`; verification accepts the accepted
 * generation (a "pending" write is in flight) and exactly `pending`. A crash between 2 and 3 leaves
 * the row AT `next` and `pending: next`, which verification accepts as "pending". So neither crash
 * point can strand a bot, and the replay window is one write wide, only while a crashed writer's
 * `pending` mark is still there. `row generation === accepted` is the normal state; a row AHEAD of
 * the file is refused ("generation-ahead"), and every generation at or below an abandoned plan is
 * refused as "generation-behind" — which the never-lowered high-water makes true by construction.
 * A file written BEFORE the high-water existed (an entry carrying `generation` and `pending` only,
 * where `generation` was the planned write) is read as accepted = g-1 with the high-water at g
 * (item J5), so the row a crashed write left behind is accepted rather than refused.
 *
 * ERA. The family converts in the pre-listen boot (`servers/gateway/boot/bot-def-mac.js`), which
 * snapshots every row, writes `def_generation = 1` + its MAC, marks the token-mac family, and records
 * the era in the HOST-SIDE record `<CROW_HOME>/secrets/bot-def-era.json` (`{state: "converted" |
 * "failed" | "skipped" | "pre-era"}`, written on every boot outcome, fresh installs included). That
 * record is the ONLY thing that decides the era, for every verifier (the gateway's, the bridge's
 * separate process — which reads the file directly): an UNSEALED row is accepted only when the record
 * exists and says "pre-era" (written by nothing in production; fixtures and a deliberately
 * un-upgraded box). A MISSING, unreadable, "failed" or "skipped" record REFUSES an unsealed row, a MAC
 * that does not verify, or a generation below the recorded one; sealed rows verify normally in every
 * state. The DB mirror (`token_hmac_era:bot:def`), a `def_mac` scan and the token-mac marker open
 * nothing: a contained bot can write crow.db, so none of them may. Deploy order is gateway first (it
 * writes the record), then the bridge. A row that carries no `def_mac` COLUMN at all is refused too
 * (`no-mac-column`). The generation FILE missing after the era is a refusal ("generations-missing",
 * with one loud line): accepting then would silently drop replay protection. A definition nested or
 * sized past `canonicalJson`'s bounds is refused as "definition-too-complex", never a throw.
 *
 * A KEY RESET NEVER BLESSES AN UNVERIFIED ROW. `verifyAllBotDefs` (the operator's
 * `scripts/token-hmac.mjs --reset`, step 0) verifies each row under the key it is retiring and returns
 * the row TUPLES that verified; `resealAllBotDefs` writes exactly those tuples under the new key — it
 * never re-reads a row to decide what to bless, so a definition rewritten between the two steps is
 * skipped (its pinned UPDATE lands nowhere) instead of being stamped with content no key holder
 * vouched for. A row that did not verify is left exactly as it is (so it stays refused) and is
 * reported by `bot_id` to the operator, who re-approves that bot with
 * `scripts/cli/bot-def-reapprove.mjs`. If the old key is gone there is nothing to verify with, so
 * NOTHING is re-sealed and every bot is listed instead. A reset is a key change, never an amnesty.
 *
 * WHAT THIS MAC DOES NOT COVER. `project_spaces.workspace_dir` / `tasks_db_uri` /
 * `storage_prefix` decide a bot's world root and are BOT-WRITABLE too: they are outside this MAC
 * (it covers the row's own definition, not the project it points at) and are covered by the
 * crow.db brokering work instead. A verified `project_id` therefore names a project whose
 * placement fields are still only as trustworthy as crow.db.
 *
 * NOR DOES IT COVER A CAPTURED VERSION (round C, item E8, acknowledged). `item_versions` lives in
 * crow.db too, and a bot can INSERT a version row whose `snapshot_json` carries a CAPTURED
 * `(def_mac, def_generation)` pair that is genuinely the owner's — a copy of an OLDER version of its
 * own definition, content the owner once signed. That pair verifies (the history restore checks it
 * at its own generation, `replay: false`, which is exactly what an old version needs), so a restore
 * of it succeeds — rolling the bot back to older, genuinely-approved content, which is what a
 * History restore MEANS. Two things bound the exposure: the restore is the OWNER's action (never a
 * bot's), and it can only bring back content a key holder signed, never content a bot invented. What
 * it cannot do is tell the owner that the version row was planted there; the refusal a fabricated
 * version gets (content no key holder signed) is the rule this MAC enforces.
 *
 * HOST-ONLY. This module holds the key (through token-mac), so no bot-reachable file may import
 * it; `tests/bot-def-single-writer.test.js` and the seed guard keep the writers in one place.
 * Bot-reachable code reaches the WRITE through `servers/shared/bot-def-seal.js`, an
 * import-free seam this module's store installs into (a process with no store installed refuses
 * to write at all), and reaches the READ raw — reported, not verified (see the store module).
 */
import {
  closeSync, constants as fsConstants, fstatSync, fsyncSync, lstatSync, linkSync, openSync, readFileSync, readSync,
  renameSync, unlinkSync, writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  TOKEN_MAC_ALARM_WINDOW_MS, TokenMacKeyError, ensureKey, eraSettingKey, familyConverted, keyState,
  macToken, readState, tokenMacKeyPath, verifyMacValue,
} from "./token-mac.js";
// The secrets-directory helper comes from its own module (see ./secrets-dir.js): importing it from
// ./peer-credentials.js would put the peer credential store into the import graph of the separate bot
// host processes, which must never load it (tests/no-peer-key-in-bot-process.test.js).
import { ensureSecretsDir } from "./secrets-dir.js";
import { writeAlertFile } from "./alert-spool.js";

/** The family domain of a bot definition's MAC (§1d of the keyed-hashes design). */
export const BOT_DEF_FAMILY = "bot:def";

/** Reasons `verifyBotDef` can refuse with — fixed strings, never a value from the row. */
export const BOT_DEF_REFUSALS = Object.freeze([
  "pre-era", "mac", "pending",
  "no-mac", "no-mac-column", "mac-mismatch", "mac-invalid", "foreign-mac",
  "key-lost", "key-invalid", "key-missing",
  "generation-invalid", "generation-behind", "generation-ahead", "generations-missing",
  "row-types", "definition-text", "definition-too-complex",
]);

/** The generations file's own version + its lock's staleness bound. */
const GENERATIONS_VERSION = 1;
const LOCK_STALE_MS = 30 * 1000;
const LOCK_ATTEMPTS = 400;
const LOCK_SLEEP_MS = 5;

/** A coded failure of the generations FILE (never of a definition). */
export class BotDefStateError extends Error {
  constructor(code, message, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = "BotDefStateError";
    this.code = code;
  }
}

// ─── the canonical form ────────────────────────────────────────────────────

/**
 * Bounds on a definition's canonical form. A definition nested thousands deep used to overflow the
 * recursion (a RangeError no caller handled): it could stop the boot conversion from ever finishing
 * and make the verify path throw. Past any bound the value is refused with the fixed reason
 * "definition-too-complex" (`DefinitionTooComplexError`), which every caller maps to a refusal.
 */
export const CANONICAL_MAX_DEPTH = 64;
export const CANONICAL_MAX_NODES = 100000;
export const CANONICAL_MAX_TEXT = 4 * 1024 * 1024;

/** `canonicalJson` refused a value that is too deep, too big or not finite-sized. */
export class DefinitionTooComplexError extends Error {
  constructor() {
    super("definition-too-complex");
    this.name = "DefinitionTooComplexError";
    this.code = "DEFINITION_TOO_COMPLEX";
  }
}

/**
 * `value` as canonical JSON: object keys sorted (recursively), no whitespace, arrays in order,
 * and every primitive exactly as `JSON.stringify` writes it. `undefined` in an object is
 * dropped and in an array becomes `null`, which is what `JSON.stringify` does too — so the
 * canonical form is a function of the VALUE, never of the text it arrived in.
 *
 * ITERATIVE (an explicit stack, never the call stack) and bounded by `CANONICAL_MAX_DEPTH`,
 * `CANONICAL_MAX_NODES` and `CANONICAL_MAX_TEXT`; beyond them it throws `DefinitionTooComplexError`.
 */
export function canonicalJson(value) {
  const out = [];
  let size = 0;
  let nodes = 0;
  const emit = (text) => {
    size += text.length;
    if (size > CANONICAL_MAX_TEXT) throw new DefinitionTooComplexError();
    out.push(text);
  };
  // A frame is a pending piece: a string to emit, or a value to expand at a depth.
  const stack = [{ v: value, d: 0 }];
  while (stack.length) {
    const f = stack.pop();
    if (typeof f === "string") { emit(f); continue; }
    const v = f.v;
    if (++nodes > CANONICAL_MAX_NODES) throw new DefinitionTooComplexError();
    if (v === null) { emit("null"); continue; }
    if (typeof v === "object") {
      if (f.d >= CANONICAL_MAX_DEPTH) throw new DefinitionTooComplexError();
      if (Array.isArray(v)) {
        if (v.length > CANONICAL_MAX_NODES) throw new DefinitionTooComplexError();
        stack.push("]");
        for (let i = v.length - 1; i >= 0; i--) {
          stack.push({ v: v[i] === undefined ? null : v[i], d: f.d + 1 });
          if (i > 0) stack.push(",");
        }
        emit("[");
      } else {
        const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
        if (keys.length > CANONICAL_MAX_NODES) throw new DefinitionTooComplexError();
        stack.push("}");
        for (let i = keys.length - 1; i >= 0; i--) {
          stack.push({ v: v[keys[i]], d: f.d + 1 });
          stack.push(`${JSON.stringify(keys[i])}:`);
          if (i > 0) stack.push(",");
        }
        emit("{");
      }
      continue;
    }
    const prim = JSON.stringify(v);
    emit(prim === undefined ? "null" : prim);
  }
  return out.join("");
}

/** `JSON.parse` that refuses (rather than overflows on) a document nested past the canonical bound. */
function parseBounded(text) {
  if (typeof text !== "string" || text.length > CANONICAL_MAX_TEXT) throw new DefinitionTooComplexError();
  let depth = 0;
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++; else if (c === 34) inStr = false;
    } else if (c === 34) inStr = true;
    else if (c === 91 || c === 123) { if (++depth > CANONICAL_MAX_DEPTH) throw new DefinitionTooComplexError(); }
    else if (c === 93 || c === 125) depth--;
  }
  return JSON.parse(text);
}

/**
 * The MAC input of one `pi_bot_defs` row: `{bot_id, definition, enabled, generation, project_id}`
 * in canonical JSON. THIS IS THE WHOLE COVERAGE — every key of `definition`, known or not.
 *
 * `definition` is the PARSED definition (the stored text is JSON); a definition that does not
 * parse is canonicalised with `definition` = the raw string and a sibling `definition_kind: "raw"` inside
 * the MAC'd object (JSON rows carry no such field, so their form is unchanged), so a corrupt row still has a stable, verifiable form
 * instead of silently verifying as `{}`. `enabled`, `project_id` and the generation go in EXACTLY
 * as they are stored — NO COERCION (`1` and `"1"` are different MAC inputs, which is only safe
 * because verification also refuses a row whose column types are not the ones the writer stores;
 * see `verifyBotDefSync`). A missing `project_id` is null.
 *
 * The generation is read from `def_generation`, falling back to `generation` so a caller holding
 * a row from before the column existed (or a fresh snapshot being converted) can pass either.
 */
export function canonicalBotDef(row) {
  const raw = row?.definition;
  let definition;
  let rawKind = false;
  if (typeof raw === "string") {
    try {
      definition = parseBounded(raw);
    } catch (err) {
      if (err instanceof DefinitionTooComplexError) throw err;
      // Text that is not JSON is wrapped (L3), so it can never collide with the canonical form of a
      // definition that IS a JSON string holding the same characters.
      definition = raw;
      rawKind = true;
    }
  } else {
    definition = raw === undefined ? null : raw;
  }
  const generation = row?.def_generation ?? row?.generation ?? null;
  return canonicalJson({
    bot_id: String(row?.bot_id ?? ""),
    definition,
    ...(rawKind ? { definition_kind: "raw" } : {}),
    enabled: row?.enabled === undefined ? null : row.enabled,
    generation: generation === null ? null : generation,
    project_id: row?.project_id ?? null,
  });
}

/**
 * The text a `pi_bot_defs.definition` column HOLDS: the canonical serialization of the definition's
 * value (`canonicalJson` of the parsed document), or — for a definition that is not JSON at all —
 * the raw string, unchanged, so a corrupt row keeps a stable value the MAC can still cover.
 *
 * Every writer stores this (`writeBotDef`, the boot converter, the history restore through
 * `signBotDefSealed`), and verification refuses a row whose stored text is anything else. That is
 * how duplicate JSON keys and any `JSON.parse`-vs-`json_extract` disagreement are excluded: only
 * one document can be read out of the column, and it is the one the MAC covers.
 *
 * @param {string|object|null} value the stored TEXT or the object
 * @returns {string|null} the text to store
 */
export function canonicalDefinitionText(value) {
  if (value === undefined || value === null) return null;
  let parsed;
  if (typeof value === "string") {
    try { parsed = parseBounded(value); } catch (err) {
      if (err instanceof DefinitionTooComplexError) throw err;
      return value;
    }
  } else {
    parsed = value;
  }
  return canonicalJson(parsed);
}

/**
 * The stored verifier for one row: `macToken("bot:def", canonicalBotDef(row))`.
 *
 * Throws `TokenMacKeyError` when this process has no usable key — a writer must never store a
 * definition the boot cannot verify. `opts` are token-mac's seams (`path`, `statePath`,
 * `crowHome`) and, when `allowCreate` is true, the explicit era-evidence flags it demands.
 */
export function macBotDef(row, opts = {}) {
  return macToken(BOT_DEF_FAMILY, canonicalBotDef(row), opts);
}

// ─── the generations file ──────────────────────────────────────────────────

/**
 * `<CROW_HOME>/secrets/bot-def-generations.json` — beside the key, in the directory the KEY FILE
 * itself lives in (`tokenMacKeyPath()`'s dirname; see the header on why not `dirname(dirname())`).
 */
export function botDefGenerationsPath(opts = {}) {
  return opts.generationsPath || join(dirname(tokenMacKeyPath(opts)), "bot-def-generations.json");
}

function emptyGenerations(path, { exists = false, corrupt = false } = {}) {
  return { path, exists, corrupt, v: GENERATIONS_VERSION, bots: {} };
}

/**
 * Read the generations file.
 *
 * ENOENT is "no file" (`exists: false`), any OTHER read error is THROWN (unreadable is not
 * "empty": treating it as empty would drop replay protection), and structural damage is
 * `corrupt: true`, which every reader refuses.
 */
export function readBotDefGenerations(opts = {}) {
  const path = botDefGenerationsPath(opts);
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return emptyGenerations(path, { exists: false });
    throw new BotDefStateError(
      "BOT_DEF_GENERATIONS_UNREADABLE",
      `bot definition generations ${path} could not be read: ${err.message}`,
      err,
    );
  }
  let j;
  try { j = JSON.parse(raw); } catch { return emptyGenerations(path, { exists: true, corrupt: true }); }
  if (!j || typeof j !== "object" || Array.isArray(j)) return emptyGenerations(path, { exists: true, corrupt: true });
  const bots = j.bots === undefined ? {} : j.bots;
  if (!bots || typeof bots !== "object" || Array.isArray(bots)) {
    return emptyGenerations(path, { exists: true, corrupt: true });
  }
  const out = {};
  for (const [botId, entry] of Object.entries(bots)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const generation = Number(entry.generation);
    if (!Number.isInteger(generation) || generation < 0) continue;
    const pending = Number(entry.pending);
    const planned = Number(entry.planned);
    const hasPending = Number.isInteger(pending) && pending > 0;
    // A file written before the high-water existed (item J5) stored `generation` and `pending`
    // only, and its `generation` was the PLANNED write, not the accepted one: `{generation: g,
    // pending: g}` means "a write at g is in flight" and says nothing about the row, which a crash
    // before the write landed left at g-1. Reading it as accepted=g would refuse that row as
    // "generation-behind" and no bot would spawn, so that entry is read as accepted = g-1 and
    // high-water = g (the in-flight generation stays acceptable as `pending`). Any other shape
    // without `planned` — a settled `{generation: g}` with no pending, or a stale `pending` below
    // the accepted generation — reads as it always did.
    const oldFormat = !Object.prototype.hasOwnProperty.call(entry, "planned")
      && hasPending && pending === generation && generation > 0;
    out[String(botId)] = {
      generation: oldFormat ? generation - 1 : generation,
      // The high-water takes every number that was ever PLANNED (the old shape's `generation` and its
      // `pending` both were), so nothing this file has already promised is handed out twice.
      planned: Math.max(
        generation,
        Number.isInteger(planned) && planned > 0 ? planned : 0,
        hasPending ? pending : 0,
      ),
      // A pending mark at or below the accepted generation is spent, never a second acceptable value.
      pending: hasPending && pending > (oldFormat ? generation - 1 : generation) ? pending : null,
    };
  }
  return { path, exists: true, corrupt: false, v: GENERATIONS_VERSION, bots: out };
}

/** Write the generations file atomically (0600 temp + fsync + rename + fsync the directory). */
function writeBotDefGenerations(path, bots, opts = {}) {
  ensureSecretsDir(dirname(path));
  const body = { v: GENERATIONS_VERSION, bots, updated_at: new Date().toISOString() };
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  try {
    const dfd = openSync(dirname(path), "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  return path;
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Serialize read-modify-write of one generations file inside this process. */
const fileLocks = new Map();
function withProcessLock(path, fn) {
  const prev = fileLocks.get(path) || Promise.resolve();
  const next = prev.then(fn, fn);
  fileLocks.set(path, next.then(() => {}, () => {}));
  return next;
}

/**
 * Take over a lock a crashed writer abandoned, without letting two takers both win.
 *
 * The stale lock is RENAMED aside first and the renamed inode compared with the one stat'ed as
 * stale: two takers may both rename, but only the one whose renamed inode IS the stale lock
 * proceeds, and a displaced fresh lock is put back with `link` (which never clobbers a path).
 * Same rule as `servers/shared/token-mac.js`'s state lock; kept small here because this file's
 * critical section is one read and one write.
 *
 * @returns {boolean} true when a stale lock was taken over and the caller may retry at once
 */
function takeOverStaleLock(lockPath) {
  let stale;
  try { stale = lstatSync(lockPath); } catch { return false; }
  if (!stale.isFile()) return false;
  if (Date.now() - stale.mtimeMs <= LOCK_STALE_MS) return false;
  const aside = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString("hex")}`;
  try { renameSync(lockPath, aside); } catch { return false; }
  let moved;
  try { moved = lstatSync(aside); } catch { return false; }
  if (moved.ino !== stale.ino || moved.dev !== stale.dev) {
    try { linkSync(aside, lockPath); } catch { /* the path is occupied again: superseded */ }
    try { unlinkSync(aside); } catch { /* already gone */ }
    return false;
  }
  try { unlinkSync(aside); } catch { /* another taker was faster: the O_EXCL retry decides */ }
  return true;
}

/**
 * Cross-process read-modify-write lock for the generations file: `<file>.lock`, created `O_EXCL`
 * 0600. The gateway and host-side CLI scripts can both write, so an in-process chain is not
 * enough. The critical section MUST stay synchronous (no await).
 */
function withFileLock(path, fn) {
  const lockPath = `${path}.lock`;
  ensureSecretsDir(dirname(path));
  let fd = null;
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
      break;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      if (takeOverStaleLock(lockPath)) continue;
      sleepSync(LOCK_SLEEP_MS);
    }
  }
  if (fd === null) {
    throw new BotDefStateError(
      "BOT_DEF_GENERATIONS_LOCKED",
      `bot definition generations ${path} is locked by another process (${lockPath})`,
    );
  }
  try {
    try { writeSync(fd, JSON.stringify({ pid: process.pid, ts: new Date().toISOString() })); } catch { /* the file IS the lock */ }
    return fn();
  } finally {
    try { closeSync(fd); } catch { /* already closed */ }
    try { unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

/**
 * Plan the generation for a write that is about to happen (step 1 of the header's order):
 * `high-water + 1`, written and fsynced BEFORE the row statement, and never lowered again.
 *
 * SYNCHRONOUS on purpose: the history restore runs inside a `runTransaction` callback, which may
 * not await, and it must sign the row it is about to write.
 *
 * @returns {{ generation: number, previous: number, planned: number }} `previous` is the ACCEPTED
 *   generation the entry held (kept for the `abandon` call's signature; the high-water is what the
 *   next plan reads).
 */
export function planBotDefGeneration(botId, opts = {}) {
  const id = String(botId ?? "");
  if (!id) throw new Error("a bot definition needs a bot_id");
  const path = botDefGenerationsPath(opts);
  return withFileLock(path, () => {
    const st = readBotDefGenerations(opts);
    if (st.corrupt) {
      throw new BotDefStateError(
        "BOT_DEF_GENERATIONS_CORRUPT",
        `bot definition generations ${path} is corrupt (not an object carrying an object "bots"); writer refused, file left untouched`,
      );
    }
    const previous = st.bots[id]?.generation ?? 0;
    const highWater = st.bots[id]?.planned ?? previous;
    const generation = highWater + 1;
    writeBotDefGenerations(path, { ...st.bots, [id]: { generation: previous, planned: generation, pending: generation } }, opts);
    return { generation, previous, planned: generation };
  });
}

/**
 * Step 3 on success: the entry is settled — the accepted generation moves to `generation` and
 * `pending` clears. The PLANNING HIGH-WATER never decreases (it is the next plan's base).
 *
 * Only the write that still owns `pending` settles: a concurrent writer that has already planned a
 * HIGHER generation owns that mark, and settling it here would accept a generation this write does
 * not hold.
 */
export function settleBotDefGeneration(botId, generation, opts = {}) {
  const id = String(botId ?? "");
  const path = botDefGenerationsPath(opts);
  return withFileLock(path, () => {
    const st = readBotDefGenerations(opts);
    if (st.corrupt || !st.exists) return false;
    const entry = st.bots[id];
    if (!entry) return false;
    if (entry.pending !== null && entry.pending !== generation) return false;
    const accepted = Math.max(entry.generation, generation);
    const planned = Math.max(entry.planned, generation, accepted);
    if (entry.generation === accepted && entry.planned === planned && entry.pending === null) return true;
    writeBotDefGenerations(path, { ...st.bots, [id]: { generation: accepted, planned, pending: null } }, opts);
    return true;
  });
}

/**
 * The row's write did NOT happen (an exception, or a compare-and-swap that matched no row):
 * clear the `pending` mark ONLY. The accepted generation stays where it was and the PLANNING
 * HIGH-WATER keeps the abandoned generation, so the next write plans a higher one and the tuple
 * this write signed (which a trigger on the table may have stashed) can never verify — that is the
 * whole point of the high-water (I1). Only when the entry still carries this write's `pending`
 * mark: a concurrent writer that already planned past it wins.
 *
 * `previous` is accepted for the callers' sake and never lowers anything.
 */
export function abandonBotDefGeneration(botId, generation, previous, opts = {}) {
  const id = String(botId ?? "");
  const path = botDefGenerationsPath(opts);
  return withFileLock(path, () => {
    const st = readBotDefGenerations(opts);
    if (st.corrupt || !st.exists) return false;
    const entry = st.bots[id];
    if (!entry) return false;
    if (entry.pending !== null && entry.pending !== generation) return false;
    const planned = Math.max(entry.planned, generation, entry.generation);
    if (entry.planned === planned && entry.pending === null) return true;
    writeBotDefGenerations(path, { ...st.bots, [id]: { generation: entry.generation, planned, pending: null } }, opts);
    return true;
  });
}

// ─── does a row's own MAC verify, and stale pending marks ──────────────────

/**
 * Does this row's `def_mac` verify under the key, for the content and generation it carries? Never
 * throws (a row too complex to canonicalise, a lost key: false). Used where the converter and the
 * pending reconcile must know a row is genuinely sealed, never trusting a planted generation alone.
 */
export function botDefRowMacVerifies(row, opts = {}) {
  try {
    if (typeof row?.def_mac !== "string" || row.def_mac === "") return false;
    if (typeof row.enabled !== "number" || (row.enabled !== 0 && row.enabled !== 1)) return false;
    if (!Number.isSafeInteger(row.def_generation)) return false;
    return verifyMacValue(BOT_DEF_FAMILY, canonicalBotDef(row), row.def_mac, keyLocation(opts)).ok === true;
  } catch {
    return false;
  }
}

/**
 * Settle or abandon every PENDING mark (M1): a crashed writer leaves `pending` behind, and until it
 * is resolved the tuple that writer signed at that generation stays acceptable (a trigger can have
 * stashed it). For each bot whose entry carries a pending generation above the accepted one:
 * if the row carries exactly that generation and its MAC verifies under it, the write landed, so
 * SETTLE; otherwise (only when `abandon`) ABANDON — `pending` clears, the planning high-water stays,
 * so the abandoned tuple can never verify. `abandon` is for the pre-listen boot, where no writer is in
 * flight; a live reader (the bridge) passes `abandon: false` and only settles.
 *
 * @param {Map<string, object>|object[]} rows `pi_bot_defs` rows (with def_mac/def_generation)
 * @returns {{settled: string[], abandoned: string[]}}
 */
export function reconcileBotDefPending(rows, { abandon = false, ...opts } = {}) {
  const byId = new Map();
  if (rows instanceof Map) for (const [k, v] of rows) byId.set(String(k), v);
  else for (const r of rows || []) byId.set(String(r?.bot_id ?? ""), r);
  const out = { settled: [], abandoned: [] };
  let st;
  try { st = readBotDefGenerations(opts); } catch { return out; }
  if (st.corrupt || !st.exists) return out;
  for (const [id, entry] of Object.entries(st.bots)) {
    if (!(entry.pending !== null && entry.pending > entry.generation)) continue;
    const row = byId.get(id);
    if (row && row.def_generation === entry.pending && botDefRowMacVerifies(row, opts)) {
      if (settleBotDefGeneration(id, entry.pending, opts)) out.settled.push(id);
    } else if (abandon) {
      if (abandonBotDefGeneration(id, entry.pending, entry.generation, opts)) out.abandoned.push(id);
    }
  }
  return out;
}

// ─── the era state file ────────────────────────────────────────────────────

/** The host-side era record's name inside the secrets dir (beside the key). */
export const BOT_DEF_ERA_FILENAME = "bot-def-era.json";
/** Every state the record can hold. Only "pre-era" admits an unsealed row; nothing in production writes it. */
export const BOT_DEF_ERA_STATES = Object.freeze(["converted", "failed", "skipped", "pre-era"]);
const ERA_MAX_BYTES = 4096;

/** `<secrets dir>/bot-def-era.json` — in the directory the KEY FILE lives in. */
export function botDefEraStatePath(opts = {}) {
  return opts.eraStatePath || join(dirname(tokenMacKeyPath(opts)), BOT_DEF_ERA_FILENAME);
}

/**
 * Read the era record HARDENED (host state a bot must not forge): opened `O_NOFOLLOW`, judged from the
 * very fd — a regular file, owned by this user, no group/other bits, small. Result
 * `{state: "absent"|"unreadable"|<one of BOT_DEF_ERA_STATES>, doc?}`. Only an unambiguous "pre-era"
 * record admits an unsealed row; absent, unreadable, corrupt and every other state refuse it.
 */
export function readBotDefEraState(opts = {}) {
  let path;
  try { path = botDefEraStatePath(opts); } catch { return { state: "unreadable" }; }
  let fd;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (err) {
    return { state: err.code === "ENOENT" ? "absent" : "unreadable" };
  }
  try {
    const st = fstatSync(fd);
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    if (!st.isFile() || st.size > ERA_MAX_BYTES || (st.mode & 0o077) !== 0 || (uid !== null && st.uid !== uid)) {
      return { state: "unreadable" };
    }
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n <= 0) break;
      got += n;
    }
    const doc = JSON.parse(buf.subarray(0, got).toString("utf8"));
    if (!doc || typeof doc !== "object" || Array.isArray(doc) || !BOT_DEF_ERA_STATES.includes(doc.state)) {
      return { state: "unreadable" };
    }
    return { state: doc.state, doc };
  } catch {
    return { state: "unreadable" };
  } finally {
    try { closeSync(fd); } catch { /* closed */ }
  }
}

/**
 * Record the era (atomic: 0600 temp + fsync + rename + fsync dir). "converted" is final: asked to
 * write any other state over it, this does nothing and returns false. Throws when the secrets
 * directory cannot be written (the caller logs one error).
 *
 * @returns {boolean} true when the file now holds `state`
 */
export function writeBotDefEraState(state, { reason, at } = {}, opts = {}) {
  if (!BOT_DEF_ERA_STATES.includes(state)) throw new TypeError(`unknown bot:def era state ${String(state)}`);
  const path = botDefEraStatePath(opts);
  if (state !== "converted" && readBotDefEraState(opts).state === "converted") return false;
  ensureSecretsDir(dirname(path));
  const body = { v: 1, state, at: at || new Date().toISOString() };
  if (reason) body.reason = String(reason).slice(0, 300);
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  try {
    const dfd = openSync(dirname(path), "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  return true;
}

/**
 * Has the `bot:def` era begun — must an UNSEALED row be refused? Decided by the host-side era record
 * ONLY (`<secrets>/bot-def-era.json`): ON unless the record exists and says "pre-era". A MISSING
 * record is ON, so a contained bot that stops the converter from ever writing it (or deletes a DB
 * copy) never opens the unsealed path; the gateway's converter writes the record on its first boot,
 * on every outcome, including a fresh install (deploy order: gateway first, then the bridge).
 * The DB mirror, a sealed-row scan and the token-mac marker open nothing here. Synchronous, for the
 * bridge's per-turn `loadBot` and the host callers; extra flags in `opts` are ignored.
 */
export function botDefEraConvertedSync(opts = {}) {
  return readBotDefEraState(opts).state !== "pre-era";
}

/**
 * Record every converter row's generation 1 in ONE file write (the boot converter's step 3), so
 * a crash before `markConverted` re-runs against a file that already agrees with the rows.
 */
export function seedBotDefGenerations(botIds, opts = {}) {
  const path = botDefGenerationsPath(opts);
  return withFileLock(path, () => {
    const st = readBotDefGenerations(opts);
    if (st.corrupt) {
      throw new BotDefStateError(
        "BOT_DEF_GENERATIONS_CORRUPT",
        `bot definition generations ${path} is corrupt; the converter refuses rather than overwrite it`,
      );
    }
    const bots = { ...st.bots };
    for (const botId of botIds) {
      const id = String(botId ?? "");
      if (!id) continue;
      // The converter's rows are generation 1, and it plans through the same high-water: an entry
      // that already carries a higher planned generation (a re-run after a crash, a write that raced
      // the conversion) keeps it, so nothing this file has already promised is handed out twice.
      const generation = Math.max(1, bots[id]?.generation ?? 0);
      const planned = Math.max(generation, bots[id]?.planned ?? 0);
      bots[id] = { generation, planned, pending: null };
    }
    writeBotDefGenerations(path, bots, opts);
    return path;
  });
}

// ─── the era ───────────────────────────────────────────────────────────────

/**
 * Has the `bot:def` family's era begun? The secrets-side marker OR the `token_hmac_era:bot:def`
 * DB mirror, failing closed — see `familyConverted`.
 */
export async function botDefFamilyConverted({ readSetting, ...location } = {}) {
  return familyConverted(BOT_DEF_FAMILY, { ...location, readSetting });
}

/** The era mirror's setting key (`token_hmac_era:bot:def`). */
export function botDefEraSettingKey() {
  return eraSettingKey(BOT_DEF_FAMILY);
}

// ─── the one loud line + the bell ─────────────────────────────────────────

/** key path (or "state") → the last time this process said the loud line. */
const loudSeen = new Map();

/** Test seam: forget this process's 24 h de-duplication of the loud line. */
export function forgetBotDefAlarms() {
  loudSeen.clear();
  refusalSeen.clear();
}

/**
 * Set by the boot converter when it could NOT convert: from then on this process refuses a row
 * with no MAC as well, even on a box whose era marker never appeared. Same rule as the
 * `oauth_tokens` boot's `forceRefuseLegacy` — a FAILED conversion must never leave the legacy
 * (unsealed) form accepted for the rest of the process's life.
 */
let forcedUnsealedRefusal = false;

/** Test seam: clear `forceRefuseBotDefUnsealed`. */
export function forgetBotDefForcedRefusal() {
  forcedUnsealedRefusal = false;
}

/** Refuse every unsealed (no-MAC) definition for the rest of this process (a failed conversion). */
export function forceRefuseBotDefUnsealed() {
  forcedUnsealedRefusal = true;
}

/**
 * ONE loud line per process per 24 h: every bot definition is refused because the KEY is lost or
 * unusable, naming the key file and the operator's reset command, plus one spooled bell
 * (`writeAlertFile`, whose default title is "Crow alert" — the P1 alarm path every other
 * token-mac-era alarm uses, with no new user-visible sentence).
 *
 * @returns {boolean} true when this call emitted the line
 */
export function botDefKeyAlarm(keyPath, state, { now = Date.now(), windowMs = TOKEN_MAC_ALARM_WINDOW_MS } = {}) {
  const slot = `${keyPath}\0${state}`;
  const at = loudSeen.get(slot);
  if (typeof at === "number" && now - at < windowMs) return false;
  loudSeen.set(slot, now);
  console.error(
    `[bot-def] the token-mac key is ${state === "lost" ? "lost" : "unusable"}: ${keyPath}. `
    + "Every bot definition is refused, so no bot spawns. Recreate it deliberately with "
    + "`node scripts/token-hmac.mjs --reset` (operator shell), then restart the gateway AND the "
    + "bot bridge process.",
  );
  try {
    writeAlertFile({ code: `bot-def-key-${state === "lost" ? "lost" : "invalid"}` });
  } catch { /* an alerting failure never becomes the refusal's failure */ }
  return true;
}

/** `<bot_id>` + reason → the last time this process logged a refused definition. */
const refusalSeen = new Map();

/**
 * ONE line per bot per reason per 24 h when a definition is refused (the spawn path calls this
 * before it refuses the turn): `[bot-def] <bot_id> settings could not be verified (<reason>)`.
 * Same de-duplication shape as `legacyAlarm` — an attacker cannot flush the log by retrying.
 *
 * @returns {boolean} true when this call emitted the line
 */
export function botDefRefusalAlarm(botId, reason, { now = Date.now(), windowMs = TOKEN_MAC_ALARM_WINDOW_MS } = {}) {
  const slot = `${String(botId ?? "")}\0${String(reason ?? "")}`;
  const at = refusalSeen.get(slot);
  if (typeof at === "number" && now - at < windowMs) return false;
  refusalSeen.set(slot, now);
  console.warn(
    `[bot-def] ${String(botId ?? "")} settings could not be verified (${String(reason ?? "")}); review it with `
    + `\`node scripts/cli/bot-def-reapprove.mjs ${String(botId ?? "")} --show\``,
  );
  return true;
}

// ─── verification ──────────────────────────────────────────────────────────

/**
 * The key a WRITE needs: the box's key, created only when the box is genuinely new (both
 * evidence flags explicit and false). `mirrorConverted` and `h1ValuesExist` are computed from the
 * same stores verification reads, so a converted box can never mint a second key here.
 */
export async function ensureBotDefWriteKey(db, opts = {}) {
  let mirrorConverted = false;
  try {
    mirrorConverted = await botDefFamilyConverted({ ...opts, readSetting: settingReader(db, opts) });
  } catch {
    mirrorConverted = true; // cannot tell → never "this box is new"
  }
  let h1ValuesExist = false;
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM pi_bot_defs WHERE def_mac IS NOT NULL LIMIT 1",
      args: [],
    });
    h1ValuesExist = rows.some((row) => Number(row?.present) === 1);
  } catch {
    h1ValuesExist = true; // cannot tell → never "this box is new"
  }
  return ensureKey({ ...opts, allowCreate: true, mirrorConverted, h1ValuesExist });
}

/**
 * The key a SIGNER needs (see `bot-def-store.js` `signBotDef`): the existing key, or — only in
 * token-mac's "first-boot" state, a box with no key file, no state file and no era at all — a new
 * one. A lost or invalid key is refused, never replaced.
 */
export function ensureSigningKeyFor(seams = {}) {
  try {
    return ensureKey({ ...seams, allowCreate: false });
  } catch (err) {
    if (err instanceof TokenMacKeyError && err.state === "missing") {
      return ensureKey({ ...seams, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    }
    throw err;
  }
}

/**
 * A `readSetting` for `familyConverted`/`markConverted`, bound to this db — unless the caller
 * passed one, or passed no db at all (then the era is read from the secrets-side marker only).
 */
export function settingReader(db, opts = {}) {
  if (typeof opts.readSetting === "function") return opts.readSetting;
  if (!db || typeof db.execute !== "function") return undefined;
  return async (key) => {
    const { readSetting } = await import("../gateway/dashboard/settings/registry.js");
    return readSetting(db, key);
  };
}

/** Map token-mac's `{form, reason}` refusal onto this module's reason vocabulary. */
function reasonForVerdict(verdict) {
  if (verdict.reason) return verdict.reason; // key-lost / key-invalid / key-missing
  if (verdict.form === "foreign") return "foreign-mac";
  if (verdict.form === "invalid") return "mac-invalid";
  return "mac-mismatch";
}

/**
 * Is this row's definition the one a key holder wrote?
 *
 * @param {{bot_id: string, definition: string|null, enabled: number|boolean, project_id: number|null,
 *          def_mac?: string|null, def_generation?: number|null}} row
 * @param {{db?: object, readSetting?: Function, crowHome?: string, path?: string, statePath?: string,
 *          generationsPath?: string, audit?: Function, alarm?: boolean, replay?: boolean}} [opts]
 * @returns {Promise<{ok: boolean, reason: string}>} `reason` is one of BOT_DEF_REFUSALS; `ok` with
 *   "mac" is the normal case, "pre-era" an install that has not converted yet, "pending" the row a
 *   crashed writer left one generation behind.
 */
export async function verifyBotDef(row, opts = {}) {
  // The DB mirror may only ADD a refusal (an alarm), never open anything.
  let marker = false;
  try { marker = await botDefFamilyConverted({ ...opts, readSetting: settingReader(opts.db, opts) }); } catch { marker = true; }
  // ONE era decision for every reader (round C, item E3): the DB marker/mirror, and the
  // secrets-side evidence the synchronous readers use (the marker file, the generations file, or a
  // caller's own `anyMac`/`h1ValuesExist` scan). A row without the `def_mac` COLUMN is refused
  // ("no-mac-column") once ANY of them says the box was converted.
  const converted = marker || botDefEraConvertedSync(opts);
  return verifyBotDefSync(row, { ...opts, converted });
}

/**
 * `verifyBotDef` with the era already decided — the SYNCHRONOUS form the bridge's per-turn
 * `loadBot` needs (better-sqlite3, no await). Everything below is the same rule set; see
 * `botDefEraConvertedSync` for how a sync caller decides `converted`.
 *
 * @param {object} row the `pi_bot_defs` row (definition, enabled, project_id, def_mac, def_generation)
 * @param {{converted: boolean, replay?: boolean} & object} opts `converted` is REQUIRED (the era
 *        marker), plus the key/file seams and `audit`/`alarm` for token-mac's alarm. `replay: false`
 *        skips the generation floor for the one caller that verifies a CAPTURED version
 *        (servers/shared/history/api.js); it never skips the MAC.
 * @returns {{ok: boolean, reason: string}}
 */
export function verifyBotDefSync(row, opts = {}) {
  // NEVER THROWS for a bad row (a missing `converted` is the one programming error).
  if (typeof opts.converted === "boolean") {
    try {
      return verifyBotDefInner(row, opts);
    } catch (err) {
      if (err instanceof DefinitionTooComplexError) return { ok: false, reason: "definition-too-complex" };
      return { ok: false, reason: "mac-invalid" };
    }
  }
  return verifyBotDefInner(row, opts);
}

function verifyBotDefInner(row, opts) {
  if (typeof opts.converted !== "boolean") {
    throw new TypeError("verifyBotDefSync needs opts.converted (the bot:def era marker) as a boolean");
  }
  const converted = opts.converted;
  const botId = String(row?.bot_id ?? "");
  const mac = typeof row?.def_mac === "string" && row.def_mac !== "" ? row.def_mac : null;

  // BEFORE the era there is nothing to check: the row has no MAC because the converter has not
  // run on this install yet (every install upgrading to this release, and every seeded test row).
  if (!mac) {
    // A row object WITHOUT the `def_mac` KEY is not an unsealed row: it is a `pi_bot_defs` that has
    // no such COLUMN at all. Before the era that is a store whose migration has not run (accepted,
    // as before); after it, somebody DROPPED the column, and accepting that as "pre-era" would let a
    // contained bot shake off verification by running one ALTER TABLE (round C, item E3). The ERA
    // decides, never the row's shape — including the generations file, which is written after the
    // conversion's seal and proves one happened even when the marker and mirror are gone.
    const columnless = !Object.prototype.hasOwnProperty.call(row ?? {}, "def_mac");
    if (columnless) {
      // THE ERA DECIDES (round C, item E3): the DB mirror and the secrets-side marker both say
      // "converted" on any box the converter has run on, and a contained bot can delete only the DB
      // copy — `<CROW_HOME>/secrets/token-mac.json` is out of its reach. The generations file is NOT
      // consulted as evidence here: it is keyed by bot id alone, so one `secrets/` serving several
      // crow.db copies (an operator's backups, a test suite) would make a fresh store look converted
      // and refuse every row it has not sealed.
      if (converted || forcedUnsealedRefusal) return { ok: false, reason: "no-mac-column" };
      const state = keyState(opts);
      if (state === "lost" || state === "invalid") {
        botDefKeyAlarm(tokenMacKeyPath(opts), state);
        return { ok: false, reason: state === "lost" ? "key-lost" : "key-invalid" };
      }
      return { ok: true, reason: "pre-era" };
    }
    if (converted || forcedUnsealedRefusal) return { ok: false, reason: "no-mac" };
    // A box that LOST its key before the era is not a new box: accepting its unsealed rows would
    // hand the policy to whoever can write them. "first-boot" (no key, no state, no evidence) is
    // the only key state in which an unsealed row is accepted.
    const state = keyState(opts);
    if (state === "lost" || state === "invalid") {
      botDefKeyAlarm(tokenMacKeyPath(opts), state);
      return { ok: false, reason: state === "lost" ? "key-lost" : "key-invalid" };
    }
    return { ok: true, reason: "pre-era" };
  }

  // STRICT TYPES. The MAC input takes the columns exactly as stored (canonicalBotDef coerces
  // nothing), so a row whose `enabled` is not the 0/1 NUMBER the writer stores — or whose
  // `project_id`/generation is not a safe integer — is refused before it is hashed rather than
  // verifying some coerced reading of itself.
  if (typeof row?.enabled !== "number" || (row.enabled !== 0 && row.enabled !== 1)) {
    return { ok: false, reason: "row-types" };
  }
  if (!(row?.project_id === null || row?.project_id === undefined || Number.isSafeInteger(row.project_id))) {
    return { ok: false, reason: "row-types" };
  }
  if (row?.def_generation !== undefined && row?.def_generation !== null && !Number.isSafeInteger(row.def_generation)) {
    return { ok: false, reason: "generation-invalid" };
  }

  // A present MAC must verify REGARDLESS of the era marker: a crash between the converter's
  // commit and `markConverted` leaves keyed rows behind on a box that is "not converted" yet,
  // and those rows are exactly as trustworthy as a converted one. `verifyMacValue` has no legacy
  // branch and no era to consult, so a bare sha256 in `def_mac` is refused whatever the marker says.
  const verdict = verifyMacValue(BOT_DEF_FAMILY, canonicalBotDef(row), mac, keyLocation(opts));
  if (!verdict.ok) {
    if (verdict.reason === "key-lost" || verdict.reason === "key-invalid" || verdict.reason === "key-missing") {
      botDefKeyAlarm(tokenMacKeyPath(opts), verdict.reason === "key-lost" ? "lost" : "invalid");
    }
    return { ok: false, reason: reasonForVerdict(verdict) };
  }
  if (!converted) return { ok: true, reason: "pre-era" };

  // ─── the canonical TEXT ───
  // The MAC covers the definition's VALUE, so two texts that parse differently (a duplicate key,
  // an escape) could still hash the same while a SQL reader (`json_extract`, the history
  // projection) saw something else. So the stored text must BE the canonical serialization of the
  // one document it holds. A row written before this rule is canonicalised by the boot converter,
  // which is why the check only applies after the era.
  if (row?.definition !== null && row?.definition !== undefined) {
    if (typeof row.definition !== "string" || canonicalDefinitionText(row.definition) !== row.definition) {
      return { ok: false, reason: "definition-text" };
    }
  }

  // ─── the replay floor ───
  // `opts.replay === false` is for ONE caller: the history restore verifies a VERSION's own MAC at
  // the generation it was captured at, which is legitimately behind the live counter.
  if (opts.replay === false) {
    return { ok: true, reason: "mac" };
  }
  let st;
  try {
    st = readBotDefGenerations(opts);
  } catch {
    return { ok: false, reason: "generations-missing" };
  }
  if (st.corrupt) return { ok: false, reason: "generations-missing" };
  if (!st.exists) {
    console.error(
      `[bot-def] ${botDefGenerationsPath(opts)} is missing while the bot:def era is converted, so no `
      + "bot definition can be verified and no bot spawns. Restore it from the instance's backups; this "
      + "instance refused the definitions rather than accept one without replay protection.",
    );
    return { ok: false, reason: "generations-missing" };
  }
  const generation = row?.def_generation;
  if (!Number.isSafeInteger(generation) || generation < 1) return { ok: false, reason: "generation-invalid" };
  const entry = st.bots[botId];
  // The ACCEPTED generation is the only one a settled row may carry; a write that is still in flight
  // adds exactly one more acceptable value, `pending` (its own planned generation). Every generation
  // at or below an ABANDONED plan is neither: it was signed once and never landed, so a bot that
  // stashes that tuple (a RAISE(IGNORE) trigger) cannot replay it after the owner's next write.
  const accepted = entry?.generation ?? 0;
  const pending = entry && Number.isInteger(entry.pending) && entry.pending > accepted ? entry.pending : null;
  // The row the write in flight has already written (it has not settled yet): the normal equal case.
  if (pending !== null && generation === pending) return { ok: true, reason: "mac" };
  // The row a crashed writer left behind: the file records that the next generation was in flight, so
  // the last good row is still accepted.
  if (generation === accepted) return { ok: true, reason: pending !== null ? "pending" : "mac" };
  if (generation < accepted) return { ok: false, reason: "generation-behind" };
  // Above the accepted generation and not the generation in flight: a row ahead of the file (which
  // the plan-first order makes impossible for a legitimate row) or a leftover planned-and-abandoned
  // generation. Either way it is refused.
  return { ok: false, reason: "generation-ahead" };
}

/** The key-location seams token-mac takes, without the options that are ours. */
function keyLocation(opts = {}) {
  const out = {};
  for (const key of ["crowHome", "path", "statePath"]) {
    if (opts[key] !== undefined) out[key] = opts[key];
  }
  return out;
}

export { TokenMacKeyError };