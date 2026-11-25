/**
 * The ONE writer of `pi_bot_defs`, and the verified read every authority reader should use.
 *
 * A bot definition is authority (see `servers/shared/bot-def-mac.js`), so every row carries a
 * keyed MAC over its whole content plus a monotonic generation, and a write must set both in the
 * SAME statement as the definition. This module is that statement:
 *
 *   writeBotDef(db, { bot_id, definition, enabled, project_id, display_name, mode, expect* })
 *   setBotEnabled(db, bot_id, enabled, { expect* })
 *   setBotProjectId(db, bot_id, project_id, { expect* })
 *   readVerifiedBotDef(db, bot_id)          — the row AND its verification verdict
 *   signBotDef(row)                          — for a caller that issues its own UPDATE
 *   verifyAllBotDefs(db)                     — verify every row (the operator key reset's step 0)
 *   resealAllBotDefs(db, { verifiedRows })   — re-MAC the rows step 0 verified (the reset's last step)
 *
 * THE VERIFIED ROW IS THE ONLY ROW A WRITE CAN LAND ON (round C, item E1). Verification and the
 * statement are TWO steps, so a row can change in between (a contained bot flipping its definition
 * from the sealed S to a tampered T without touching `def_mac`/`def_generation`). The UPDATE's
 * WHERE therefore pins EVERY MAC-covered column of the row that was VERIFIED
 * (`definition IS ? AND enabled IS ? AND project_id IS ? AND def_mac IS ? AND def_generation IS ?`),
 * so the statement lands only on the state it verified — a row that moved makes it land nowhere (and
 * the caller sees its ordinary "stale" answer) instead of re-signing content nothing vouched for.
 * EVERY PARTIAL WRITE STATES THE ROW IT READ (round D, item F1). An UPDATE is only written by a
 * caller that hands in the exact raw row content it read and based its change on
 * (`expectDefinition`, `expectEnabled`, `expectProjectId` — REQUIRED for every update, not an
 * optional extra): the store then refuses unless those agree exactly with the row it verified
 * (the distinct reason `caller-read-differs`). A writer that read a TAMPERED row therefore cannot
 * sign anything: nothing in this module builds content out of a raw read on its behalf, and there
 * is no mode that does (the former `transform: (verifiedRow) => next` mode is gone — a backfill
 * reads the row, builds its change from what it read, and passes those values as `expect*`, so a
 * tampered row is refused instead of quietly rewritten). The only two exemptions are structural:
 * an INSERT (a create takes nothing from a row) and `ownerFullReplace` (a full-form save supplies
 * the whole MAC-covered content itself). A caller that omits `expect*` for an update gets a
 * PROGRAMMING error (`BOT_DEF_EXPECT_REQUIRED`), never a write.
 *
 * ONE STATEMENT IS THE ATOMIC UNIT. A `BEGIN IMMEDIATE` is deliberately NOT used: `db.execute` is an
 * ASYNC facade over one shared connection (`servers/db.js`), so a statement any other caller issues
 * while this function awaits JOINS the open transaction and commits or rolls back with it. The
 * pinned-content UPDATE is atomic on its own: SQLite evaluates its WHERE against the row at write
 * time under the write lock, so it lands exactly when the row is still the one verified above.
 *
 * Callers keep their own optimistic concurrency: each `expect*` option they pass becomes one
 * `column IS ?` clause (`expectDefinition` is the `definition IS ?` several callers already use),
 * so a stale form still writes 0 rows and the caller still answers "reload and try again". (The three
 * required `expect*` values are ALSO the proof of the read — see above.) A compare-and-swap that
 * matches nothing, or a statement that throws, leaves the generation counter's ACCEPTED generation
 * where it was and only clears the `pending` mark — the planning high-water keeps the abandoned
 * generation, so the next write plans a higher one and the tuple this one signed can never verify
 * (`servers/shared/bot-def-mac.js`, item I1). An EXCEPTION after a row LANDED settles instead of
 * abandoning (item J1): SQLite's `RAISE(FAIL)` stops a statement but keeps the row change it had
 * already made, so a writer that treated "it threw" as "it did not land" would leave its own row one
 * generation AHEAD of the counter (refused as "generation-ahead", so no bot spawns) while the older
 * tuple it replaced stayed replayable. Every catch after a statement therefore re-reads the row:
 * when it carries the `(def_mac, def_generation)` pair this write signed, the write landed and the
 * counter settles (accepted = planned); only a row that does not carry the tuple abandons
 * (`settleIfLanded`).
 *
 * NO FOREIGN TRIGGER ON `pi_bot_defs` (round I, item I2). A trigger fires with no code of ours in
 * between, so it can rewrite a row after this module signed it, or swallow the write (`RAISE(IGNORE)`)
 * and stash the parameters. Before any generation is planned, every write reads the table's triggers
 * from `sqlite_master`/`sqlite_temp_master` and compares them with the set Crow installs
 * (`servers/shared/trigger-catalog.js`: the history layer's `hist_pi_bot_defs_a[diu]`, with their
 * exact generated SQL, and any other static one) by NAME AND whitespace-normalised SQL. Anything
 * foreign or body-changed refuses the write with `BOT_DEF_FOREIGN_TRIGGER` and one log line naming
 * the trigger — no trigger is ever dropped or modified here. A store whose trigger list cannot be
 * read refuses too (fail closed: a table this important is not written blind).
 *
 * …AND ON EVERY TABLE THE WRITE REACHES (item J2). A trigger on `pi_bot_defs` that Crow DID install
 * still runs Crow's own body, and those bodies write other tables: the history capture triggers
 * insert into `item_versions`, which carries the append-only guards. A trigger somebody added down
 * that path fires inside the same statement and can abort it after the row change was made, or
 * swallow it, so the same check covers every table reachable through Crow's own trigger bodies —
 * the set is DERIVED from the catalogue (`reachableTriggerTables`), never copied, and table names
 * are compared case-insensitively (SQLite keeps `tbl_name` as it was written). The check runs
 * immediately before the statement, on the same connection (see `executeGuarded` for why it is not
 * one transaction, and what covers the window), and the never-lowered high-water plus the landing
 * check below make that window unable to produce a replayable tuple.
 *
 * NO WRITE SIGNS CONTENT IT COULD NOT VERIFY ("MAC laundering"). Almost every caller builds the
 * new definition from a raw read of the row (a tab save, a toggle, a rename, a move, a Studio
 * grant, a peer patch, a backfill, a skill promotion, a history restore). Signing that content
 * would seal whatever the row happens to hold, INCLUDING an edit a contained bot made to a field
 * the caller never looked at — a tampered `permission_policy` would come back stamped as the
 * owner's. So an UPDATE reads the current row and VERIFIES it first (`verifyBotDef`), and refuses
 * with `code === BOT_DEF_UNVERIFIED` when it does not verify (nothing written, no generation
 * bumped, one log line). The only way to write over an unverified row is `ownerFullReplace: true`
 * plus an explicit `definition`, `enabled` AND `project_id` — the full-form saves (the wizard's
 * create, the voice-bot editor's save, the CLI import), where NOTHING from the row is used. The
 * row's own `def_mac`/`def_generation` join the compare-and-swap, so the row that was verified is
 * the row the statement lands on.
 *
 * EVERY SUCCESSFUL SEALED WRITE ALSO LEAVES AN APPROVED COPY (round D, item F2): the content it just
 * stored goes to `<CROW_HOME>/secrets/bot-def-approved/<bot_id>.json` (`servers/shared/bot-def-approved.js`),
 * which is what `node scripts/cli/bot-def-reapprove.mjs <bot_id> --show` diffs a refused row against.
 * It is a recovery aid, never authority: a copy that cannot be written only weakens that diff (one
 * log line, never a failed write).
 *
 * HOST-ONLY (it reaches the key through `bot-def-mac.js`). Bot-loadable code writes through
 * `servers/shared/bot-def-seal.js`, which this module installs into at import time — so a process
 * that imports the store for any reason (the gateway's pre-listen converter, the bridge's spawn
 * path) also serves those callers.
 *
 * WHY A BOT DOES NOT GET A VERIFIED READ HERE. A bot's own MCP children (the storage server, for
 * one) read a definition to scope a call, and they cannot hold the key. So they read the row raw,
 * as they always did — `tests/bot-def-single-writer.test.js` lists those sites, and the gateway's
 * own copies of the same decisions are the verified ones. Giving a child the key would hand it
 * exactly what this module exists to withhold.
 */
import {
  macBotDef, canonicalBotDef, canonicalDefinitionText, verifyBotDef, verifyBotDefSync,
  botDefEraConvertedSync, botDefEraSettingKey,
  ensureBotDefWriteKey, planBotDefGeneration, settingReader, TokenMacKeyError, ensureSigningKeyFor,
  settleBotDefGeneration, abandonBotDefGeneration, botDefGenerationsPath, readBotDefGenerations,
  seedBotDefGenerations, forgetBotDefAlarms,
} from "./bot-def-mac.js";
import { installBotDefSeal } from "./bot-def-seal.js";
import { writeApprovedBotDef } from "./bot-def-approved.js";
import {
  expectedTriggersOnTables, readTriggerRows, reachableTriggerTables, unexpectedTriggers,
} from "./trigger-catalog.js";

/**
 * The refusal code a write raises when `pi_bot_defs` carries a trigger Crow did not install (or one
 * whose body changed): nothing is planned and nothing is written, because a trigger can rewrite or
 * swallow the statement this module signs (item I2).
 */
export const BOT_DEF_FOREIGN_TRIGGER = "BOT_DEF_FOREIGN_TRIGGER";

/**
 * The refusal code a write raises when the row it was about to re-sign does not verify. Distinct on
 * purpose: a route maps it to its own generic "reload" answer, and it never means "stale".
 */
export const BOT_DEF_UNVERIFIED = "BOT_DEF_UNVERIFIED";

/**
 * The error a PARTIAL write throws when it was not given the row it read (round D, item F1): a
 * programming error, never a datastore answer — every update must state `expectDefinition`,
 * `expectEnabled` and `expectProjectId`, so nothing is signed on the strength of a read nobody made.
 */
export const BOT_DEF_EXPECT_REQUIRED = "BOT_DEF_EXPECT_REQUIRED";

/** `<bot_id>` → the last time this process said a row was changed outside Crow (24 h de-duplication). */
const unverifiedSeen = new Map();
const UNVERIFIED_ALARM_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Test seam: forget this process's de-duplication of the "changed outside Crow" line. */
export function forgetBotDefUnverifiedAlarms() {
  unverifiedSeen.clear();
}

/**
 * ONE line per bot per 24 h: the refused write's operator-facing half (the ROUTE says nothing new).
 * It names the OPERATOR COMMAND (round C, item E6): an ordinary bot refused as unverified otherwise
 * had no recovery path at all, and "open Bot Builder and save it" was only true for the bots that
 * have a page there.
 */
function unverifiedAlarm(botId, reason, { now = Date.now() } = {}) {
  const id = String(botId ?? "");
  const at = unverifiedSeen.get(id);
  if (typeof at === "number" && now - at < UNVERIFIED_ALARM_WINDOW_MS) return false;
  unverifiedSeen.set(id, now);
  console.warn(
    `[bot-def] ${id} was changed outside Crow; review it with `
    + `\`node scripts/cli/bot-def-reapprove.mjs ${id} --show\`, then re-approve exactly that content with `
    + `\`--approve <digest>\` (${String(reason ?? "")})`,
  );
  return true;
}

/** The error a refused write throws (see `BOT_DEF_UNVERIFIED`). */
function botDefUnverified(botId, reason) {
  const err = new Error(`bot ${botId} settings could not be verified (${reason})`);
  err.code = BOT_DEF_UNVERIFIED;
  err.reason = reason;
  return err;
}

/** `<bot_id>` → the last time this process named a foreign trigger on `pi_bot_defs` (24 h). */
const foreignTriggerSeen = new Map();

/** Test seam: forget this process's de-duplication of the foreign-trigger line. */
export function forgetForeignTriggerAlarms() {
  foreignTriggerSeen.clear();
}

/**
 * ONE line per trigger per 24 h, naming the trigger NAME ONLY (a name is bot-written text, so it is
 * escaped to a single printable token rather than trusted to a terminal): the operator's half of the
 * refusal, which the route turns into its own generic answer.
 */
function foreignTriggerAlarm(trigger, { now = Date.now() } = {}) {
  const name = String(trigger?.name ?? "");
  const at = foreignTriggerSeen.get(name);
  if (typeof at === "number" && now - at < UNVERIFIED_ALARM_WINDOW_MS) return false;
  foreignTriggerSeen.set(name, now);
  console.warn(
    `[bot-def] pi_bot_defs carries the trigger ${name.replace(/[^\x20-\x7e]/g, "?")} which Crow did not install as it `
    + "now stands, so bot definitions are not written while it is there. Crow never drops a trigger; "
    + "inspect it (SELECT sql FROM sqlite_master WHERE type='trigger' AND name='…') and remove it by hand "
    + "if Crow did not put it there.",
  );
  return true;
}

/**
 * The tables ONE `pi_bot_defs` write can reach through Crow's OWN triggers, plus the table itself
 * (item J2: the history capture triggers write `item_versions`, whose guards fire next).
 */
function guardedTriggerTables() {
  return reachableTriggerTables("pi_bot_defs");
}

/** The trigger rows a write must account for: the ones on any table it can reach, any case. */
function rowsOnGuardedTables(rows, tables) {
  const guarded = tables || guardedTriggerTables();
  return (rows || []).filter((row) => {
    const table = String(row?.tbl_name ?? "").toLowerCase();
    // A trigger the database cannot attribute to a table is not "somebody else's table": it is
    // one this guard cannot rule out, so it is checked against the whole expected set.
    return table === "" || guarded.has(table);
  });
}

/**
 * The offenders in one set of `sqlite_master` trigger rows, or one entry when the list could not be
 * read at all (item I2/J2). The comparison is NAME plus normalised SQL against the triggers Crow
 * installs on EVERY table a `pi_bot_defs` write can reach (`tables`, derived once by the caller).
 */
function triggerOffenders(rows, error, tables) {
  if (error) {
    // Cannot tell is not "none there": a table whose trigger list cannot be read is not written.
    return [{ name: "(trigger list unreadable)", table: "pi_bot_defs", reason: "unreadable" }];
  }
  const guarded = tables || guardedTriggerTables();
  return unexpectedTriggers(rowsOnGuardedTables(rows, guarded), expectedTriggersOnTables(guarded));
}

/**
 * Refuse when any table a `pi_bot_defs` write can reach carries a trigger Crow did not install, or
 * one whose body no longer matches the body Crow installs (items I2 and J2). Runs BEFORE any
 * generation is planned.
 *
 * @throws {Error} `code === BOT_DEF_FOREIGN_TRIGGER` with `trigger` naming the first offender
 */
async function refuseForeignTriggers(db, botId) {
  const tables = guardedTriggerTables();
  const { rows, error } = await readTriggerRows(db);
  throwIfForeignTriggers(triggerOffenders(rows, error, tables), botId);
}

/** Throw the refusal for the first offender (nothing is written when there is one). */
function throwIfForeignTriggers(offenders, botId) {
  if (!offenders.length) return;
  const first = offenders[0];
  foreignTriggerAlarm(first);
  const err = new Error(
    `bot ${botId} settings were not written: ${first.name} on ${first.table || "pi_bot_defs"} is not a trigger `
    + "Crow installed as it now stands",
  );
  err.code = BOT_DEF_FOREIGN_TRIGGER;
  err.trigger = first.name;
  err.reason = first.reason;
  err.table = first.table || null;
  err.offenders = offenders;
  throw err;
}

/**
 * THE TRIGGER CHECK, IMMEDIATELY BEFORE THE STATEMENT (items I2/J2).
 *
 * WHY NOT ONE `BEGIN IMMEDIATE … check … UPDATE … COMMIT`. The atomic form was considered and is not
 * used, for the reason this module's header already gives for never opening a transaction of its own:
 * `db.execute` is an ASYNC facade over ONE shared connection, so a statement any other caller issues
 * while this write awaits JOINS the open transaction and commits or rolls back with it — and this
 * write path awaits (the era read, the key check, the statement, the approved copy). Only the last
 * two could sit inside a transaction, and moving the statement off `db.execute` onto a transaction
 * callback's synchronous `run` changes the write's shape for every caller that watches this client
 * (a route's own retry hook, a panel's save path).
 *
 * WHAT COVERS THE REMAINING WINDOW. A trigger created between this check and the statement cannot
 * make an abandoned tuple replayable: the planned generation is written and fsynced BEFORE the
 * statement and never lowered, so a trigger that swallows the write (0 rows) leaves an abandoned
 * generation that can never be signed again, one that rewrites the row leaves a row the MAC refuses,
 * and one that raises AFTER the row change is kept settles rather than abandons (`settleIfLanded`,
 * item J1). Nor is the gap the tamper this exists for: creating a trigger takes crow.db write
 * access, which is the same access writing the row directly would take.
 */
async function executeGuarded(db, botId, statement) {
  await refuseForeignTriggers(db, botId);
  return db.execute(statement);
}

/**
 * THE THREE expectations a partial write must state (round D, item F1). `display_name` is NOT one of
 * them: it is outside the MAC, so it stays an optional extra condition (`expectDisplayName`).
 */
const REQUIRED_EXPECTATIONS = Object.freeze([
  ["expectDefinition", "definition"],
  ["expectEnabled", "enabled"],
  ["expectProjectId", "project_id"],
]);

/**
 * Refuse a partial write that did not state the row it read — see `BOT_DEF_EXPECT_REQUIRED`.
 * Only an INSERT (`mode: "insert"`, a create takes nothing from a row) and `ownerFullReplace` (a
 * full-form save supplies the whole MAC-covered content) are exempt.
 */
function requireExpectations(args) {
  const merged = expectationsOf(args);
  const missingOptions = REQUIRED_EXPECTATIONS
    .filter(([option, key]) => !Object.prototype.hasOwnProperty.call(args, option)
      && !Object.prototype.hasOwnProperty.call(args.expect || {}, key))
    .map(([option]) => option);
  if (!missingOptions.length) return merged;
  const err = new Error(
    `writeBotDef needs ${missingOptions.join(", ")} for an update: a partial write must state the row it read `
    + "(see servers/shared/bot-def-store.js)",
  );
  err.code = BOT_DEF_EXPECT_REQUIRED;
  err.missing = missingOptions;
  throw err;
}

/** Warned-once set: a `pi_bot_defs` shaped before this feature (a store whose init-db never ran). */
const warnedUnsealed = new WeakSet();

/** How many times a write re-signs when another writer planned a higher generation meanwhile. */
const WRITE_ATTEMPTS = 3;

/**
 * Does this store's `pi_bot_defs` carry the two seal columns? Probed ONCE per db handle (a
 * `SELECT … LIMIT 0`), so a schema that predates them — a unit-test fixture, an instance whose
 * migration has not run yet — does not turn every write into a failure. The write then lands
 * UNSEALED, which is exactly the pre-era shape verification already refuses on a converted
 * instance, and one warning names the fix.
 */
const sealProbes = new WeakMap();
async function sealable(db) {
  if (db && typeof db === "object" && sealProbes.has(db)) return sealProbes.get(db);
  let ok = true;
  try {
    await db.execute({ sql: "SELECT def_mac, def_generation FROM pi_bot_defs LIMIT 0", args: [] });
  } catch {
    ok = false;
  }
  if (db && typeof db === "object") sealProbes.set(db, ok);
  return ok;
}

/** A definition argument may be the stored TEXT or the object; the column stores CANONICAL text. */
function normalizeDefinition(value) {
  return canonicalDefinitionText(value);
}

/**
 * May this write replace an UNVERIFIED row? Only a full-form save: the caller passed
 * `ownerFullReplace` AND supplied all three MAC-covered fields itself, so nothing is taken from the
 * row (see the module header). Every partial/derived writer omits the flag and refuses instead.
 */
function isOwnerFullReplace(args) {
  return args.ownerFullReplace === true
    && args.definition !== undefined
    && args.enabled !== undefined
    && args.project_id !== undefined;
}

const asBit = (value) => (Number(value) ? 1 : 0);
const asId = (value) => (value === undefined ? undefined : value === null || value === "" ? null : Number(value));
async function selectRow(db, botId) {
  const { rows } = await db.execute({
    sql: "SELECT * FROM pi_bot_defs WHERE bot_id = ? LIMIT 1",
    args: [String(botId)],
  });
  return rows?.[0] || null;
}

/** One warning per db handle when the seal columns are missing: the write cannot be sealed. */
function warnUnsealed(db) {
  if (db && typeof db === "object") {
    if (warnedUnsealed.has(db)) return;
    warnedUnsealed.add(db);
  }
  console.warn(
    "[bot-def] pi_bot_defs has no def_mac/def_generation columns: this write cannot be sealed. "
    + "Run `npm run init-db` (or the migration rail) so bot definitions are verifiable again.",
  );
}

/**
 * The optimistic-concurrency conditions, as SQL fragments on ONE row. `expect` is
 * `{definition, display_name, project_id, enabled}`; an option that is not given is not
 * conditioned on (so a caller can keep exactly the condition it had).
 */
function expectClauses(expect = {}) {
  const clauses = [];
  const args = [];
  if (Object.prototype.hasOwnProperty.call(expect, "definition")) {
    clauses.push("definition IS ?");
    args.push(expect.definition ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(expect, "display_name")) {
    clauses.push("display_name IS ?");
    args.push(expect.display_name ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(expect, "project_id")) {
    clauses.push("project_id IS ?");
    args.push(expect.project_id ?? null);
  }
  if (Object.prototype.hasOwnProperty.call(expect, "enabled")) {
    clauses.push("enabled IS ?");
    args.push(asBit(expect.enabled));
  }
  return { clauses, args };
}

/** The caller's `expect*` options plus a nested `expect` object, merged (nested wins). */
function expectationsOf(opts = {}) {
  const out = { ...(opts.expect && typeof opts.expect === "object" ? opts.expect : {}) };
  for (const key of ["definition", "display_name", "project_id", "enabled"]) {
    const option = `expect${key.replace(/(^|_)([a-z])/g, (_, __, c) => c.toUpperCase())}`;
    if (Object.prototype.hasOwnProperty.call(opts, option)) out[key] = opts[option];
  }
  return out;
}

/**
 * Which of the caller's own expectations is NOT the row this call verified, or null when they agree
 * (round C, item E1). A caller that read the row itself (a tab save, an artifact house style, a
 * share grant, a federation patch) hands its read along as `expectDefinition` & co. When that read
 * is not the row verification accepted, the caller built its new content from something nothing
 * vouched for — a bot flipping S→T→S around the two reads is exactly that — so the write refuses
 * instead of signing it. The definition is compared as its CANONICAL text, so a caller that read the
 * stored text verbatim (whatever its formatting) agrees with the row it verified.
 */
function expectationDiffers(expect = {}, row) {
  const has = (key) => Object.prototype.hasOwnProperty.call(expect, key);
  if (has("definition")
    && canonicalDefinitionText(expect.definition ?? null) !== canonicalDefinitionText(row?.definition ?? null)) {
    return "definition";
  }
  if (has("display_name") && String(expect.display_name ?? "") !== String(row?.display_name ?? "")) return "display_name";
  if (has("project_id") && asId(expect.project_id) !== asId(row?.project_id)) return "project_id";
  if (has("enabled") && asBit(expect.enabled) !== asBit(row?.enabled)) return "enabled";
  return null;
}

/**
 * The `bot:def` era for THIS store — ONE decision for every reader (round C, item E3): the DB
 * marker/mirror and the secrets-side marker. The DB mirror is read DIRECTLY here
 * rather than through `botDefFamilyConverted`, which answers
 * "converted" when its settings reader throws. That fail-closed answer is right for a KEY decision
 * (never mint a key on a box we cannot read) and wrong here: a store whose settings schema is
 * partial — a fixture, an install mid-migration — would then read as converted and refuse every
 * unsealed row, which is not evidence of anything.
 *
 * The OTHER kind of evidence — a sealed row in this table — is what `verifyAllBotDefs` scans for, and it
 * settles the one decision a columnless table cannot answer for itself: a row whose `def_mac` COLUMN
 * was dropped is refused (`no-mac-column`), never accepted as "pre-era".
 */
async function eraConvertedFor(db, seams = {}) {
  try {
    const readSetting = settingReader(db, seams);
    if (typeof readSetting === "function") {
      const raw = await readSetting(botDefEraSettingKey());
      const value = raw === null || raw === undefined ? "" : String(raw).trim();
      if (value !== "" && value !== "0" && value.toLowerCase() !== "false") return true;
    }
  } catch { /* no mirror here: the secrets side decides */ }
  return botDefEraConvertedSync(seams);
}

/**
 * Does ANY row in this table carry a `def_mac`? It scans with `SELECT 1 … WHERE def_mac IS NOT NULL`,
 * so a table that has no such COLUMN answers false (there is nothing to scan). Used by
 * `verifyAllBotDefs`, whose rows come from `SELECT *` on this same handle.
 */
async function anySealedRow(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM pi_bot_defs WHERE def_mac IS NOT NULL LIMIT 1",
      args: [],
    });
    return (rows || []).some((row) => Number(row?.present) === 1);
  } catch {
    return false; // no `def_mac` column here: no sealed row can exist
  }
}

/**
 * Write ONE bot definition — insert or update — setting `definition`, `def_mac` and
 * `def_generation` together, so a row can never hold a definition its MAC does not cover.
 *
 * @param {object} db crow.db client (`execute`, `runTransaction`)
 * @param {{ bot_id: string, definition?: string|object|null, display_name?: string,
 *           enabled?: number|boolean, project_id?: number|null,
 *           mode?: "insert"|"update", orIgnore?: boolean, ownerFullReplace?: boolean,
 *           expect?: object, expectDefinition?: string|null, expectDisplayName?: string|null,
 *           expectProjectId?: number|null, expectEnabled?: number|boolean,
 *           opts?: object }} args `opts` carries this module's key/file seams (tests).
 *           For an UPDATE, `expectDefinition`, `expectEnabled` and `expectProjectId` are REQUIRED
 *           (round D, item F1): the caller states the exact raw row content it read and based its
 *           change on. `ownerFullReplace` is for a FULL-FORM owner save only (see the module
 *           header): it must come with `definition`, `enabled` and `project_id`, and then nothing is
 *           read from the row.
 * @returns {Promise<{rowsAffected: number, generation: number|null, missing?: boolean}>}
 * @throws {import("./bot-def-mac.js").TokenMacKeyError} when this process has no usable key
 * @throws {Error} `code === BOT_DEF_EXPECT_REQUIRED` when an update omits one of the three `expect*`
 *   values (a programming error)
 * @throws {Error} `code === BOT_DEF_UNVERIFIED` when the row this write would re-sign does not verify
 *   (its `reason` is the verification's own, `no-mac-column` for a store that lost the column, or
 *   `caller-read-differs` when the caller's `expect*` read is not the row that verified)
 */
export async function writeBotDef(db, args = {}) {
  const botId = String(args.bot_id ?? "");
  if (!botId) throw new Error("writeBotDef needs a bot_id");
  const mode = args.mode === "insert" ? "insert" : "update";
  const seams = args.opts && typeof args.opts === "object" ? args.opts : {};
  const existing = await selectRow(db, botId);

  if (mode === "insert" && !args.orIgnore && existing) {
    // A plain INSERT, never an upsert: replacing an existing bot's whole definition from a
    // "create" path is the data loss Bot Builder's create rule exists to prevent.
    throw new Error(`bot ${botId} already exists`);
  }
  if (mode === "update" && !existing) {
    return { rowsAffected: 0, generation: null, missing: true };
  }
  // An INSERT starts from nothing: the row's own values are never a source for it (and with
  // `orIgnore` the statement lands nowhere when the row is there).
  const current = mode === "update" ? existing : null;

  // A `pi_bot_defs` shaped before this feature cannot hold a MAC. The write still lands (an
  // unsealed row is the pre-era shape, refused by verification on a converted instance) and one
  // warning names the fix — failing the write would break every caller on a mid-migration box.
  const sealed = await sealable(db);
  const converted = await eraConvertedFor(db, seams);
  const verifyOpts = { ...seams, converted };

  // …AFTER the era, a store with no seal COLUMN is a column somebody DROPPED, and a row written
  // unsealed there could never be verified again: the write refuses (round C, item E3). The era
  // decides, never the table's shape.
  if (!sealed && converted) {
    unverifiedAlarm(botId, "no-mac-column");
    throw botDefUnverified(botId, "no-mac-column");
  }

  // ─── the content authority (the module header's "no write signs what it could not verify") ───
  // An UPDATE fills the fields it was not given from the row it read, and signs all of them. So the
  // row must verify — unless this is a full-form save, which supplies the whole MAC-covered content
  // and takes nothing from the row.
  let rowVerified = null;
  if (current) {
    const verdict = verifyBotDefSync(current, verifyOpts);
    if (verdict.ok) rowVerified = current;
    else if (!isOwnerFullReplace(args)) {
      unverifiedAlarm(botId, verdict.reason);
      throw botDefUnverified(botId, verdict.reason);
    }
  }
  // From here on, `current` is only ever read when it verified.
  //
  // F1: A PARTIAL WRITE STATES THE ROW IT READ. A create (`mode: "insert"`) and a full-form owner
  // save take nothing from the row, so they state nothing; every other update must name all three
  // values, or it is a programming error (asked AFTER the authority check above, so a partial write
  // over an unverified row still answers its own `BOT_DEF_UNVERIFIED` refusal).
  const statedExpectations = mode === "update" && !isOwnerFullReplace(args)
    ? requireExpectations(args)
    : expectationsOf(args);
  //
  // THE CALLER'S READ IS PART OF THE PROOF (E1): a caller that states what it read may only write
  // over the row this call verified. Two different reads of the same row mean the row moved between
  // them, and the content the caller built cannot be vouched for.
  if (rowVerified) {
    const differs = expectationDiffers(statedExpectations, rowVerified);
    if (differs) throw botDefUnverified(botId, "caller-read-differs");
  }

  // ─── what this write sets ───
  // An UPDATE fills the fields it was not given from the row it VERIFIED, and signs all of them; the
  // caller's `expect*` (above) is what makes that row the one the caller read. Nothing else is
  // derived here — there is no mode that builds content from the table on a caller's behalf.
  const supplied = {
    definition: args.definition,
    display_name: args.display_name,
    enabled: args.enabled,
    project_id: args.project_id,
  };
  const from = rowVerified;

  const definition = normalizeDefinition(
    supplied.definition !== undefined ? supplied.definition : from ? from.definition : null,
  );
  const displayName = supplied.display_name !== undefined
    ? String(supplied.display_name)
    : from?.display_name ?? botId;
  const enabled = supplied.enabled !== undefined
    ? asBit(supplied.enabled)
    : from
      ? asBit(from.enabled)
      : 1;
  const projectId = supplied.project_id !== undefined ? asId(supplied.project_id) : asId(from?.project_id ?? null);

  if (!sealed) {
    warnUnsealed(db);
    return writeUnsealed(db, {
      botId, mode, orIgnore: !!args.orIgnore, definition, displayName, enabled, projectId, expect: statedExpectations,
      touchUpdatedAt: args.touchUpdatedAt !== false,
    });
  }

  // I2: a trigger on `pi_bot_defs` that Crow did not install (or whose body changed) runs inside any
  // statement this module issues, so it can rewrite the row AFTER it was signed or swallow it whole
  // and stash the parameters for a replay. Nothing is planned and nothing is written while one is
  // there; Crow never drops it (that is the operator's call).
  await refuseForeignTriggers(db, botId);

  // The key first: a box whose key is lost/invalid refuses the write, and nothing else moves.
  await ensureBotDefWriteKey(db, seams);

  // One plan → one statement, retried when ANOTHER writer planned a higher generation while this
  // statement was in flight (two processes can save the same bot). The retry re-signs the very
  // values this call wrote, at the new generation, so a row can never be left BEHIND the counter
  // — which verification refuses as a replay.
  //
  // THE VERIFIED ROW'S CONTENT IS THE COMPARE-AND-SWAP (E1). Attempt 0 pins every MAC-covered column
  // of the row verification accepted (`definition IS ? AND enabled IS ? AND project_id IS ? AND
  // def_mac IS ? AND def_generation IS ?`) plus the caller's own conditions, so the row that was
  // verified is the only row the statement can land on: a row that moved in between makes it match
  // nothing (the caller reports "stale") instead of signing content nobody verified. A retry pins
  // what THIS call's previous attempt wrote, at the seal it made (E7: a write that landed is re-signed,
  // never reported stale), and drops the caller's conditions — that attempt already satisfied them.
  let rowsAffected = 0;
  let generation = null;
  let previousSeal = null;
  const callerCas = expectClauses(statedExpectations);
  for (let attempt = 0; attempt < WRITE_ATTEMPTS; attempt += 1) {
    const planned = planBotDefGeneration(botId, seams);
    generation = planned.generation;
    const defMac = macBotDef({
      bot_id: botId,
      definition,
      enabled,
      project_id: projectId,
      def_generation: generation,
    }, seams);
    const writeMode = attempt === 0 ? mode : "update";

    let sql;
    let sqlArgs;
    if (writeMode === "insert") {
      sql = `INSERT ${args.orIgnore ? "OR IGNORE " : ""}INTO pi_bot_defs `
        + "(bot_id, display_name, definition, enabled, project_id, def_mac, def_generation) "
        + "VALUES (?,?,?,?,?,?,?)";
      sqlArgs = [botId, displayName, definition, enabled, projectId, defMac, generation];
    } else {
      let clauses;
      let casArgs;
      if (attempt === 0) {
        clauses = [...callerCas.clauses];
        casArgs = [...callerCas.args];
      } else {
        clauses = [];
        casArgs = [];
      }
      const anchor = attempt === 0
        ? (rowVerified
          ? {
            definition: rowVerified.definition ?? null,
            enabled: rowVerified.enabled ?? null,
            project_id: rowVerified.project_id ?? null,
            def_mac: rowVerified.def_mac ?? null,
            def_generation: rowVerified.def_generation ?? null,
          }
          : null)
        : {
          definition,
          enabled,
          project_id: projectId,
          def_mac: previousSeal.def_mac,
          def_generation: previousSeal.generation,
        };
      if (anchor) {
        clauses.push("definition IS ?", "enabled IS ?", "project_id IS ?", "def_mac IS ?", "def_generation IS ?");
        casArgs.push(anchor.definition, anchor.enabled, anchor.project_id, anchor.def_mac, anchor.def_generation);
      }
      const sets = ["definition=?", "display_name=?", "enabled=?", "project_id=?", "def_mac=?", "def_generation=?"];
      sqlArgs = [definition, displayName, enabled, projectId, defMac, generation];
      if (args.touchUpdatedAt !== false) sets.push("updated_at=datetime('now')");
      sql = `UPDATE pi_bot_defs SET ${sets.join(", ")} WHERE bot_id=?`
        + (clauses.length ? ` AND ${clauses.join(" AND ")}` : "");
      sqlArgs.push(botId, ...casArgs);
    }

    try {
      // The trigger check and the statement (item J2): one transaction where the client can, the
      // check immediately before it otherwise — see `executeGuarded`.
      const res = await executeGuarded(db, botId, { sql, args: sqlArgs });
      rowsAffected = Number(res && res.rowsAffected) || 0;
    } catch (err) {
      // AN EXCEPTION IS NOT PROOF THE ROW DID NOT LAND (item J1). SQLite's `RAISE(FAIL)` — and a
      // trigger that aborts — stops the statement but KEEPS the row changes it already made (Crow's
      // own `hist_pi_bot_defs_au` writes `item_versions`, and a trigger there can raise), and a
      // client can also throw on the way back from a committed statement. Abandoning then would
      // leave the landed row AHEAD of the accepted generation ("generation-ahead", so no bot
      // spawns) while the bot's older, still-valid tuple stayed replayable — which is the rollback
      // this item is about. So: if the row now carries the very tuple this write signed, the write
      // DID land and it SETTLES; only a row that does not carry the tuple is abandoned.
      if (await settleIfLanded(db, botId, { def_mac: defMac, generation }, seams)) {
        // The row holds this write's content, so it is an approved one too (F2).
        writeApprovedBotDef({ bot_id: botId, definition, enabled, project_id: projectId, generation }, seams);
      } else {
        abandonBotDefGeneration(botId, generation, planned.previous, seams);
      }
      throw err;
    }
    if (rowsAffected === 0) {
      // Nothing landed (a stale form, a row that changed under us, or a retry whose CAS lost to a
      // newer save): the pending mark is cleared, the planning high-water keeps this generation, and
      // the caller reports "stale".
      abandonBotDefGeneration(botId, generation, planned.previous, seams);
      return { rowsAffected: 0, generation };
    }
    previousSeal = { def_mac: defMac, generation };
    settleBotDefGeneration(botId, generation, seams);
    // F2: the approved copy of what this write just stored (a recovery aid; its own failure is
    // logged and swallowed — see servers/shared/bot-def-approved.js).
    writeApprovedBotDef({ bot_id: botId, definition, enabled, project_id: projectId, generation }, seams);
    const floor = generationFloorOf(botId, seams);
    if (floor === null || floor <= generation) return { rowsAffected, generation };
  }
  return { rowsAffected, generation };
}

/**
 * DID THE STATEMENT THAT THREW ACTUALLY LAND? (item J1) Re-read the row and compare its seal with
 * the `(def_mac, def_generation)` pair this write signed — a pair nothing else can hold, because
 * the MAC covers the content and the generation is this write's own planned one.
 *
 * ON A MATCH the generation is SETTLED (accepted = planned) before the caller rethrows, so the
 * landed row is the accepted one: verification accepts it, the bot spawns from the owner's change,
 * and the older tuple the row replaced is "generation-behind" if anything writes it back.
 *
 * ON NO MATCH (the row is gone, it still holds the old row, it holds something else) the caller
 * abandons as before. A read that FAILS is treated as "not ours" — the safe direction: settling a
 * tuple that may not be in the table would make a stashed one replayable, which is exactly what the
 * never-lowered high-water exists to prevent.
 *
 * @returns {Promise<boolean>} true when the row carries this write's seal (and was settled)
 */
async function settleIfLanded(db, botId, seal, seams = {}) {
  if (!seal || seal.def_mac === null || seal.def_mac === undefined
    || seal.generation === null || seal.generation === undefined) {
    return false; // nothing was signed yet (the MAC/key step itself threw): nothing can have landed
  }
  let row;
  try {
    row = await selectRow(db, botId);
  } catch {
    return false; // cannot read → do not bless a tuple that may not be there
  }
  if (!row) return false;
  if (String(row.def_mac ?? "") !== String(seal.def_mac)) return false;
  if (Number(row.def_generation) !== Number(seal.generation)) return false;
  try {
    settleBotDefGeneration(botId, seal.generation, seams);
  } catch { /* the row carries this write's seal either way; a later write settles the counter */ }
  return true;
}

/**
 * The generation another writer has already reached for `botId` (null when it cannot be read).
 *
 * It is the PLANNING HIGH-WATER, not the accepted generation: a generation another writer has planned
 * (and whose write is still in flight) is already promised, so this call's row would be left BEHIND it
 * — which verification refuses as a replay. Comparing with the high-water makes this loop re-sign at
 * a fresh generation instead.
 */
function generationFloorOf(botId, seams = {}) {
  try {
    const st = readBotDefGenerations(seams);
    if (!st.exists || st.corrupt) return null;
    const entry = st.bots[String(botId)];
    if (!entry) return 0;
    return Math.max(entry.generation ?? 0, entry.planned ?? 0, entry.pending ?? 0);
  } catch {
    return null;
  }
}

/** The unsealed fallback (see `warnUnsealed`): the statement `writeBotDef` issues without a MAC. */
async function writeUnsealed(db, { botId, mode, orIgnore, definition, displayName, enabled, projectId, expect, touchUpdatedAt }) {
  let sql;
  let sqlArgs;
  if (mode === "insert") {
    sql = `INSERT ${orIgnore ? "OR IGNORE " : ""}INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id) VALUES (?,?,?,?,?)`;
    sqlArgs = [botId, displayName, definition, enabled, projectId];
  } else {
    const { clauses, args: casArgs } = expectClauses(expect);
    const sets = ["definition=?", "display_name=?", "enabled=?", "project_id=?"];
    if (touchUpdatedAt) sets.push("updated_at=datetime('now')");
    sql = `UPDATE pi_bot_defs SET ${sets.join(", ")} WHERE bot_id=?` + (clauses.length ? ` AND ${clauses.join(" AND ")}` : "");
    sqlArgs = [definition, displayName, enabled, projectId, botId, ...casArgs];
  }
  const res = await db.execute({ sql, args: sqlArgs });
  return { rowsAffected: Number(res && res.rowsAffected) || 0, generation: null, unsealed: true };
}

/**
 * Switch a bot on or off. `enabled` is inside the MAC, so this is a full re-sign (never a bare
 * `SET enabled`): a toggle a bot could write without the key would be a policy change.
 *
 * `opts` carries the three `expect*` values the caller read (REQUIRED — round D, item F1: a toggle
 * is a partial write like any other, and signing the row's current content on the strength of a
 * read nobody made is exactly the laundering this module refuses) plus the `opts` seam object.
 *
 * @returns {Promise<{rowsAffected: number, generation: number|null, missing?: boolean}>}
 */
export async function setBotEnabled(db, botId, enabled, opts = {}) {
  return writeBotDef(db, { ...(opts && typeof opts === "object" ? opts : {}), bot_id: botId, enabled, mode: "update" });
}

/** Re-file a bot into another project (`project_id` is inside the MAC too; `expect*` required). */
export async function setBotProjectId(db, botId, projectId, opts = {}) {
  return writeBotDef(db, { ...(opts && typeof opts === "object" ? opts : {}), bot_id: botId, project_id: projectId, mode: "update" });
}

/**
 * The key a SIGNER needs. Unlike a full write (which scans era evidence before it will create
 * one), a signer holds no database to scan — the history restore signs inside a transaction. So it
 * takes the existing key, and mints one ONLY in token-mac's "first-boot" state, which is a box
 * with no key file, no state file and no recorded era at all: a genuinely new install whose first
 * bot-definition write happens before the boot converter ran (a CLI, a test, an eval harness). A
 * lost or invalid key is never replaced here (`ensureKey` refuses it).
 */
function ensureSigningKey(seams = {}) {
  return ensureSigningKeyFor(seams);
}

/**
 * Sign a row a caller is about to write with its OWN statement (the version-history restore,
 * whose UPDATE is issued by a generic table-driven runner inside one transaction).
 *
 * Returns the generation and MAC to put in that statement plus `settle()`, which the caller runs
 * after the transaction COMMITS (before the commit the row is not there yet, and a crash in
 * between is exactly the header's "pending" case: verification accepts the previous generation).
 *
 * @param {{bot_id: string, definition: string|null, enabled: number, project_id: number|null}} row
 * @returns {{generation: number, def_mac: string, definition: string|null,
 *            settle: () => boolean, abandon: () => boolean}} `definition` is the CANONICAL text the
 *   MAC covers — the caller writes exactly that value, so the row's stored text is canonical (see
 *   `canonicalDefinitionText`) rather than a re-serialisation of its own.
 */
export function signBotDef(row, seams = {}) {
  const botId = String(row?.bot_id ?? "");
  if (!botId) throw new Error("signBotDef needs a bot_id");
  if (row?.sealable === false) {
    // A store without the columns (see `sealable`): nothing to sign, nothing to add.
    return { generation: null, def_mac: null, definition: canonicalDefinitionText(row?.definition), settle: () => false, abandon: () => false };
  }
  // The text is canonicalised BEFORE it is signed, so the value the MAC covers and the text the
  // caller writes are the same document (verification refuses any other text after the era).
  const definition = canonicalDefinitionText(row?.definition === undefined ? null : row.definition);
  const { generation, previous } = planBotDefGeneration(botId, seams);
  let defMac;
  try {
    ensureSigningKey(seams);
    defMac = macBotDef({ ...row, definition, def_generation: generation }, seams);
  } catch (err) {
    // NOTHING WAS WRITTEN YET, so there is nothing to re-read (item J1 asks every catch AFTER a
    // statement to check whether the row carries the tuple it signed; this catch is before any
    // statement exists — the MAC could not even be computed). The settle-or-abandon decision for a
    // statement that threw belongs to the caller that issued it: the history restore runs its
    // UPDATE inside `runOneTransaction`, whose failure ROLLS BACK, so its `abandon()` is right, and
    // a commit that throws after the fact is settled by the next write's own check.
    abandonBotDefGeneration(botId, generation, previous, seams);
    throw err;
  }
  return {
    generation,
    def_mac: defMac,
    definition,
    settle: () => settleBotDefGeneration(botId, generation, seams),
    abandon: () => abandonBotDefGeneration(botId, generation, previous, seams),
  };
}

/**
 * Verify a SET of rows read in one query — one era read for all of them, then the synchronous rule
 * set per row. For a reader that already has the rows (a project's bots, the bots advertised to a
 * peer), this costs ONE settings read instead of one per bot.
 *
 * @param {object[]} rows `pi_bot_defs` rows (they must carry def_mac/def_generation)
 * @returns {Promise<Array<{row: object, ok: boolean, reason: string}>>}
 */
export async function verifyBotRows(db, rows, opts = {}) {
  const converted = await eraConvertedFor(db, opts);
  return (rows || []).map((row) => ({
    row,
    ...verifyBotDefSync(row, { ...opts, converted }),
  }));
}

/**
 * Read one bot definition AND its verification verdict — the read an AUTHORITY decision must
 * make. Never throws for a bad row: `ok: false` with a `reason` is the answer, and the caller
 * decides (refuse the call, omit the bot, refuse the spawn).
 *
 * The era is the STORE's decision (`eraConvertedFor`): the DB marker/mirror and the secrets-side
 * marker. A `pi_bot_defs` that carries no `def_mac` COLUMN at all reads as
 * the pre-era shape it is only while NEITHER says the box was converted; after the era it is a column
 * somebody dropped and the read is refused (`no-mac-column`, round C item E3) — never accepted as
 * "pre-era", which would let a contained bot shake off verification with one ALTER TABLE.
 *
 * @returns {Promise<{ok: boolean, reason: string, row: object|null, def: object|null,
 *                    verification: {ok: boolean, reason: string}}>}
 */
export async function readVerifiedBotDef(db, botId, opts = {}) {
  const row = await selectRow(db, botId);
  if (!row) {
    return { ok: false, reason: "unknown-bot", row: null, def: null, verification: { ok: false, reason: "unknown-bot" } };
  }
  const converted = await eraConvertedFor(db, opts);
  const verdict = verifyBotDefSync(row, { ...opts, converted });
  const ok = verdict.ok;
  const reason = verdict.reason;
  let def = null;
  if (ok) {
    try { def = JSON.parse(row.definition || "{}"); } catch { def = null; }
  }
  return {
    ok,
    reason,
    row,
    def,
    verification: { ok, reason },
  };
}

/**
 * The row content a reseal writes and pins: EXACTLY the columns the MAC covers, COPIED out of the
 * row that verified. A tuple (never the read row itself) so what step 0 verified is a value that
 * cannot change under a later reader — see `resealAllBotDefs`.
 */
function verifiedRowTuple(row, botId) {
  const keep = (key) => (row?.[key] === undefined ? null : row[key]);
  return {
    bot_id: botId,
    definition: keep("definition"),
    enabled: keep("enabled"),
    project_id: keep("project_id"),
    def_mac: keep("def_mac"),
    def_generation: keep("def_generation"),
  };
}

/**
 * Verify EVERY row under the key this process holds, one era read for all of them.
 *
 * This is the check the operator's key reset makes BEFORE it retires the old key (it is the last
 * moment the old MACs can be verified): only the rows it returns as verified may be re-sealed, and
 * the CONTENT it returns for them is what the re-seal writes (`resealAllBotDefs`).
 *
 * `verified` is a list of row TUPLES (`{bot_id, definition, enabled, project_id, def_mac,
 * def_generation}`), not ids: the reset's last step happens after the old key is gone, so it can no
 * longer tell which content was vouched for — the tuples ARE that record. `unverified` stays a list
 * of ids (nothing about an unverified row is ever re-used).
 *
 * @returns {Promise<{verified: Array<{bot_id: string, definition: string|null, enabled: number|null,
 *            project_id: number|null, def_mac: string|null, def_generation: number|null}>,
 *            unverified: string[], rows: Array<{bot_id: string, ok: boolean, reason: string}>}>}
 */
export async function verifyAllBotDefs(db, opts = {}) {
  const out = { verified: [], unverified: [], rows: [] };
  let rows;
  try {
    ({ rows } = await db.execute({ sql: "SELECT * FROM pi_bot_defs", args: [] }));
  } catch {
    return out; // no such table: nothing to verify
  }
  // ONE era decision for every row: the marker/mirror, the secrets-side evidence, and a row in this
  // very table that carries a `def_mac` (`eraConvertedFor` — round C, item E3).
  const converted = await eraConvertedFor(db, opts);
  const era = converted || (await anySealedRow(db));
  for (const row of rows || []) {
    const id = String(row?.bot_id ?? "");
    if (!id) continue;
    // THE REPLAY FLOOR STAYS ON (round C, item E5). A key reset re-seals what a key holder can vouch
    // for NOW; a row at a generation BELOW the recorded one is a replay (an old pair written back),
    // and re-sealing it would bless exactly the rollback the generation exists to refuse.
    const verdict = verifyBotDefSync(row, { ...opts, converted: era });
    out.rows.push({ bot_id: id, ok: verdict.ok, reason: verdict.reason });
    if (verdict.ok) out.verified.push(verifiedRowTuple(row, id));
    else out.unverified.push(id);
  }
  return out;
}

/**
 * Re-seal the rows the operator's key reset VERIFIED UNDER THE RETIRING KEY, bumping each bot's
 * generation — the reset's last step (`scripts/token-hmac.mjs --reset`). Without it, after a key
 * reset every row's MAC belongs to the retired key ("foreign-mac") and no bot could ever spawn
 * again.
 *
 * THE CONTENT IT WRITES IS STEP 0'S CONTENT, NEVER A FRESH READ. `verifiedRows` — REQUIRED — is the
 * list of row TUPLES `verifyAllBotDefs` returned while the OLD key was still loadable
 * (`{bot_id, definition, enabled, project_id, def_mac, def_generation}`). There is deliberately no
 * mode that reads the table and decides for itself what to bless: a re-read here would sign
 * whatever the row holds at THIS moment, so a definition a contained bot rewrote between the two
 * steps would be stamped with the new key although no key holder ever vouched for it. This function
 * therefore never reads a row's content — it reads the ids the table carries, and nothing else.
 *
 * THE RESEAL IS A COMPARE-AND-SWAP ON THE STEP-0 TUPLE. Each UPDATE pins every MAC-covered column
 * of the tuple that verified (`definition IS ? AND enabled IS ? AND project_id IS ? AND def_mac IS ?
 * AND def_generation IS ?`) and writes THAT tuple's content under the new MAC and a freshly planned
 * generation. A row that changed in between (a bot is still running, a peer is still patching) makes
 * the statement land 0 rows: it is left EXACTLY as it is — so it still does not verify, under either
 * key — and its id is reported in `skipped` (with `failed`) for the operator to deal with. A bot in
 * the table whose id is not among `verifiedRows` is reported in `refused` and not touched: a reset
 * is a key change, never an amnesty.
 *
 * A missing `pi_bot_defs` table (a unit-test store, an install with no bots yet) is skipped.
 *
 * @param {{at?: Date, verifiedRows: Array<{bot_id: string, definition: string|null,
 *           enabled: number|null, project_id: number|null, def_mac: string|null,
 *           def_generation: number|null}>, opts?: object}} options `verifiedRows` is what step 0
 *   returned; omitting it is a programming error, never "verify again now".
 * @returns {Promise<{resealed: number, failed: number, refused: string[], skipped: string[]}>}
 * @throws {TypeError} when `verifiedRows` is not an array (there is no verify-again path)
 */
export async function resealAllBotDefs(db, { at = new Date(), verifiedRows, opts = {} } = {}) {
  if (!Array.isArray(verifiedRows)) {
    throw new TypeError(
      "resealAllBotDefs needs verifiedRows: the row tuples verifyAllBotDefs returned under the key being "
      + "retired. A reset never re-reads a row to decide what to bless.",
    );
  }
  const out = { resealed: 0, failed: 0, refused: [], skipped: [] };
  let present;
  try {
    ({ rows: present } = await db.execute({ sql: "SELECT bot_id FROM pi_bot_defs", args: [] }));
  } catch {
    return out; // no such table: nothing to re-seal
  }
  if (!(await sealable(db))) return out; // a store without the columns
  // One tuple per bot: the first one wins (a caller that verified twice hands in the same rows).
  const verified = new Map();
  for (const row of verifiedRows) {
    const id = String(row?.bot_id ?? "");
    if (!id || verified.has(id)) continue;
    verified.set(id, row);
  }
  const presentIds = new Set();
  for (const row of present || []) {
    const id = String(row?.bot_id ?? "");
    if (!id) continue;
    presentIds.add(id);
    if (!verified.has(id)) out.refused.push(id);
  }

  for (const [id, row] of verified) {
    if (!presentIds.has(id)) {
      // The row is gone since step 0: there is nothing to land on, and it is named (E5).
      out.failed += 1;
      out.skipped.push(id);
      continue;
    }
    const { generation, previous } = planBotDefGeneration(id, opts);
    // The content step 0 verified — canonicalised ONCE, because the stored text must be the one the
    // MAC covers (the value is unchanged, so this cannot alter what was vouched for).
    const definition = canonicalDefinitionText(row.definition === undefined ? null : row.definition);
    // What this row's statement will carry, so a throw can be told apart from a write that landed
    // (item J1, `settleIfLanded`). `null` until the MAC is computed: a key failure signed nothing.
    let signed = null;
    try {
      const defMac = macBotDef({
        bot_id: id,
        definition,
        enabled: row.enabled ?? null,
        project_id: row.project_id ?? null,
        def_generation: generation,
      }, opts);
      signed = { def_mac: defMac, generation };
      // eslint-disable-next-line no-await-in-loop -- one row per bot, an operator run
      const res = await db.execute({
        sql: "UPDATE pi_bot_defs SET def_mac=?, def_generation=?, definition=?, updated_at=? WHERE bot_id=?"
          + " AND definition IS ? AND enabled IS ? AND project_id IS ? AND def_mac IS ? AND def_generation IS ?",
        args: [
          defMac, generation, definition, at.toISOString(), id,
          row.definition ?? null, row.enabled ?? null, row.project_id ?? null,
          row.def_mac ?? null, row.def_generation ?? null,
        ],
      });
      if (Number(res && res.rowsAffected) > 0) {
        settleBotDefGeneration(id, generation, opts);
        // F2: the re-sealed row is an approved one — refresh its copy (a failure is logged, never
        // fatal: this is the operator's key reset).
        writeApprovedBotDef({
          bot_id: id, definition, enabled: row.enabled, project_id: row.project_id ?? null, generation,
        }, opts);
        out.resealed += 1;
      } else {
        // The row is not the one step 0 verified: left exactly as it is, and named (E5).
        abandonBotDefGeneration(id, generation, previous, opts);
        out.failed += 1;
        out.skipped.push(id);
      }
    } catch {
      // J1: a statement that threw may still have LANDED (a trigger that aborts keeps the row
      // change). The row carries this row's seal → the re-seal happened, so it settles and counts.
      // eslint-disable-next-line no-await-in-loop -- one row per bot, an operator run
      if (await settleIfLanded(db, id, signed, opts)) {
        writeApprovedBotDef({
          bot_id: id, definition, enabled: row.enabled, project_id: row.project_id ?? null, generation,
        }, opts);
        out.resealed += 1;
      } else {
        abandonBotDefGeneration(id, generation, previous, opts);
        out.failed += 1;
        out.skipped.push(id);
      }
    }
  }
  return out;
}

/**
 * An `execute({sql, args}) -> {rows, rowsAffected}` facade over a better-sqlite3 connection: the
 * shape `writeBotDef` needs, for the operator CLIs and harnesses that hold a synchronous handle.
 * Read statements answer `rows`; anything else answers `rowsAffected` (`changes`).
 */
export function sqliteDbFacade(conn) {
  return {
    execute: async ({ sql, args = [] } = {}) => {
      const statement = conn.prepare(sql);
      if (statement.reader) return { rows: statement.all(...args), rowsAffected: 0 };
      const info = statement.run(...args);
      return { rows: [], rowsAffected: Number(info && info.changes) || 0 };
    },
  };
}

/**
 * `SELECT bot_id, canonical form` for the boot converter's snapshot — exported so the converter
 * hashes exactly what the MAC covers (generation 1), never a re-serialisation of its own.
 */
export { canonicalBotDef, canonicalDefinitionText, verifyBotDef, botDefGenerationsPath, readBotDefGenerations, seedBotDefGenerations, forgetBotDefAlarms };

// Any process that imports the store can serve the bot-loadable write seam — that is the point of
// it (see servers/shared/bot-def-seal.js). The gateway installs it by importing this module in its
// pre-listen bot-def boot; the bridge, by importing it on the spawn path. `verify` is the
// SYNCHRONOUS entry (the era marker read from the secrets side) for a caller that must decide
// inside its own transaction, and for the history restore's captured-version check.
//
// ONE ERA DECISION, THE SAME ONE THE BRIDGE MAKES (round C, items E3/M4). The seam's verify takes
// the evidence its caller scanned — `anyMac` (a sealed row in `pi_bot_defs`), token-mac's own
// `h1ValuesExist`/`mirrorConverted` — plus what the secrets side proves on its own (the marker
// file, the generations file), so a row that lost its `def_mac` COLUMN is refused (`no-mac-column`)
// here exactly as it is at the spawn gate.
installBotDefSeal({
  write: writeBotDef,
  setEnabled: setBotEnabled,
  sign: signBotDef,
  verify: (row, verifyOpts = {}) => {
    const converted = verifyOpts.converted === true || botDefEraConvertedSync(verifyOpts);
    return verifyBotDefSync(row, { ...verifyOpts, converted });
  },
});