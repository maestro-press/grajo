/**
 * THE TRIGGERS CROW INSTALLS — one catalogue, derived from code, used by two guards.
 *
 * A SQLite trigger on a table Crow treats as authority runs INSIDE every write to it, with no code of
 * ours in between: it can rewrite a row after a writer signed it, or swallow a write whole
 * (`RAISE(IGNORE)`) and stash the parameters for a later replay. crow.db is bound read-write into
 * every contained bot, so creating one is a thing a bot can do.
 *
 * So this module answers ONE question from code — "is this trigger one Crow installed, and is its
 * body still the body Crow installs?" — and nothing else. It never drops, disables or rewrites a
 * trigger: naming it is the whole action (see `servers/gateway/boot/trigger-inventory.js` for the
 * whole-database report, and `servers/shared/bot-def-store.js` for the refusal that protects the one
 * writer of `pi_bot_defs`).
 *
 * THE EXPECTED SET, in four parts, each derived rather than copied:
 *   1. HISTORY (`servers/shared/history/covered.js`): `hist_<table>_{ai,au,ad}` per covered item
 *      type, from the same `triggerDefs()` the migration and the boot re-ensure execute, plus the
 *      three append-only guards on `item_versions` (`guardTriggerDefs()`).
 *   2. SCHEMA/FTS (`scripts/init-db.js`): the FTS shadow triggers and the `contact_groups` uid
 *      trigger, lifted out of the file's own SQL text (see `triggerBlocksIn`) with exactly the body
 *      the file creates — a second copy of that SQL here would be free to drift.
 *   3. MAIL (`servers/shared/mail-schema.js`): its `mail_messages_{ai,au,ad}` FTS triggers, same way.
 *   4. BUNDLES: every `bundles/<id>/server/**` file's own CREATE TRIGGER text (the FTS and history
 *      triggers a bundle installs with its tables), same way.
 *
 * "Derived rather than copied" has one honest limitation: a bundle trigger built by JS string
 * interpolation (its source text holds `${…}`) cannot be reconstructed here. Such a trigger is
 * accepted BY NAME ONLY when its table is the one its own source creates (`CREATE TABLE … <table>`
 * in the same file) — i.e. it belongs to that installed bundle, which is the only attribution this
 * catalogue can make without executing the bundle. It says so in `sqlSource: "name-only"`.
 *
 * The comparison is NAME PLUS WHITESPACE-NORMALISED SQL (`normalizeTriggerSql`): SQLite stores the
 * CREATE TRIGGER text verbatim, so a same-named trigger with a different body is a body somebody
 * changed — the exact tamper this catalogue exists to notice.
 */

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { COVERED, guardTriggerDefs, triggerDefs } from "./history/covered.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..");

/** The non-bundle source files whose CREATE TRIGGER text Crow installs itself. */
const SCHEMA_SOURCES = Object.freeze([
  "scripts/init-db.js",
  "servers/shared/mail-schema.js",
]);

/**
 * Two SQLite identifiers name the same table whatever their CASE (`PI_BOT_DEFS` IS `pi_bot_defs`),
 * so every table comparison here is folded (item J2). A guard that compared them verbatim would be
 * bypassed by one capital letter — SQLite keeps `sqlite_master.tbl_name` as it was WRITTEN.
 */
export function sameTableName(a, b) {
  return String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
}

/** Lower-cased table name, the form every comparison here uses. */
const foldTable = (name) => String(name ?? "").toLowerCase();

/** SQL text with every run of whitespace collapsed and no trailing semicolon, for comparison. */
export function normalizeTriggerSql(sql) {
  // `IF NOT EXISTS` is dropped on both sides: SQLite does not keep it in `sqlite_master.sql`, and a
  // trigger created with it is the same trigger as one without.
  return String(sql ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^CREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?/i, "CREATE TRIGGER ")
    .replace(/;\s*$/, "")
    .trim();
}

/**
 * Every `CREATE TRIGGER … END;` block in a JS source file, as `{name, sql}`.
 *
 * The sources this reads keep each trigger's SQL verbatim inside one template literal (only the
 * history module builds its SQL from JS, and it is read through `triggerDefs()` instead), so the
 * block ends at the first `END;`/``END` `` after the CREATE. A body holding a SQL `CASE … END` would
 * confuse that — none of the triggers in these files does, and one that did would simply be reported
 * as body-changed (loud, and dropped by nobody) rather than silently accepted.
 *
 * @param {string} source the file's text
 * @returns {Array<{name: string, table: string|null, sql: string, sqlSource: "source"|"name-only"}>}
 */
export function triggerBlocksIn(source) {
  const out = [];
  const create = /CREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi;
  let match;
  while ((match = create.exec(String(source ?? ""))) !== null) {
    const name = match[1];
    const rest = String(source).slice(match.index);
    // The block ends at the first standalone `END` (a whitespace/semicolon before it, so an identifier
    // that merely contains those letters does not count) — the JS quote or `;` after it is syntax, not
    // SQL, so the slice stops right after `END` itself.
    const end = /[\s;]END\b/i.exec(rest);
    const sql = (end ? rest.slice(0, end.index + end[0].length) : rest).trim();
    // `ON <table>` names the trigger's table when the source writes it literally.
    const onTable = /\bON\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/i.exec(sql);
    // A body built by interpolation cannot be reconstructed here: accept it by name (see the header)
    // only when its table is literal, so the caller can check it belongs to this file's own table.
    const interpolated = sql.includes("${");
    out.push({
      name,
      table: onTable ? onTable[1] : null,
      sql,
      sqlSource: interpolated ? "name-only" : "source",
    });
  }
  return out;
}

/** Every `.js`/`.mjs` file under `dir` (recursively). A missing directory answers []. */
function jsFilesIn(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) jsFilesIn(path, out);
    else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) out.push(path);
  }
  return out;
}

/** The bundle source files that install triggers: every `bundles/<id>/server/**` file. */
function bundleServerSources(root = REPO_ROOT) {
  const bundlesDir = join(root, "bundles");
  let ids;
  try {
    ids = readdirSync(bundlesDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
  const files = [];
  for (const id of ids) files.push(...jsFilesIn(join(bundlesDir, id, "server")));
  return files;
}

/** The tables a source file creates (`CREATE TABLE … <name>`), for the name-only bundle rule. */
function tablesCreatedIn(source) {
  const out = new Set();
  const create = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?([A-Za-z_][A-Za-z0-9_]*)/gi;
  let match;
  while ((match = create.exec(String(source ?? ""))) !== null) out.add(match[1]);
  return out;
}

/**
 * The history layer's triggers for one store: its capture triggers plus the append-only guards.
 * `store` is `"crow"` or `"tasks"` (see `history/covered.js`); both stores get the guards, because
 * each has its own `item_versions` (a SQLite trigger cannot write across databases).
 */
export function historyTriggerDefs(store = "crow") {
  const out = guardTriggerDefs().map((def) => ({
    name: def.name, table: "item_versions", sql: def.sql, sqlSource: "module", source: "history/covered.js (guard)",
  }));
  for (const [itemType, spec] of Object.entries(COVERED)) {
    if ((spec.store || "crow") !== store) continue;
    for (const def of triggerDefs(itemType)) {
      out.push({ name: def.name, table: spec.table, sql: def.sql, sqlSource: "module", source: "history/covered.js" });
    }
  }
  return out;
}

/**
 * Every trigger Crow installs, from code. Freshly derived on each call (a few small file reads), so a
 * long-lived process cannot compare against a catalogue that went stale after an update.
 *
 * @returns {Array<{name: string, table: string|null, sql: string|null, sqlSource: string, source: string}>}
 *   `sql: null` marks a name-only entry (see the header).
 */
export function expectedTriggerDefs({ root = REPO_ROOT } = {}) {
  const defs = [...historyTriggerDefs("crow"), ...historyTriggerDefs("tasks")];
  const read = (rel) => {
    try {
      return readFileSync(join(root, rel), "utf8");
    } catch {
      return "";
    }
  };
  for (const rel of SCHEMA_SOURCES) {
    const source = read(rel);
    for (const block of triggerBlocksIn(source)) {
      defs.push({ ...block, source: rel, sql: block.sqlSource === "source" ? block.sql : null });
    }
  }
  for (const file of bundleServerSources(root)) {
    const source = readFileSync(file, "utf8");
    const created = tablesCreatedIn(source);
    for (const block of triggerBlocksIn(source)) {
      const derived = block.sqlSource === "source";
      // A name-only entry is trusted only when the SAME file creates the trigger's table: that is
      // the "this trigger belongs to that installed bundle" rule in the header.
      const belongsToThisBundle = !derived && block.table !== null && created.has(block.table);
      if (!derived && !belongsToThisBundle) continue;
      defs.push({
        ...block,
        source: file.slice(root.length + 1),
        sql: derived ? block.sql : null,
        sqlSource: derived ? "source" : "name-only",
      });
    }
  }
  return defs;
}

/**
 * The expected set as `Map<name, {table, sql, sqlSource, source}>`. A duplicate name keeps the first
 * entry, which is the history/schema one (the order `expectedTriggerDefs` returns).
 */
export function expectedTriggerIndex(opts = {}) {
  const index = new Map();
  for (const def of expectedTriggerDefs(opts)) {
    if (!def?.name || index.has(def.name)) continue;
    index.set(def.name, {
      table: def.table ?? null,
      sql: def.sql === null || def.sql === undefined ? null : normalizeTriggerSql(def.sql),
      sqlSource: def.sqlSource ?? "source",
      source: def.source ?? "",
    });
  }
  return index;
}

/**
 * Every trigger Crow installs on ONE table (`pi_bot_defs` is the one the store guards). The table
 * comparison is case-insensitive (item J2): the caller's name and the catalogue's are both SQLite
 * identifiers, and `UPPER(table)` names the same table.
 */
export function expectedTriggersOnTable(table, opts = {}) {
  const index = new Map();
  const wanted = foldTable(table);
  for (const [name, def] of expectedTriggerIndex(opts)) {
    if (foldTable(def.table) === wanted) index.set(name, def);
  }
  return index;
}

/**
 * Every trigger Crow installs on any of `tables`, merged into one `Map` (name → entry) — the shape
 * `unexpectedTriggers` reads. `tables` holds names in any case (item J2).
 */
export function expectedTriggersOnTables(tables, opts = {}) {
  const index = new Map();
  for (const table of tables || []) {
    for (const [name, def] of expectedTriggersOnTable(table, opts)) index.set(name, def);
  }
  return index;
}

/**
 * Every table a trigger BODY writes: `INSERT [OR …] INTO <table>`, `REPLACE INTO <table>`,
 * `UPDATE [OR …] <table> SET …`, `DELETE FROM <table>`. Lower-cased names, deduplicated.
 *
 * A read (`SELECT … FROM <table>`, which the append-only guards use in their WHEN) is not a write:
 * the guards raise and write nothing, so they add no table to the reachable set.
 *
 * @param {string} sql the trigger's CREATE text
 * @returns {Set<string>} the tables its body writes
 */
export function writtenTablesIn(sql) {
  const out = new Set();
  const text = String(sql ?? "");
  const patterns = [
    /\bINSERT\s+(?:OR\s+[A-Za-z]+\s+)?INTO\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
    /\bREPLACE\s+INTO\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
    // `… SET` after the name: a trigger's own `BEFORE UPDATE ON <table>` must not read as a write.
    /\bUPDATE\s+(?:OR\s+[A-Za-z]+\s+)?["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?\s+SET\b/gi,
    /\bDELETE\s+FROM\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) out.add(foldTable(match[1]));
  }
  return out;
}

/**
 * Every table ONE write to `table` can reach through Crow's OWN triggers, transitively, plus
 * `table` itself — lower-cased (item J2).
 *
 * The set is DERIVED from the catalogue, never copied: a trigger Crow installs on `pi_bot_defs`
 * (the history capture triggers) writes `item_versions`, and `item_versions` carries its own Crow
 * triggers (the append-only guards), so both tables are in the set. A trigger on a table this
 * write reaches runs INSIDE the statement and can raise after the row change was made (SQLite's
 * `RAISE(FAIL)` keeps it) or swallow it — which is why the store's refusal covers them all, not
 * just the table it is writing.
 *
 * @param {string} table the table being written (`pi_bot_defs`)
 * @returns {Set<string>}
 */
export function reachableTriggerTables(table, opts = {}) {
  const index = expectedTriggerIndex(opts);
  const seen = new Set([foldTable(table)]);
  const queue = [...seen];
  while (queue.length) {
    const current = queue.shift();
    for (const def of index.values()) {
      if (foldTable(def.table) !== current) continue;
      if (!def.sql) continue; // a name-only entry has no derivable body
      for (const written of writtenTablesIn(def.sql)) {
        if (seen.has(written)) continue;
        seen.add(written);
        queue.push(written);
      }
    }
  }
  return seen;
}

/** One trigger row as the comparison reads it (`name`, the table it fires on, its stored SQL). */
const asTriggerRow = (row) => ({
  name: String(row?.name ?? ""),
  table: String(row?.tbl_name ?? row?.table ?? ""),
  sql: row?.sql === null || row?.sql === undefined ? "" : String(row.sql),
});

/**
 * The legacy knowledge-base 1.0.2 `hsds_services` full-text-index triggers. Their bodies only maintain
 * `hsds_services_fts`. Reviewed by hand: add entries here only after reviewing the body, NEVER by
 * reading a bundle file (a bundle directory is easier to write than this repo, so a derived list would
 * let a planted file whitelist itself). An entry matches only on name, table (any case) AND the sha256
 * of `normalizeTriggerSql(stored sql)`.
 */
export const REVIEWED_LEGACY_TRIGGERS = Object.freeze([
  { name: "hsds_services_ad", table: "hsds_services", sha256: "210323c12764a28a6141185abc8f4425ef0299c01ee63f6b9f22bc14e2a1befc" },
  { name: "hsds_services_ai", table: "hsds_services", sha256: "cc9a56d11d69b45ee6411c47fc0cc27e6e2d72f040e18b71ff545452a567e877" },
  { name: "hsds_services_au", table: "hsds_services", sha256: "56835866eef3d73b958caf0d183cbdea1bd7cf3d6426c67cca328d1e4d13b735" },
]);

/** sha256 (hex) of a trigger's normalised SQL. */
export function triggerSqlHash(sql) {
  return createHash("sha256").update(normalizeTriggerSql(sql)).digest("hex");
}

/** "ok" for exactly a reviewed legacy trigger, "body-changed" for its name+table with another body, else null. */
function reviewedLegacyStatus(trigger) {
  const entry = REVIEWED_LEGACY_TRIGGERS.find((e) => e.name === trigger.name);
  if (!entry || !sameTableName(entry.table, trigger.table)) return null;
  return entry.sha256 === triggerSqlHash(trigger.sql) ? "ok" : "body-changed";
}

/**
 * Which of `rows` Crow did NOT install, or whose body is no longer the body Crow installs.
 *
 * @param {Array<{name: string, tbl_name?: string, sql?: string}>} rows `sqlite_master` rows
 * @param {Map<string, {table: string|null, sql: string|null}>} expected `expectedTriggerIndex()`
 * @returns {Array<{name: string, table: string, reason: "foreign"|"body-changed"}>}
 */
export function unexpectedTriggers(rows, expected) {
  const out = [];
  for (const row of rows || []) {
    const trigger = asTriggerRow(row);
    if (!trigger.name) continue;
    const def = expected.get(trigger.name);
    if (!def) {
      const legacy = reviewedLegacyStatus(trigger);
      if (legacy === "ok") continue;
      out.push({ name: trigger.name, table: trigger.table, reason: legacy || "foreign" });
      continue;
    }
    // A name-only entry has no derivable body, so the NAME alone is not enough to accept it (item
    // J3): the row must still be the trigger the entry describes — the same table (any case) and a
    // body that says `ON <table>`. A same-named trigger moved to another table, or one whose body no
    // longer names its own table, is reported like any other trigger Crow did not install.
    if (def.sql === null) {
      const wantedTable = foldTable(def.table);
      // A quoted identifier is the same table: `ON "kb_articles"` and `ON kb_articles` agree.
      const quoted = "[\"'`]?";
      const ownBody = new RegExp(
        `\\bON\\s+${quoted}${escapeRegExp(String(def.table ?? ""))}${quoted}(?![A-Za-z0-9_])`,
        "i",
      );
      if (!wantedTable || foldTable(trigger.table) !== wantedTable) {
        out.push({ name: trigger.name, table: trigger.table, reason: "foreign" });
        continue;
      }
      if (!ownBody.test(trigger.sql)) {
        out.push({ name: trigger.name, table: trigger.table, reason: "body-changed" });
      }
      continue;
    }
    if (normalizeTriggerSql(trigger.sql) !== def.sql) {
      out.push({ name: trigger.name, table: trigger.table, reason: "body-changed" });
    }
  }
  return out;
}

/** A literal string as a regex that matches it verbatim. */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The SELECT that lists one database's triggers (main schema and the connection's temp schema). */
export const TRIGGER_ROWS_SQL = "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger'"
  + " UNION ALL SELECT name, tbl_name, sql FROM sqlite_temp_master WHERE type = 'trigger'";

/**
 * Read every trigger of one database through a Crow db client (`{execute}`).
 *
 * A store that cannot answer (a fixture without a schema, a read failure) answers the throws-and-
 * caught shape `{rows: [], error}` — the caller decides whether "cannot tell" means refuse.
 *
 * @returns {Promise<{rows: Array<object>, error: Error|null}>}
 */
export async function readTriggerRows(db) {
  try {
    const { rows } = await db.execute({ sql: TRIGGER_ROWS_SQL, args: [] });
    return { rows: Array.isArray(rows) ? rows : [], error: null };
  } catch (error) {
    return { rows: [], error };
  }
}