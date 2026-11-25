/**
 * ONE writer for `pi_bot_defs` — a source guard.
 *
 * A bot definition is AUTHORITY (`tools.crow_mcp`, `permission_policy`, `write_paths`,
 * `project_id`, remote servers), and a contained bot has crow.db bound read-write. So every row
 * carries a keyed MAC over its whole definition plus a replay generation (see
 * `servers/shared/bot-def-mac.js`), and a write that sets the definition WITHOUT re-signing it
 * leaves a row the spawn gate refuses — a bot that can never run again, or worse, one whose
 * definition changed without anyone noticing.
 *
 * That makes the write a chokepoint: `servers/shared/bot-def-store.js` (`writeBotDef` /
 * `setBotEnabled` / `signBotDef`), reached from a bot-loadable module through the import-free seam
 * `servers/shared/bot-def-seal.js`. This test fails on any other literal writer, so a new call
 * site cannot be added silently.
 *
 * The allow-list is deliberately tiny and each entry is a REASON:
 *   - `servers/shared/bot-def-store.js`  — the writer itself;
 *   - `scripts/init-db.js`               — schema only (no DML on rows);
 *   - `servers/gateway/boot/bot-def-mac.js` — the converter's one transaction, which must set
 *     generation 1 on rows that have none yet (`WHERE def_generation IS NULL`), a condition the
 *     store's CAS vocabulary deliberately does not express;
 *   - `scripts/pi-bots/skill_promote.mjs` — a better-sqlite3 BEGIN IMMEDIATE transaction in a
 *     bot-loadable module (it cannot import the store), so it signs through the seam
 *     (`signBotDefSealed`) and writes def_mac + def_generation in the same statement.
 *
 * Rows are also DELETED in places (delete-bot, erase); that is not a definition write and needs no
 * MAC, so DELETEs are out of scope here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

/** A directory the guard never descends into: dependencies and test fixtures (neither ships code). */
const SKIP_DIRS = new Set(["node_modules", ".git", "test", "tests", "__tests__"]);

/** Every `.js`/`.mjs` file under `dir` (no node_modules, no test trees). */
function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) out.push(path);
  }
  return out;
}

/** Comments blanked (strings kept): a prose mention of a statement is not a writer. */
function code(src) {
  let out = "";
  let i = 0;
  let mode = null;
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (mode === null) {
      if (c === "/" && next === "/") { mode = "line"; out += "  "; i += 2; continue; }
      if (c === "/" && next === "*") { mode = "block"; out += "  "; i += 2; continue; }
      if (c === '"' || c === "'" || c === "`") mode = c;
      out += c;
      i += 1;
      continue;
    }
    if (mode === "line") { if (c === "\n") { mode = null; out += c; } else out += " "; i += 1; continue; }
    if (mode === "block") {
      if (c === "*" && next === "/") { mode = null; out += "  "; i += 2; continue; }
      out += c === "\n" ? "\n" : " ";
      i += 1;
      continue;
    }
    out += c;
    if (c === "\\") { out += next ?? ""; i += 2; continue; }
    if (c === mode) mode = null;
    i += 1;
  }
  return out;
}

/** A literal DML statement against pi_bot_defs (INSERT / REPLACE / UPDATE, any quoting). */
const WRITER = /\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|REPLACE\s+INTO|UPDATE)\s+["'`]?pi_bot_defs\b/i;

/** The files allowed to write a `pi_bot_defs` row directly, each with its reason. */
const ALLOWED = Object.freeze({
  "servers/shared/bot-def-store.js":
    "the one writer: it sets definition + def_mac + def_generation in one statement.",
  "scripts/init-db.js":
    "schema only — no DML against pi_bot_defs rows.",
  "servers/gateway/boot/bot-def-mac.js":
    "the pre-listen converter's one transaction: `SET def_generation = 1, def_mac = ? WHERE … AND " +
    "def_generation IS NULL`, the anti-laundering CAS the store's caller-facing vocabulary omits.",
  "scripts/pi-bots/skill_promote.mjs":
    "a bot-loadable module (scripts/pi-bots/**) with its own BEGIN IMMEDIATE transaction, so it " +
    "signs through the seam (signBotDefSealed) and sets def_mac + def_generation in the same " +
    "statement as the definition.",
});

test("no literal pi_bot_defs writer outside the one writer (and the four reasoned exceptions)", () => {
  const files = [
    ...walk(join(ROOT, "servers")),
    ...walk(join(ROOT, "scripts")),
    ...walk(join(ROOT, "bundles")),
  ];
  const offenders = [];
  for (const file of files) {
    const rel = relative(ROOT, file).split("\\").join("/");
    const src = code(readFileSync(file, "utf8"));
    const m = WRITER.exec(src);
    if (!m) continue;
    if (Object.prototype.hasOwnProperty.call(ALLOWED, rel)) continue;
    const line = src.slice(0, m.index).split("\n").length;
    offenders.push(`${rel}:${line}: ${src.split("\n")[line - 1].trim().slice(0, 120)}`);
  }
  assert.deepEqual(
    offenders,
    [],
    "a pi_bot_defs row carries a keyed MAC over its whole definition (servers/shared/bot-def-mac.js), "
    + "so the definition, def_mac and def_generation must be written in ONE statement: call "
    + "writeBotDef / setBotEnabled from servers/shared/bot-def-store.js (a bot-loadable module: "
    + "through servers/shared/bot-def-seal.js), or add a reasoned entry to ALLOWED. Offenders: "
    + offenders.join(" | "),
  );
});

test("the allow-list cannot rot: each entry still holds a writer, and the store is the only one with a MAC", () => {
  for (const [rel, reason] of Object.entries(ALLOWED)) {
    assert.ok(reason.length > 40, `${rel}: the entry carries a reason`);
    const src = code(readFileSync(join(ROOT, rel), "utf8"));
    if (rel === "scripts/init-db.js") {
      assert.equal(WRITER.test(src), false, "init-db.js is schema only: it must not write a row");
      continue;
    }
    assert.ok(WRITER.test(src), `${rel} is on the allow-list but no longer writes pi_bot_defs: delete the entry`);
  }
  // The converter and skill promotion both set the MAC in their own statement; a bare
  // `SET definition=?` there would be a stale MAC.
  for (const rel of ["servers/gateway/boot/bot-def-mac.js", "scripts/pi-bots/skill_promote.mjs"]) {
    assert.ok(/def_mac/.test(readFileSync(join(ROOT, rel), "utf8")), `${rel} writes the MAC too`);
  }
});

test("the store is the only module that mints a bot-definition MAC, and it is host-only", () => {
  const store = readFileSync(join(ROOT, "servers/shared/bot-def-store.js"), "utf8");
  assert.ok(/macBotDef\(/.test(store), "the store signs what it writes");
  assert.ok(/writeBotDef\(/.test(store) && /setBotEnabled\(/.test(store), "and is the writer");
  for (const file of [...walk(join(ROOT, "scripts", "pi-bots")), ...walk(join(ROOT, "bundles"))]) {
    const src = readFileSync(file, "utf8");
    if (!/macBotDef\(|planBotDefGeneration\(/.test(src)) continue;
    assert.fail(`${relative(ROOT, file)} mints or counts a bot-definition MAC outside the store: `
      + "bot-loadable code reaches the write through servers/shared/bot-def-seal.js only");
  }
  // The seam itself holds nothing: no imports, so it can sit on a bot's load path.
  const seal = readFileSync(join(ROOT, "servers/shared/bot-def-seal.js"), "utf8");
  assert.equal(/^\s*import\s/m.test(seal), false, "servers/shared/bot-def-seal.js imports nothing");
});

test("the version-history restore signs a bot definition instead of writing it bare", () => {
  const api = readFileSync(join(ROOT, "servers/shared/history/api.js"), "utf8");
  assert.ok(/signBotDefSealed\(/.test(api), "the generic restore asks the seam for the MAC");
  assert.ok(/def_mac = \?/.test(api) && /def_generation = \?/.test(api), "and adds both to its own UPDATE");
});

// ─── round D, item F1: every partial write states the row it read ────────────

/** The text between a call's `(` and its matching `)` (string literals skipped). */
function callArgs(src, openIndex) {
  let depth = 0;
  let i = openIndex;
  let quote = null;
  for (; i < src.length; i += 1) {
    const c = src[i];
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "(") depth += 1;
    else if (c === ")") {
      depth -= 1;
      if (depth === 0) return src.slice(openIndex + 1, i);
    }
  }
  return src.slice(openIndex + 1);
}

/** Files allowed to call a writer without stating `expect*`, each with its reason. */
const EXPECT_EXEMPT = Object.freeze({
  "servers/shared/bot-def-store.js":
    "the chokepoint itself: setBotEnabled/setBotProjectId forward the caller's options, and the rule "
    + "is enforced inside writeBotDef (BOT_DEF_EXPECT_REQUIRED).",
});

const WRITE_CALL = /\b(writeBotDef|writeBotDefSealed|setBotEnabled|setBotEnabledSealed|setBotProjectId)\s*\(/g;

/**
 * F1 (round D): every partial write states the exact row it read. A call is exempt only when it is
 * an INSERT (`mode: "insert"` — a create takes nothing from a row), an `ownerFullReplace` full-form
 * save (it supplies the whole MAC-covered content itself), or a pure forward of a caller's `args`
 * (a wrapper that cannot state them itself, whose real call site in the same file must). Anything
 * else must name `expectDefinition`, `expectEnabled` and `expectProjectId`, or the store will throw
 * `BOT_DEF_EXPECT_REQUIRED` at runtime.
 */
test("every partial bot-definition write states the row it read (expectDefinition/expectEnabled/expectProjectId)", () => {
  const files = [
    ...walk(join(ROOT, "servers")),
    ...walk(join(ROOT, "scripts")),
    ...walk(join(ROOT, "bundles")),
  ];
  const offenders = [];
  for (const file of files) {
    const rel = relative(ROOT, file).split("\\").join("/");
    if (Object.prototype.hasOwnProperty.call(EXPECT_EXEMPT, rel)) continue;
    const src = code(readFileSync(file, "utf8"));
    WRITE_CALL.lastIndex = 0;
    let m;
    while ((m = WRITE_CALL.exec(src)) !== null) {
      // A DEFINITION, not a call: `function writeBotDef(`, `export async function setBotEnabled(`…
      const before = src.slice(Math.max(0, m.index - 40), m.index);
      if (/function\s+$/.test(before) || /=\s*$/.test(before)) continue;
      const args = callArgs(src, m.index + m[0].length - 1);
      if (/ownerFullReplace/.test(args)) continue;
      if (/mode:\s*["']insert["']/.test(args)) continue;
      if (/^(?:db,\s*)?args$/.test(args.trim())) continue; // a pure forward (defaultWriteDef)
      const missing = ["expectDefinition", "expectEnabled", "expectProjectId"].filter((name) => !args.includes(name));
      if (!missing.length) continue;
      const line = src.slice(0, m.index).split("\n").length;
      offenders.push(`${rel}:${line}: ${m[1]}(…) is missing ${missing.join(", ")}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    "a partial write must state the row it read (expectDefinition + expectEnabled + expectProjectId: "
    + "the store refuses with `caller-read-differs` when they are not the row it verified, and throws "
    + "BOT_DEF_EXPECT_REQUIRED when they are absent). Exempt: an INSERT, an ownerFullReplace full-form "
    + `save, and the chokepoint itself. Offenders: ${offenders.join(" | ")}`,
  );
});
/**
 * RAW READERS of `pi_bot_defs` that are reported, not verified, each with the reason a raw read is
 * acceptable there. (Not an exhaustive census of every read — it names the readers a review found
 * and judged; a reader that gates AUTHORITY must go through readVerifiedBotDef / verifyBotRows.)
 */
const RAW_READER_INVENTORY = Object.freeze({
  "servers/gateway/routes/mail-drafts-api.js":
    "lists enabled bots as drafting CANDIDATES from definition + project_id; the choice only picks whose "
    + "drafting rules to show, and the draft itself is made through the verified path at send time.",
  "servers/gateway/routes/streams.js":
    "reads a bot's tracker_config to label a stream view for the operator; display only, the row never "
    + "grants a tool, a path or a project to anything.",
  "servers/gateway/make/sources.js":
    "reads project_id only to pick which project's sources a Make job lists; the project is then "
    + "membership-checked on its own, so a raised project_id on the bot row opens nothing by itself.",
  "servers/memory/summary-recall.js":
    "reads the bot's default model only to RANK a summary candidate (cloud or local); a ranking input "
    + "that grants no authority, and an unverified row can at most reorder candidates.",
});

test("the raw pi_bot_defs readers an authority review judged are inventoried, each with a reason", () => {
  for (const [rel, reason] of Object.entries(RAW_READER_INVENTORY)) {
    assert.ok(reason.length > 40, `${rel}: the entry carries a reason`);
    const src = code(readFileSync(join(ROOT, rel), "utf8"));
    assert.ok(/FROM\s+pi_bot_defs/i.test(src), `${rel} still reads pi_bot_defs raw (remove the entry if it no longer does)`);
    assert.ok(!WRITER.test(src), `${rel} is a reader, never a writer`);
  }
});
