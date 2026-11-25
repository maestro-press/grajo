#!/usr/bin/env node
/**
 * `bot-def-reapprove` — the operator's way back for an ordinary bot that Crow refuses as
 * unverified.
 *
 * A `pi_bot_defs` row carries a keyed MAC over its whole definition plus a replay generation
 * (`servers/shared/bot-def-mac.js`), and every authority reader refuses a row it cannot verify (the
 * spawn gate, the voice turn, the storage door, the share decisions, …). Until this command there was
 * no recovery path for a bot that does not have a page in Bot Builder: "open it in Bot Builder and
 * save it" only ever worked for the bots that do. A definition changed outside Crow — a bot editing its
 * own row, a hand-edited crow.db, a restored backup whose generation file went back in time — left the
 * bot refused with nothing to run.
 *
 * Two steps, because the operator must SEE what they are approving:
 *
 *   node scripts/cli/bot-def-reapprove.mjs <bot_id> --show
 *       The verification reason today, then a FIELD-LEVEL diff of the stored row against the last
 *       APPROVED copy (`<CROW_HOME>/secrets/bot-def-approved/<bot_id>.json`, written by every
 *       successful sealed write), and a DIGEST: the FULL 64-character `sha256(canonicalBotDef(row))`
 *       hex — the same canonical form the MAC covers, so the digest names EXACTLY the content
 *       (bot id, definition, enabled, project_id, generation) the operator read. `--approve` takes
 *       that full value and nothing else (a truncated digest names a prefix, not the content).
 *
 *       The diff lists EVERY top-level definition key plus `enabled` and `project_id` as unchanged /
 *       changed / added / removed, prints a line diff of the pretty JSON for each changed key, and
 *       marks the AUTHORITY fields with `!!` (tools, permission_policy, write_paths, read_paths,
 *       project_id, enabled, spawn_env, gateways, models, engine, session_dir, skills, triggers,
 *       voice). Values of keys that look like a credential (`*token*`, `*secret*`, `*key*`,
 *       `*password*`) inside `spawn_env`/`gateways` are never printed: the line says
 *       `<redacted, changed>` or `<redacted, unchanged>` instead. A bot with no approved copy (created
 *       before this feature) prints its whole stored definition and the line
 *       `no previous approved version`.
 *
 *   node scripts/cli/bot-def-reapprove.mjs <bot_id> --approve <digest>
 *       Re-seals exactly that content, and nothing else: the row must still hash to <digest> (it is
 *       a compare-and-swap on the whole row, so a bot that wrote to the row between `--show` and
 *       `--approve` gets "it changed since --show, look again" and nothing is written). The write goes
 *       through the ONE writer (`writeBotDef`, `ownerFullReplace`: the whole MAC-covered content is
 *       supplied by this command, so nothing is taken from the row), which also refreshes the
 *       approved copy, and one `audit_log` row records who approved which digest.
 *
 * CONTROL AND INVISIBLE CHARACTERS. A bot id, a definition KEY and every value in the row is text a
 * bot wrote (a contained bot has crow.db bound read-write), so printing it straight to a terminal
 * would let it move the cursor (ESC/cursor sequences), repaint lines (CR, backspace), reorder what
 * the operator reads (bidi overrides) — or hide in plain sight inside an ordinary-looking line
 * (any Unicode SEPARATOR or FORMAT character: a no-break space, an em space, a zero-width joiner, a
 * language tag character, a line separator). So EVERY bot-derived string this command prints goes
 * through `safeText()`, which escapes ONE class — the Unicode categories Cc, Cf, Zl, Zp and Zs plus
 * the historic invisible few — as a visible `\uXXXX` (BMP) or `\u{XXXXX}` (astral) escape, with plain
 * U+0020 space left alone because it is what ordinary text is made of. When the stored row holds such
 * a character at all, `--show` also prints a loud WARNING and `--approve` REFUSES unless the operator
 * adds `--allow-control-chars`: the digest then names content whose shape they could only see escaped.
 *
 *   node scripts/cli/bot-def-reapprove.mjs <bot_id> --approve <digest> --allow-control-chars
 *
 * ONE LINE PER FORGED LINE, TOO (item I6). Everything printed from the row is ALSO prefixed with
 * `| `, so a line the operator sees at the start of the output is provably the command's own (the
 * controlled sentences — the warning, the usage block — stay unprefixed, and a bot-derived line never
 * begins at column 0). A definition that is not valid JSON is rendered on ONE line with its newlines
 * escaped, so a corrupt row cannot spill into lines that look like the command's.
 *
 * Nothing here decides whether a bot may run: re-approving is the owner's statement that the stored
 * definition is the one they want. A bot whose row cannot be written at all (a `pi_bot_defs` that lost
 * its `def_mac` column, an unusable token-mac key) is refused with the reason, and the fix for those is
 * `npm run init-db` / `node scripts/token-hmac.mjs --reset`.
 *
 * THIS IS THE CLI HALF, ON PURPOSE. A dashboard "re-approve this bot" page (a button on the Bot
 * Builder card, in plain operator words instead of a shell command) is a later, owner-facing UI item;
 * this command is the documented way out today, and the `[bot-def] … could not be verified` log line
 * names it.
 *
 * Same conventions as `scripts/cli/local-model-pin.js`: this instance's `CROW_HOME` decides the
 * instance (`resolveCrowHome()`, which refuses to guess under a test runner), the database is the
 * instance's own crow.db, and `main()` takes every dependency as a parameter so a test can run it
 * in-process.
 *
 * Usage:
 *   node scripts/cli/bot-def-reapprove.mjs <bot_id> --show
 *   node scripts/cli/bot-def-reapprove.mjs <bot_id> --approve <digest> [--allow-control-chars]
 */
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

import { createDbClient, auditLog } from "../../servers/db.js";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import {
  BOT_DEF_UNVERIFIED, canonicalBotDef, readVerifiedBotDef, writeBotDef,
} from "../../servers/shared/bot-def-store.js";
import { readApprovedBotDef } from "../../servers/shared/bot-def-approved.js";

/**
 * The definition keys that carry AUTHORITY: a change to one of these changes what the bot may do, so
 * `--show` flags it with `!!`. Kept in this file (not in the store) because it is a display rule.
 */
export const SECURITY_FIELDS = Object.freeze([
  "tools", "permission_policy", "write_paths", "read_paths", "project_id", "enabled",
  "spawn_env", "gateways", "models", "engine", "session_dir", "skills", "triggers", "voice",
]);

const SECURITY = new Set(SECURITY_FIELDS);

/** A key whose VALUE must never be printed (a credential, by name). */
const SENSITIVE_KEY = /token|secret|key|password/i;

/** The definition keys whose values are redacted leaf-by-leaf by `--show`. */
const REDACTED_CONTAINERS = new Set(["spawn_env", "gateways"]);

const REDACTED_CHANGED = "<redacted, changed>";
const REDACTED_SAME = "<redacted, unchanged>";

/**
 * The ONE character class that must never reach the operator's terminal raw: the Unicode FORMAT
 * characters (Cc controls — an ESC sequence can move the cursor or repaint a line, `\r` can overwrite
 * the line just read, `\b` can un-type it, `\u009b` is a C1 CSI — Cf invisible formatting, including
 * the bidi overrides and every tag character, and Zl/Zp line and paragraph separators) and the
 * Unicode SPACE separators (a no-break space, an em space, an ideographic space: a line that looks
 * like two words and is one token). The historic invisibles (`\u00ad`, `\u034f`, `\u180e`) are listed
 * explicitly so an engine that classifies one of them differently still escapes it.
 *
 * PLAIN U+0020 SPACE IS NOT IN IT: it is not a hidden character, it is what ordinary text is made of,
 * so every regex below carries `(?![ ])` in front of the class.
 */
const UNSAFE_CLASS = "[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\p{Zs}\\u00ad\\u034f\\u180e]";
const UNSAFE_SOURCE = `(?![ ])${UNSAFE_CLASS}`;
const UNSAFE_CHAR = new RegExp(UNSAFE_SOURCE, "u");
const UNSAFE_CHAR_ALL = new RegExp(UNSAFE_SOURCE, "gu");

/**
 * The same class for the inside of a VALUE, minus the two characters that are ORDINARY TEXT there: a
 * multi-line `system_prompt` really does hold `\n` (and `\t`), and JSON prints both as escapes, so
 * neither can spoof a line. A control or separator that is NOT a line break or a tab is a different
 * matter, and a KEY holding either is inspected with the full class (`anyUnsafe`).
 */
const UNSAFE_VALUE_SOURCE = `(?![ \\n\\t])${UNSAFE_CLASS}`;
const UNSAFE_VALUE_CHAR = new RegExp(UNSAFE_VALUE_SOURCE, "u");

/** The loud `--show` line, and the reason `--approve` needs `--allow-control-chars`. */
export const CONTROL_CHARS_WARNING =
  "WARNING: this definition contains control or invisible characters (shown escaped); review carefully";

/** One escaped code point: `\uXXXX` in the BMP, `\u{XXXXX}` above it. */
function escapeChar(ch) {
  const cp = ch.codePointAt(0);
  return cp <= 0xffff ? `\\u${cp.toString(16).padStart(4, "0")}` : `\\u{${cp.toString(16)}}`;
}

/**
 * One bot-derived string, made safe to print: every character of the unsafe class becomes a visible
 * escape (`\uXXXX` in the BMP, `\u{XXXXX}` above it), so what the operator reads is what the row
 * holds (a `\n` is escaped too: a caller that wants real line breaks splits the text first —
 * `safeLines`).
 *
 * @param {unknown} value
 * @returns {string}
 */
export function safeText(value) {
  return String(value ?? "").replace(UNSAFE_CHAR_ALL, escapeChar);
}

/** Multi-line text printed line by line: real line breaks stay line breaks, each line is escaped. */
export function safeLines(value) {
  return String(value ?? "").split("\n").map((line) => safeText(line));
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function anyUnsafe(text) {
  return UNSAFE_CHAR.test(String(text ?? ""));
}

function unsafeInValues(value) {
  if (typeof value === "string") return UNSAFE_VALUE_CHAR.test(value);
  if (Array.isArray(value)) return value.some((item) => unsafeInValues(item));
  if (isPlainObject(value)) {
    return Object.entries(value).some(([k, v]) => anyUnsafe(k) || unsafeInValues(v));
  }
  return false;
}

/**
 * Does anything the operator is about to read — a key, a string value, the bot id, or a raw control
 * character inside the stored text — hide a character that can spoof a terminal? Checked on the row
 * rather than on the printed output, because a JSON escape in the stored TEXT (`"\u001b[31m"`) only
 * becomes an ESC when it is parsed, and the diff prints the parsed form.
 *
 * @param {object|null} row a `pi_bot_defs` row
 * @returns {boolean}
 */
export function rowHasUnsafeChars(row) {
  if (!row) return false;
  if (anyUnsafe(row.bot_id ?? "") || anyUnsafe(row.display_name ?? "")) return true;
  if (UNSAFE_VALUE_CHAR.test(String(row.definition ?? ""))) return true;
  const parsed = definitionObject(row.definition ?? null);
  return parsed ? unsafeInValues(parsed) : false;
}

/** The stored text as the object a diff can walk (a non-JSON definition is compared as raw text). */
function definitionObject(text) {
  if (text == null) return {};
  try {
    const value = JSON.parse(text);
    return isPlainObject(value) ? value : null;
  } catch {
    return null;
  }
}

/** Every sensitive leaf of one value replaced by a fixed marker (no comparison possible). */
function redactSolo(value) {
  if (Array.isArray(value)) return value.map(redactSolo);
  if (!isPlainObject(value)) return value;
  // A NULL-PROTOTYPE object on purpose: a bot can name a key `__proto__` (crow.db is bot-writable), and
  // `out["__proto__"] = …` on an ordinary object sets the PROTOTYPE instead of an own property — the
  // key would silently vanish from what the operator is shown.
  const out = Object.create(null);
  for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEY.test(k) ? REDACTED_CHANGED : redactSolo(v);
  return out;
}

/**
 * Two values with every credential-named leaf replaced by `<redacted, changed>`/`<redacted,
 * unchanged>`. Index/key alignment is kept where both sides have it, so the LINE DIFF of the
 * redacted pair still shows what changed without ever printing a value.
 */
function redactPair(stored, approved) {
  if (Array.isArray(stored) && Array.isArray(approved)) {
    const n = Math.max(stored.length, approved.length);
    const s = [];
    const a = [];
    for (let i = 0; i < n; i += 1) {
      if (i >= stored.length) { a.push(redactSolo(approved[i])); continue; }
      if (i >= approved.length) { s.push(redactSolo(stored[i])); continue; }
      const [rs, ra] = redactPair(stored[i], approved[i]);
      s.push(rs);
      a.push(ra);
    }
    return [s, a];
  }
  if (Array.isArray(stored) || Array.isArray(approved)) return [redactSolo(stored), redactSolo(approved)];
  if (isPlainObject(stored) || isPlainObject(approved)) {
    const so = isPlainObject(stored) ? stored : {};
    const ao = isPlainObject(approved) ? approved : {};
    // Null-prototype objects, and OWN properties only: a row can carry a `__proto__` key (a bot writes
    // crow.db), and a plain `s["__proto__"] = …` would set the prototype and drop the key from the
    // diff. `Object.keys`/`hasOwnProperty` never pick up an inherited name, so the key is shown
    // (redacted when it looks like a credential) instead of disappearing.
    const s = Object.create(null);
    const a = Object.create(null);
    for (const k of new Set([...Object.keys(so), ...Object.keys(ao)])) {
      const hasS = Object.prototype.hasOwnProperty.call(so, k);
      const hasA = Object.prototype.hasOwnProperty.call(ao, k);
      if (SENSITIVE_KEY.test(k)) {
        const same = hasS === hasA && JSON.stringify(so[k]) === JSON.stringify(ao[k]);
        if (hasS) s[k] = same ? REDACTED_SAME : REDACTED_CHANGED;
        if (hasA) a[k] = same ? REDACTED_SAME : REDACTED_CHANGED;
        continue;
      }
      const [rs, ra] = redactPair(so[k], ao[k]);
      if (hasS) s[k] = rs;
      if (hasA) a[k] = ra;
    }
    return [s, a];
  }
  return [stored, approved];
}

/**
 * A unified line diff of two pretty-printed JSON texts: `  ` unchanged, `- ` only in the approved
 * copy, `+ ` only in the stored row. Long inputs fall back to the two blocks (no LCS explosion).
 */
export function lineDiff(approvedText, storedText) {
  const a = String(approvedText).split("\n");
  const b = String(storedText).split("\n");
  if (a.length * b.length > 4_000_000) {
    return [
      "--- approved", ...a.map((l) => `- ${l}`),
      "+++ stored", ...b.map((l) => `+ ${l}`),
    ];
  }
  const lcs = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { out.push(`  ${a[i]}`); i += 1; j += 1; } else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push(`- ${a[i]}`); i += 1; } else { out.push(`+ ${b[j]}`); j += 1; }
  }
  for (; i < a.length; i += 1) out.push(`- ${a[i]}`);
  for (; j < b.length; j += 1) out.push(`+ ${b[j]}`);
  return out;
}

/** Pretty JSON of one value, or its raw text when it is not JSON. */
function prettyJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const STATUS = Object.freeze({ same: "unchanged", changed: "changed", added: "added", removed: "removed" });

/**
 * The FIELD-LEVEL diff `--show` prints: one line per top-level definition key plus `enabled` and
 * `project_id`, marked `!!` when the key carries authority, then a line diff for everything that
 * moved. Exported so a test can pin the wording without a database.
 *
 * @param {{definition: string|null, enabled?: number|boolean|null, project_id?: number|null}} row
 * @param {{definition: string|null, enabled?: number|null, project_id?: number|null}} approved
 * @returns {string[]} the lines, without a trailing newline
 */
export function approvedDiffLines(row, approved) {
  const storedDef = definitionObject(row?.definition ?? null);
  const approvedDef = definitionObject(approved?.definition ?? null);
  const entries = [];

  if (storedDef && approvedDef) {
    const keys = [...new Set([...Object.keys(approvedDef), ...Object.keys(storedDef)])].sort();
    for (const key of keys) {
      const hasS = Object.prototype.hasOwnProperty.call(storedDef, key);
      const hasA = Object.prototype.hasOwnProperty.call(approvedDef, key);
      if (!hasA) entries.push({ key, status: STATUS.added, stored: storedDef[key], approved: undefined });
      else if (!hasS) entries.push({ key, status: STATUS.removed, stored: undefined, approved: approvedDef[key] });
      else if (JSON.stringify(storedDef[key]) !== JSON.stringify(approvedDef[key])) {
        entries.push({ key, status: STATUS.changed, stored: storedDef[key], approved: approvedDef[key] });
      } else entries.push({ key, status: STATUS.same, stored: storedDef[key], approved: approvedDef[key] });
    }
  } else {
    // A definition that is not a JSON object cannot be walked key by key: compare the raw texts.
    const same = String(row?.definition ?? "") === String(approved?.definition ?? "");
    entries.push({ key: "definition", status: same ? STATUS.same : STATUS.changed, stored: row?.definition ?? null, approved: approved?.definition ?? null, raw: true });
  }

  const storedEnabled = row?.enabled == null ? null : Number(row.enabled) ? 1 : 0;
  const approvedEnabled = approved?.enabled == null ? null : Number(approved.enabled) ? 1 : 0;
  entries.push({
    key: "enabled",
    status: storedEnabled === approvedEnabled ? STATUS.same : STATUS.changed,
    stored: storedEnabled,
    approved: approvedEnabled,
  });
  const storedProject = row?.project_id == null ? null : Number(row.project_id);
  const approvedProject = approved?.project_id == null ? null : Number(approved.project_id);
  entries.push({
    key: "project_id",
    status: storedProject === approvedProject ? STATUS.same : STATUS.changed,
    stored: storedProject,
    approved: approvedProject,
  });

  const lines = [];
  // A key is bot-written text: it is printed ESCAPED, and the column width is measured on what is
  // actually printed (an ESC is one character in the row and six in the output).
  const shownKeys = new Map(entries.map((entry) => [entry, safeText(entry.key)]));
  const width = Math.max(...entries.map((entry) => shownKeys.get(entry).length)) + 2;
  lines.push("changes since the approved version (stored row vs approved copy):");
  for (const entry of entries) {
    const flag = SECURITY.has(entry.key) ? "!!" : "  ";
    lines.push(`  ${flag} ${shownKeys.get(entry).padEnd(width)}${entry.status}`);
  }
  const moved = entries.filter((e) => e.status !== STATUS.same);
  for (const entry of moved) {
    lines.push("");
    const flag = SECURITY.has(entry.key) ? "!! " : "";
    lines.push(`  ${flag}${shownKeys.get(entry)} (${entry.status}):`);
    let [left, right] = [entry.approved, entry.stored];
    if (!entry.raw && REDACTED_CONTAINERS.has(entry.key)) [left, right] = redactPair(entry.approved, entry.stored);
    const leftText = entry.approved === undefined ? "" : prettyJson(left);
    const rightText = entry.stored === undefined ? "" : prettyJson(right);
    for (const line of lineDiff(leftText, rightText)) lines.push(`    ${safeText(line)}`);
  }
  return lines;
}

const USAGE = `Usage:
  node scripts/cli/bot-def-reapprove.mjs <bot_id> --show
  node scripts/cli/bot-def-reapprove.mjs <bot_id> --approve <digest> [--allow-control-chars]`;

/**
 * The digest of one row's MAC-covered content: the FULL `sha256(canonicalBotDef(row))` hex (64
 * characters). `canonicalBotDef` is the MAC's own input, so the digest and the MAC always describe the
 * same bytes — a row whose digest is unchanged is a row with the same bot id,
 * definition, `enabled`, `project_id` and generation. The whole hash on purpose (item I4): a shortened
 * digest names a prefix, not one content.
 */
export function digestOfRow(row) {
  return createHash("sha256").update(canonicalBotDef(row)).digest("hex");
}

/**
 * A stored definition as the lines `--show` prints when there is no approved copy to diff against:
 * valid JSON is pretty-printed one line per line (JSON escapes its own controls, so no line can
 * forge another), and a definition that is NOT valid JSON is ONE line with every newline escaped
 * (item I6) — a corrupt row must never spill into lines that read like the command's own.
 */
function prettyDefinitionLines(text) {
  if (text == null) return ["null"];
  try {
    return JSON.stringify(JSON.parse(text), null, 2).split("\n");
  } catch {
    return [safeText(String(text))];
  }
}

/** The `--approve` digest: a FULL sha256 hex value, and nothing shorter. */
const DIGEST_RE = /^[0-9a-f]{64}$/i;

/**
 * Run the CLI. Returns the exit code: 0 ok, 1 refused or bad input.
 * Every dependency is a parameter so a test can run it in-process.
 *
 * EVERY line printed from bot-derived content is prefixed with `| ` (item I6): the fixed sentences
 * (the control-character warning, the usage block) start at column 0, so a line the operator sees at
 * column 0 is the command's own words and never a row's.
 */
export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = (s) => stdout.write(s);
  /** One output line: `bot: true` marks content derived from the stored row, and prefixes it. */
  const line = (text, { bot = false } = {}) => out(`${bot ? "| " : ""}${text}\n`);
  const fail = (s, { bot = false } = {}) => { stderr.write(`${bot ? "| " : ""}${s}\n`); return 1; };

  if (argv.includes("--help") || argv.includes("-h")) { out(`${USAGE}\n`); return 0; }

  const flags = { show: false, approve: null, allowControlChars: false, rest: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = String(argv[i]);
    if (arg === "--show") { flags.show = true; continue; }
    if (arg === "--allow-control-chars") { flags.allowControlChars = true; continue; }
    if (arg === "--approve") { flags.approve = String(argv[i + 1] ?? "").trim(); i += 1; continue; }
    if (arg.startsWith("--approve=")) { flags.approve = arg.slice("--approve=".length).trim(); continue; }
    flags.rest.push(arg);
  }
  const botId = String(flags.rest[0] ?? "").trim();
  if (!botId || flags.rest.length > 1) return fail(`give exactly one bot id\n${USAGE}`);
  if (flags.show === Boolean(flags.approve)) return fail(`give --show or --approve <digest>, not both\n${USAGE}`);
  if (flags.approve !== null && !DIGEST_RE.test(flags.approve)) {
    return fail(`--approve needs the full digest --show printed (64 hex characters)\n${USAGE}`);
  }

  // Fails with CROW_HOME_REQUIRED_IN_TESTS under `node --test` when this instance's home would
  // silently resolve to a real ~/.crow. The path is printed nowhere: it names a private host layout.
  let home;
  try {
    home = resolveCrowHome();
  } catch (err) {
    return fail(String((err && err.message) || err));
  }
  if (!home) return fail("CROW_HOME could not be resolved (set it to this instance's home)");

  const db = createDbClient();
  try {
    const read = await readVerifiedBotDef(db, botId);
    if (!read.row) return fail(`no bot "${safeText(botId)}" is stored in this instance`, { bot: true });
    const digest = digestOfRow(read.row);
    // Does the row hold a character that can spoof a terminal? Decided on the ROW (keys, values, the
    // stored text), and it changes what --show says and whether --approve is even allowed.
    const unsafe = rowHasUnsafeChars(read.row);

    if (flags.show) {
      // FIRST, so a spoofed key further down cannot be the first thing read as if it were fine. It is
      // the command's own sentence, so it carries no `| ` prefix: a bot-derived line can never look
      // like it.
      if (unsafe) out(`${CONTROL_CHARS_WARNING}\n`);
      line(`bot:          ${safeText(botId)}`, { bot: true });
      line(`enabled:      ${read.row.enabled == null ? "null" : Number(read.row.enabled) ? "1 (on)" : "0 (off)"}`, { bot: true });
      line(`project_id:   ${read.row.project_id == null ? "none" : Number(read.row.project_id)}`, { bot: true });
      line(`verification: ${read.ok ? `verified (${safeText(read.reason)})` : `REFUSED — ${safeText(read.reason)}`}`, { bot: true });
      out("\n");
      // F2: the FIELD-LEVEL diff against the last approved copy, so the operator can see what the row
      // holds that they never approved (a bot editing its own row, a hand edit, a restore).
      const approved = readApprovedBotDef(botId);
      if (!approved.content) {
        line("no previous approved version", { bot: true });
        // Valid JSON: one prefixed line per pretty-printed line. Not valid JSON: ONE line with its
        // newlines escaped (item I6), so a corrupt row cannot spill into lines that look like the
        // command's own.
        line("stored definition:", { bot: true });
        for (const emitted of prettyDefinitionLines(read.row.definition)) line(safeText(emitted), { bot: true });
        out("\n");
      } else {
        if (approved.corrupt) line("the approved copy could not be read back; showing the stored content instead", { bot: true });
        for (const emitted of approvedDiffLines(read.row, approved.content)) {
          if (emitted === "") out("\n");
          else line(emitted, { bot: true });
        }
        out("\n");
      }
      line(`digest:       ${digest}`, { bot: true });
      line(
        `to re-approve exactly this content: node scripts/cli/bot-def-reapprove.mjs ${safeText(botId)} `
        + `--approve ${digest}${unsafe ? " --allow-control-chars" : ""}`,
        { bot: true },
      );
      return 0;
    }

    // ── --approve ──
    // A row holding a control or invisible character is approved only when the operator SAYS so, and
    // only after a --show that showed those characters escaped: the digest names content whose true
    // shape cannot be seen in a terminal.
    if (unsafe && !flags.allowControlChars) {
      return fail(
        `${CONTROL_CHARS_WARNING}\n`
        + `| bot "${safeText(botId)}" holds a control or invisible character; nothing was written. `
        + "Run --show, read the \\uXXXX escapes carefully, then add --allow-control-chars to approve it anyway.",
      );
    }
    // A compare-and-swap on the WHOLE row: the digest the operator read is the digest of the row as it
    // is now, and the write below pins the same content, so nothing a bot wrote in between survives.
    if (digest !== flags.approve.toLowerCase()) {
      return fail(
        `bot "${safeText(botId)}" changed since that digest was printed (now ${digest}, not ${flags.approve}). `
        + "Run --show again and approve what is stored now.",
        { bot: true },
      );
    }
    let written;
    try {
      written = await writeBotDef(db, {
        bot_id: botId,
        definition: read.row.definition ?? null,
        enabled: read.row.enabled,
        project_id: read.row.project_id ?? null,
        display_name: read.row.display_name ?? botId,
        ownerFullReplace: true,
        expectDefinition: read.row.definition ?? null,
        expectEnabled: read.row.enabled,
        expectProjectId: read.row.project_id ?? null,
        expectDisplayName: read.row.display_name ?? null,
      });
    } catch (err) {
      if (err && err.code === BOT_DEF_UNVERIFIED) {
        return fail(`bot "${safeText(botId)}" could not be re-sealed (${safeText(err.reason || err.message || "unknown reason")}); nothing was written`, { bot: true });
      }
      throw err;
    }
    if (Number(written && written.rowsAffected) === 0) {
      return fail(`bot "${safeText(botId)}" changed while it was being re-approved; nothing was written. Run --show again.`, { bot: true });
    }
    // The audit line: who approved what, at which generation (ids and a hash, never content), and —
    // when it took the extra flag — that the row held control/invisible characters.
    try {
      await auditLog(db, "bot_def.reapprove", {
        actor: "operator-cli",
        details: {
          bot_id: botId, digest, generation: written.generation ?? null, ...(unsafe ? { allow_control_chars: true } : {}),
        },
      });
    } catch { /* an audit failure never reports a write that landed as a failure */ }
    if (unsafe) out(`${CONTROL_CHARS_WARNING}\n`);
    if (unsafe) line(`approved it anyway (--allow-control-chars): ${safeText(botId)} at ${digest}`, { bot: true });
    line(`re-approved ${safeText(botId)} at ${digest} (generation ${written.generation ?? "?"})`, { bot: true });
    return 0;
  } finally {
    try { db.close(); } catch { /* closed */ }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`FAIL: ${err?.message || err}`);
    process.exit(1);
  });
}