/**
 * The APPROVED COPY of a bot definition, and the recovery diff `bot-def-reapprove --show` prints
 * (round D, item F2).
 *
 * A refused bot definition is whatever a bot (or a hand edit) left in the row, so "what changed?"
 * is the one question the operator's way back has to answer. Every successful SEALED write therefore
 * drops the content it just approved into `<CROW_HOME>/secrets/bot-def-approved/<bot_id>.json`
 * (`servers/shared/bot-def-approved.js`), and `--show` diffs the stored row against it field by
 * field, flags the AUTHORITY fields with `!!`, and never prints a credential-named value.
 *
 * This file pins:
 *   - the copy written by every sealed write path (writeBotDef insert + update, setBotEnabled, the
 *     key-reset reseal, the boot converter's TOFU seal), owner-only (dir 0700, file 0600);
 *   - a copy that cannot be written never failing the database write;
 *   - the field-level diff (changed/added/removed/unchanged, `!!` on a security field, the line diff);
 *   - credential redaction inside spawn_env/gateways;
 *   - the no-copy path (the whole stored content and `no previous approved version`);
 *   - the bot-id filename refusal, and the copy going away with the bot;
 *   - borrowed text is never printed raw (round F3): a key or value holding a terminal escape, a C1
 *     control or a bidi override is shown as a visible `\uXXXX`, `--show` says so loudly and
 *     `--approve` refuses without `--allow-control-chars`.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createDbClient } from "../servers/db.js";
import { forgetTokenMacKey, tokenMacKeyPath } from "../servers/shared/token-mac.js";
import { forgetBotDefAlarms } from "../servers/shared/bot-def-mac.js";
import { setBotEnabled, resealAllBotDefs, verifyAllBotDefs, writeBotDef, readVerifiedBotDef } from "../servers/shared/bot-def-store.js";
import {
  botDefApprovedDir, botDefApprovedPath, forgetApprovedBotDef, readApprovedBotDef, writeApprovedBotDef,
} from "../servers/shared/bot-def-approved.js";
import { runBotDefMacBoot } from "../servers/gateway/boot/bot-def-mac.js";
import {
  approvedDiffLines, CONTROL_CHARS_WARNING, main as reapproveMain, rowHasUnsafeChars, safeText,
  SECURITY_FIELDS,
} from "../scripts/cli/bot-def-reapprove.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const roots = [];
const SAVED = {};
for (const key of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"]) SAVED[key] = process.env[key];
after(() => {
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  for (const [key, value] of Object.entries(SAVED)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** A fresh scratch instance with the REAL schema (init-db), every in-process cache forgotten. */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-botdef-approved-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  forgetTokenMacKey();
  forgetBotDefAlarms();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return { home, db, close: () => { try { db.close(); } catch { /* closed */ } } };
}

const DEF = {
  system_prompt: "you help",
  tools: { crow_mcp: ["crow-memory"] },
  permission_policy: { write_paths: ["~/a"] },
};

async function createBot(db, botId, definition = DEF) {
  const res = await writeBotDef(db, {
    bot_id: botId, display_name: botId, definition, enabled: 1, project_id: null, mode: "insert",
  });
  assert.equal(res.rowsAffected, 1);
  return res;
}

async function rowOf(db, botId) {
  const { rows } = await db.execute({ sql: "SELECT * FROM pi_bot_defs WHERE bot_id=?", args: [botId] });
  return rows[0] || null;
}

const mode = (path) => statSync(path).mode & 0o777;

// ─── the copy on every sealed write path ──────────────────────────────────

test("F2: every sealed write leaves an owner-only approved copy", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "keeper");
    // The directory is derived from the key path's own directory, 0700; the file is 0600.
    assert.equal(botDefApprovedDir(), join(join(tokenMacKeyPath(), ".."), "bot-def-approved"));
    assert.equal(mode(botDefApprovedDir()), 0o700, "the copy directory is owner-only");
    const first = readApprovedBotDef("keeper");
    assert.equal(first.exists, true, "the INSERT left a copy");
    assert.equal(first.corrupt, false);
    assert.equal(mode(botDefApprovedPath("keeper")), 0o600, "the copy file is owner-only");
    assert.equal(first.content.bot_id, "keeper");
    assert.equal(first.content.enabled, 1);
    assert.equal(first.content.project_id, null);
    assert.deepEqual(JSON.parse(first.content.definition), DEF);
    assert.ok(Number.isSafeInteger(first.content.generation), "the copy names the generation it approved");

    // An UPDATE (setBotEnabled is a partial, re-signed write) refreshes it.
    const before = await rowOf(s.db, "keeper");
    await setBotEnabled(s.db, "keeper", 0, {
      expectDefinition: before.definition,
      expectEnabled: before.enabled,
      expectProjectId: before.project_id ?? null,
    });
    const off = readApprovedBotDef("keeper");
    assert.equal(off.content.enabled, 0, "the toggle is in the copy");
    assert.equal(off.content.generation, Number((await rowOf(s.db, "keeper")).def_generation));

    // …and so does the operator key reset's reseal (it writes the rows step 0 verified).
    const check = await verifyAllBotDefs(s.db);
    const resealed = await resealAllBotDefs(s.db, { verifiedRows: check.verified });
    assert.equal(resealed.resealed, 1);
    const after = readApprovedBotDef("keeper");
    assert.equal(after.content.generation, Number((await rowOf(s.db, "keeper")).def_generation),
      "the reseal's generation is the approved one");
  } finally {
    s.close();
  }
});

test("F2: the boot converter's TOFU seal is an approved write too", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id) VALUES ('early','Early',?,1,NULL)",
      args: [JSON.stringify(DEF)],
    });
    const out = await runBotDefMacBoot({ db: s.db });
    assert.equal(out.count, 1);
    const copy = readApprovedBotDef("early");
    assert.equal(copy.exists, true, "the row the conversion sealed has a copy");
    assert.equal(copy.content.generation, 1);
    assert.deepEqual(JSON.parse(copy.content.definition), DEF);
  } finally {
    s.close();
  }
});

test("F2: a copy that cannot be written never fails the database write", async () => {
  const s = scratch();
  try {
    // A path under a FILE: mkdir fails, the write fails, and the row must still land.
    const broken = join(process.env.CROW_DB_PATH, "nested");
    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    let res;
    try {
      res = await writeBotDef(s.db, {
        bot_id: "copyfail", definition: DEF, enabled: 1, project_id: null, mode: "insert",
        opts: { approvedDir: broken },
      });
      // A second write logs nothing more: ONE line per bot per process.
      await writeBotDef(s.db, {
        bot_id: "copyfail", definition: { ...DEF, system_prompt: "again" }, enabled: 1, project_id: null,
        expectDefinition: JSON.stringify(DEF), expectEnabled: 1, expectProjectId: null,
        opts: { approvedDir: broken },
      });
    } finally { console.warn = realWarn; }
    assert.equal(res.rowsAffected, 1, "the row landed despite the copy failure");
    assert.equal(warns.filter((m) => m.includes("approved copy")).length, 1, "and it is ONE line for this bot");
  } finally {
    s.close();
  }
});

test("F2: the copy goes away with the bot, and an unstorable bot id is refused (never a path escape)", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "doomed");
    assert.equal(readApprovedBotDef("doomed").exists, true);
    assert.equal(forgetApprovedBotDef("doomed"), true);
    assert.equal(readApprovedBotDef("doomed").exists, false, "a deleted bot leaves no copy to diff a new one against");
    assert.equal(forgetApprovedBotDef("doomed"), false, "nothing left to remove");

    // The file name is built from the bot id, so anything that is not plainly an id is refused.
    for (const bad of ["../escape", "a/b", "with space", "..", ".", "", "x".repeat(300)]) {
      assert.equal(botDefApprovedPath(bad), null, `${JSON.stringify(bad)} is not a storable bot id`);
      const wrote = writeApprovedBotDef({ bot_id: bad, definition: DEF, enabled: 1, project_id: null, generation: 1 });
      assert.equal(wrote.ok, false);
      assert.equal(wrote.reason, "bot-id");
      assert.deepEqual(readApprovedBotDef(bad), {
        path: null, exists: false, corrupt: false, content: null,
      });
    }
    // Nothing appeared beside the real copies (no `escape.json`, no dotted name).
    const names = readdirSync(botDefApprovedDir());
    assert.deepEqual(names, [], `only the removed bot's copy ever lived here, got ${names.join(", ")}`);
  } finally {
    s.close();
  }
});

// ─── the diff `--show` prints ─────────────────────────────────────────────

const approvedOf = (definition, extra = {}) => ({
  definition: JSON.stringify(definition), enabled: 1, project_id: null, generation: 1, ...extra,
});

test("F2: the diff reports every field, and flags a changed security field with !!", () => {
  const approved = approvedOf(DEF);
  const stored = {
    definition: JSON.stringify({
      system_prompt: "you help",
      tools: { crow_mcp: ["crow-memory", "sharing/crow_send_message"] },
      permission_policy: { write_paths: ["/"] },
      brand_new_key: "added by a bot",
    }),
    enabled: 0,
    project_id: 7,
  };
  const text = approvedDiffLines(stored, approved).join("\n");
  assert.match(text, /system_prompt\s+unchanged/, "an untouched key is listed as unchanged");
  assert.match(text, /!! tools\s+changed/, "a changed AUTHORITY field is flagged");
  assert.match(text, /!! permission_policy\s+changed/);
  assert.match(text, /brand_new_key\s+added/, "a key the approved copy never had is added");
  assert.match(text, /!! enabled\s+changed/);
  assert.match(text, /!! project_id\s+changed/);
  // The line diff of a changed key is there, with both sides.
  assert.match(text, /[+-]\s*"sharing\/crow_send_message"/);
  assert.match(text, /-\s*"~\/a"/);
  assert.match(text, /^\s*\+\s*"\/"$/m);
  assert.deepEqual([...SECURITY_FIELDS].filter((f) => !["tools", "permission_policy", "enabled", "project_id"].includes(f)).length, 10,
    "the flagged list is the one the operator was promised");

  // A key that only the approved copy has is reported removed.
  const removed = approvedDiffLines(
    { definition: JSON.stringify({ system_prompt: "you help" }), enabled: 1, project_id: null },
    approvedOf({ ...DEF, triggers: [{ on: "mail" }] }),
  ).join("\n");
  assert.match(removed, /triggers\s+removed/);
});

test("F2: a credential-named value inside spawn_env/gateways is never printed", () => {
  const approved = approvedOf({
    ...DEF,
    spawn_env: { GITHUB_TOKEN: "approved-copy-secret-1", PATH: "/usr/bin" },
    gateways: [{ type: "discord", token: "discord-token-in-approved-copy", channel: "#old" }],
  });
  const stored = {
    definition: JSON.stringify({
      ...DEF,
      spawn_env: { GITHUB_TOKEN: "stored-row-secret-1", PATH: "/usr/bin" },
      gateways: [{ type: "discord", token: "discord-token-in-approved-copy", channel: "#new" }],
    }),
    enabled: 1,
    project_id: null,
  };
  const text = approvedDiffLines(stored, approved).join("\n");
  assert.equal(text.includes("approved-copy-secret-1"), false, "the approved token is not printed");
  assert.equal(text.includes("stored-row-secret-1"), false, "the stored token is not printed");
  assert.match(text, /<redacted, changed>/, "a changed secret says so instead of showing it");
  // The gateways field DID change (its channel), and its unchanged secret is still never printed.
  assert.match(text, /!! gateways\s+changed/);
  assert.equal(text.includes("discord-token-in-approved-copy"), false);
  assert.match(text, /<redacted, unchanged>/);
  assert.match(text, /\+\s*"channel": "#new"/);
});

test("F2: with no approved copy --show prints the whole stored content and says so", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "old");
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='old'", args: [JSON.stringify({ ...DEF, system_prompt: "changed by a bot" })] });
    // A bot created before this feature has no copy.
    assert.equal(forgetApprovedBotDef("old"), true);
    const out = [];
    const err = [];
    const io = () => ({ stdout: { write: (x) => out.push(String(x)) }, stderr: { write: (x) => err.push(String(x)) } });
    assert.equal(await reapproveMain({ argv: ["old", "--show"], ...io() }), 0, err.join(""));
    const shown = out.join("");
    assert.match(shown, /no previous approved version/);
    assert.ok(shown.includes('"changed by a bot"'), "the operator still sees the whole stored definition");
    assert.match(shown, /verification:\s+REFUSED — mac-mismatch/);
    assert.match(shown, /digest:\s+[0-9a-f]{64}/);

    // And with a copy there, the same command diffs instead (no full dump, no "no previous" line).
    await reapproveMain({ argv: ["old", "--approve", /digest:\s+([0-9a-f]{64})/.exec(shown)[1]], ...io() });
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='old'", args: [JSON.stringify({ ...DEF, system_prompt: "changed again" })] });
    out.length = 0;
    assert.equal(await reapproveMain({ argv: ["old", "--show"], ...io() }), 0);
    const diffed = out.join("");
    assert.equal(diffed.includes("no previous approved version"), false);
    assert.match(diffed, /system_prompt\s+changed/);
    assert.match(diffed, /[+-]\s*"changed again"/);
  } finally {
    s.close();
  }
});

// ─── borrowed text: nothing bot-written reaches the terminal raw ──────────

/** ESC (clear the screen) and RLO (a right-to-left override): both reprinted as visible escapes. */
const ESC_KEY = "sys\u001b[2Jtem";
const BIDI_KEY = "tools\u202e";

test("F3: a key holding a terminal escape or a bidi override is printed escaped, never raw", () => {
  const approved = approvedOf({
    [ESC_KEY]: "old", [BIDI_KEY]: { crow_mcp: ["crow-memory"] }, system_prompt: "you help",
  });
  const stored = {
    definition: JSON.stringify({
      [ESC_KEY]: "new",
      [BIDI_KEY]: { crow_mcp: ["crow-memory", "crow-secrets"] },
      system_prompt: "you help\u202e hidden",
    }),
    enabled: 1,
    project_id: null,
  };
  const text = approvedDiffLines(stored, approved).join("\n");

  // Nothing raw reaches the terminal: no ESC, no RLO, no zero-width space.
  for (const ch of ["\u001b", "\u202e", "\u200b", "\u009b", "\r", "\b", "\ufeff"]) {
    assert.equal(text.includes(ch), false, `no raw ${safeText(ch)} in the --show output`);
  }
  // …and the escapes ARE visible, in the key list and in the changed-key headings AND in the diff.
  assert.ok(text.includes("sys\\u001b[2Jtem"), "the ESC key is shown as \\u001b");
  assert.ok(text.includes("tools\\u202e"), "the bidi key is shown as \\u202e");
  assert.ok(text.includes("you help\\u202e hidden"), "a value's bidi override is escaped too");
  assert.match(text, /sys\\u001b\[2Jtem\s+changed/, "the key list line is the escaped one");
  assert.match(text, /sys\\u001b\[2Jtem \(changed\):/, "so is the changed-key heading");

  // The one function every bot-derived string goes through.
  assert.equal(safeText("a\u001bb"), "a\\u001bb");
  assert.equal(safeText("\u202e"), "\\u202e");
  assert.equal(safeText("\u009b"), "\\u009b", "a C1 CSI is escaped");
  assert.equal(safeText("\r\b\u0000\u007f"), "\\u000d\\u0008\\u0000\\u007f");
  assert.equal(safeText("\ufeff\u200b\u2066\u061c"), "\\ufeff\\u200b\\u2066\\u061c");
  assert.equal(safeText("plain text, no escapes"), "plain text, no escapes", "ordinary text is untouched");

  // The WARNING decision is made on the row: a parsed-value escape counts, an ordinary multi-line
  // system prompt does not (JSON prints its line breaks as escapes, so it cannot spoof anything).
  assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: stored.definition }), true);
  assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: JSON.stringify({ system_prompt: "line one\nline two\tindented" }) }), false,
    "a multi-line prompt is not a hidden-character definition");
  assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: JSON.stringify({ [ESC_KEY]: 1 }) }), true,
    "an ESC in a KEY is only visible once the text is parsed");
  assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: JSON.stringify(DEF) }), false);
});

test("F3: --show warns about hidden characters, and --approve needs --allow-control-chars", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "spooky");
    const evil = { system_prompt: "you help", [ESC_KEY]: "clear the screen", note: "abc\u202edef" };
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='spooky'", args: [JSON.stringify(evil)] });
    // No approved copy: --show prints the whole stored definition (the safeLines path).
    assert.equal(forgetApprovedBotDef("spooky"), true);

    const out = [];
    const err = [];
    const io = () => ({ stdout: { write: (x) => out.push(String(x)) }, stderr: { write: (x) => err.push(String(x)) } });
    assert.equal(await reapproveMain({ argv: ["spooky", "--show"], ...io() }), 0, err.join(""));
    const shown = out.join("");
    assert.ok(shown.startsWith(`${CONTROL_CHARS_WARNING}\n`), "the warning is the first line the operator reads");
    assert.ok(shown.includes("sys\\u001b[2Jtem"), "the ESC key is shown escaped");
    assert.ok(shown.includes("abc\\u202edef"), "the bidi override is shown escaped");
    assert.equal(shown.includes("\u001b"), false, "nothing raw is printed");
    assert.equal(shown.includes("\u202e"), false);
    assert.match(shown, /--allow-control-chars/, "and it names the flag the approval will need");
    const digest = /digest:\s+([0-9a-f]{64})/.exec(shown)[1];
    const before = (await rowOf(s.db, "spooky")).definition;

    // Without the flag: refused, nothing written, the reason names the flag.
    out.length = 0;
    assert.equal(await reapproveMain({ argv: ["spooky", "--approve", digest], ...io() }), 1);
    assert.ok(err.join("").includes(CONTROL_CHARS_WARNING));
    assert.ok(err.join("").includes("--allow-control-chars"));
    assert.equal((await rowOf(s.db, "spooky")).definition, before, "the row is untouched");
    assert.equal((await readVerifiedBotDef(s.db, "spooky")).ok, false, "nothing was re-sealed");

    // With the flag: exactly the content --show printed, hidden characters and all.
    err.length = 0;
    assert.equal(
      await reapproveMain({ argv: ["spooky", "--approve", digest, "--allow-control-chars"], ...io() }),
      0, err.join(""),
    );
    const read = await readVerifiedBotDef(s.db, "spooky");
    assert.equal(read.ok, true, "the approved row verifies");
    assert.equal(read.def[ESC_KEY], "clear the screen", "the escaped key is stored as the character it was");
    assert.equal(read.def.note, "abc\u202edef");

    // A definition with no hidden characters still approves with no flag and no warning.
    await createBot(s.db, "plain", { system_prompt: "you help\nand you help again" });
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='plain'", args: [JSON.stringify({ ...DEF, system_prompt: "changed by a bot" })] });
    out.length = 0;
    assert.equal(await reapproveMain({ argv: ["plain", "--show"], ...io() }), 0);
    const calm = out.join("");
    assert.equal(calm.includes(CONTROL_CHARS_WARNING), false, "no warning for ordinary content");
    assert.equal(calm.includes("--allow-control-chars"), false);
    assert.equal(await reapproveMain({ argv: ["plain", "--approve", /digest:\s+([0-9a-f]{64})/.exec(calm)[1]], ...io() }), 0);
  } finally {
    s.close();
  }
});

// ─── round I: the Unicode class, the one-line render, the forged-line prefix ──

/** The invisible/separator characters item I5 names explicitly, plus one from each category. */
const NBSP = "\u00a0";       // Zs — a no-break space
const EM_SPACE = "\u2003";   // Zs — an em space
const WORD_JOINER = "\u2060"; // Cf
const TAG_CHAR = "\u{e0041}"; // Cf, astral (a Unicode tag character)
const LINE_SEP = "\u2028";   // Zl

test("I5: the Cc/Cf/Zl/Zp/Zs class is escaped for keys, values and diff lines (plain space is not)", () => {
  const key = `note${NBSP}key`;
  const approved = approvedOf({
    [key]: `a${EM_SPACE}b`,
    system_prompt: `one${WORD_JOINER}two`,
    tag: `x${TAG_CHAR}y`,
    sep: `l${LINE_SEP}r`,
  });
  const stored = {
    definition: JSON.stringify({
      [key]: `a${EM_SPACE}b changed`,
      system_prompt: `one${WORD_JOINER}two changed`,
      tag: `x${TAG_CHAR}y changed`,
      sep: `l${LINE_SEP}r changed`,
    }),
    enabled: 1,
    project_id: null,
  };
  const text = approvedDiffLines(stored, approved).join("\n");

  // Nothing raw reaches the terminal — not from a key, a value line or a diff line.
  for (const ch of [NBSP, EM_SPACE, WORD_JOINER, TAG_CHAR, LINE_SEP]) {
    assert.equal(text.includes(ch), false, `no raw ${safeText(ch)} in the --show output`);
  }
  // …and each is shown as an escape: `\uXXXX` in the BMP, `\u{XXXXX}` above it.
  assert.ok(text.includes(`note\\u00a0key`), "the no-break space in a key is escaped");
  assert.ok(text.includes(`a\\u2003b`), "an em space in a value is escaped");
  assert.ok(text.includes(`one\\u2060two`), "a word joiner in a value is escaped");
  assert.ok(text.includes(`x\\u{e0041}y`), "an astral tag character is escaped as \\u{XXXXX}");
  assert.ok(text.includes(`l\\u2028r`), "a line separator in a value is escaped");

  // The escaping function itself: the class, the astral form, and the plain-space carve-out.
  assert.equal(safeText("plain text, one space"), "plain text, one space", "U+0020 is ordinary text");
  assert.equal(safeText(`${NBSP}${EM_SPACE}`), "\\u00a0\\u2003");
  assert.equal(safeText(TAG_CHAR), "\\u{e0041}");
  assert.equal(safeText(LINE_SEP), "\\u2028");
  assert.equal(safeText("\u00ad\u034f\u180e"), "\\u00ad\\u034f\\u180e", "the historic invisibles are escaped too");

  // The warning gate is the same class: each of these makes the row "unsafe" (an ordinary multi-line
  // prompt still does not, because JSON prints its line breaks as escapes).
  for (const ch of [NBSP, EM_SPACE, WORD_JOINER, TAG_CHAR, LINE_SEP]) {
    assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: JSON.stringify({ system_prompt: `a${ch}b` }) }), true,
      `a row holding ${safeText(ch)} is unsafe`);
  }
  assert.equal(rowHasUnsafeChars({ bot_id: "x", definition: JSON.stringify({ system_prompt: "line one\nline two\tindented" }) }), false,
    "a multi-line prompt is still not a hidden-character definition");
});

test("I6: a definition that is not JSON prints as ONE escaped line, and every bot-derived line is prefixed", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "corrupt");
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='corrupt'",
      args: ["{not json\nsecond line\nthird line"],
    });
    assert.equal(forgetApprovedBotDef("corrupt"), true, "no approved copy: the whole stored text is printed");
    const out = [];
    const err = [];
    const io = () => ({ stdout: { write: (x) => out.push(String(x)) }, stderr: { write: (x) => err.push(String(x)) } });
    assert.equal(await reapproveMain({ argv: ["corrupt", "--show"], ...io() }), 0, err.join(""));
    const shown = out.join("");

    // EVERY line of the report that comes from the row is prefixed with `| `, so a line at column 0 is
    // the command's own words and never a row's.
    const lines = shown.split("\n").filter((line) => line !== "");
    assert.ok(lines.length > 3);
    assert.ok(lines.every((line) => line.startsWith("| ")), shown);

    // The corrupt definition is ONE line with its newlines escaped: the row's own line breaks never
    // reach the terminal as line breaks.
    const defIndex = lines.findIndex((line) => line.includes("stored definition:"));
    assert.ok(defIndex >= 0, shown);
    const defLine = lines[defIndex + 1];
    assert.ok(defLine.startsWith("| {"), defLine);
    assert.ok(defLine.includes("second line") && defLine.includes("third line"), "the whole text is on that one line");
    assert.ok(defLine.includes("\\u000a"), "with its newlines escaped");
    assert.equal(shown.includes("second line\nthird line"), false, "no un-prefixed continuation line");
    // The header lines are prefixed too (the bot id is bot-written text).
    assert.ok(lines.some((line) => line.startsWith("| bot:")));
    assert.ok(lines.some((line) => line.startsWith("| digest:")));
  } finally {
    s.close();
  }
});

test("I6: a __proto__ key inside spawn_env/gateways is shown (redacted), never silently dropped", () => {
  // JSON.parse DEFINES an own `__proto__` property, which is what a bot can write into a definition.
  // Building the redacted pair with `out[key] = …` on an ordinary object would set the PROTOTYPE and
  // drop the whole subtree from the diff — the operator would see nothing where a credential changed.
  const approved = approvedOf({
    ...DEF,
    spawn_env: JSON.parse('{"__proto__":{"bot_token":"old-token-value"},"PATH":"/usr/bin"}'),
  });
  const stored = {
    definition: JSON.stringify({
      ...DEF,
      spawn_env: JSON.parse('{"__proto__":{"bot_token":"new-token-value"},"PATH":"/usr/bin"}'),
    }),
    enabled: 1,
    project_id: null,
  };
  const text = approvedDiffLines(stored, approved).join("\n");
  assert.equal(text.includes("old-token-value"), false, "the approved token is never printed");
  assert.equal(text.includes("new-token-value"), false, "the stored token is never printed");
  assert.match(text, /!! spawn_env\s+changed/);
  assert.ok(text.includes("__proto__"), "the key is shown instead of vanishing");
  assert.match(text, /<redacted, changed>/, "and its credential leaf is named as redacted");
});