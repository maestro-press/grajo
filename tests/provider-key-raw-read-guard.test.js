// tests/provider-key-raw-read-guard.test.js — design §5, the static guard.
//
// After the seal, `providers.api_key` holds an ENVELOPE in the gateway and null
// everywhere else. A reader that still pulls the raw column hands an envelope (or
// nothing) to an HTTP client, and a reader that reads it without the keyring
// silently sends an unauthenticated request. So the product code may not touch
// the column directly any more: it goes through ONE mapper
// (servers/shared/provider-row.js `providerRowToObject`) and the one write door
// (servers/shared/providers-db.js), and the few files that legitimately do are
// listed below.
//
// The allow-list is PER FILE **AND PER LINE** (review round 1, L3): every entry
// names the file, a regexp that must match the offending source line, and the
// reason. A file may not be allow-listed wholesale, a stale entry fails the
// honesty test, and a NEW read in an already-listed file (a second statement, a
// destructure) is caught unless it has its own entry.
//
// What is refused, after comments are stripped (a comment may name the column):
//
//   sql          a statement string that names BOTH `providers` and `api_key`
//   member       `.api_key`, `?.api_key`, `["api_key"]`
//   destructure  `{ api_key } = …` (a read that never writes the dot)
//   row-colon    `api_key:` on a line whose window also names `providers` (a row
//                image built from the table), for non-SQL code
//
// The scan covers the product trees (servers/, bundles/, scripts/), skipping
// node_modules, vendored third-party code and the tests themselves.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const TREES = ["servers", "bundles", "scripts"];
const SKIP_DIRS = new Set(["node_modules", "vendor", "third_party", ".git", "dist", "build"]);

/**
 * One entry per reviewed raw read: the repo-relative FILE, a regexp that must match
 * the offending LINE, and the reason. A file may appear several times; a NEW read
 * in a listed file needs its own matching line (review round 1, L3).
 */
const ALLOW = [
  {
    file: "servers/shared/provider-row.js",
    line: /const stored = row\.api_key;/,
    why: "the ONE mapper: reads the stored cell to classify it and to carry it as a non-enumerable storedKey",
  },
  {
    file: "servers/shared/providers-db.js",
    line: /provider\?\.apiKey \?\? provider\?\.api_key/,
    why: "the ONE write door: the incoming cell of a save (storedKey wins over apiKey) before it is sealed",
  },
  {
    file: "servers/shared/providers-db.js",
    line: /parseStoredKey\(existing\.api_key\)|sameKeyCell\(w\.id, existing\.api_key|rows\[0\]\.api_key : undefined/,
    why: "the ONE write door: the no-op comparator and the seal need the CURRENT cell",
  },
  {
    file: "servers/shared/providers-db.js",
    line: /\(id, base_url, api_key, host, bundle_id|api_key = excluded\.api_key/,
    why: "the ONE write door: the INSERT/UPDATE names the api_key column it writes a sealed value into",
  },
  {
    file: "servers/shared/cloud-consent.js",
    line: /row\?\.api_key/,
    why: "reads the SHAPE (parseStoredKey) and the plaintext of a parsed row to fingerprint a consent entry; never returns the cell",
  },
  {
    file: "servers/shared/provider-key-need.js",
    line: /hasProviderKey\(row\.api_key\)/,
    why: "presence only (hasProviderKey): a sealed key is a key this device holds",
  },
  {
    file: "servers/sharing/instance-sync.js",
    line: /hasProviderKey\(localRow\.api_key\)/,
    why: "presence only, for the endpoint-change hold (a sealed cell is a key held here)",
  },
  {
    file: "servers/sharing/instance-sync.js",
    line: /providers: Object\.freeze\(\["api_key"\]\)/,
    why: "the LOCAL_ONLY column list that keeps api_key off the sync wire",
  },
  {
    file: "scripts/init-db.js",
    line: /^\s*api_key TEXT,\s*$/,
    why: "the schema: one column declaration, no read",
  },
  {
    file: "scripts/migrations/0040-seal-provider-keys.mjs",
    line: /providers\.api_key:/,
    why: "the migration's own log line names the column; it never reads a value",
  },
  {
    file: "bundles/phone/panel/routes.js",
    line: /api_key: mapped\.apiKey/,
    why: "SELECT * row; the key itself is read through providerRowToObject (the heal of the sql window)",
  },
  {
    file: "servers/gateway/ai/add-provider.js",
    line: /row\.storedKey \?\? row\.api_key/,
    why: "the reuse-by-key check: passes the cell to sameKeyCell (the one door) and never returns it",
  },
  {
    file: "servers/gateway/dashboard/settings/sections/llm/ai-profiles.js",
    line: /SELECT id, provider_type, base_url, api_key, models FROM providers/,
    why: "the profile panel's enrichment SELECT feeds providerRowToObject, which is what the mask renders",
  },
  {
    file: "servers/shared/pick-checks.js",
    line: /parseStoredKey\(row\?\.api_key\)/,
    why: "the pick-check stamp reads the envelope's fp16 (never the value) so a check follows its key",
  },
  {
    file: "servers/gateway/dashboard/settings/sections/llm/providers-tab.js",
    line: /hasProviderKey\(p\.api_key/,
    why: "presence only (hasProviderKey) so the needs-key line also reads a raw-shaped row",
  },
  {
    file: "servers/gateway/dashboard/settings/sections/llm/providers-tab.js",
    line: /base_url, api_key, model_id, description \} = req\.body/,
    why: "the form's own field name (`api_key` is an input name), not a providers row read",
  },
  {
    file: "servers/gateway/keychain/provider-keys-sweep.js",
    line: /prepare\("(?:SELECT id, api_key FROM providers|SELECT api_key FROM providers|UPDATE providers SET api_key)/,
    why: "the seal/unseal pass: its SELECT/UPDATE statements are the migration",
  },
  {
    file: "servers/gateway/keychain/provider-keys-sweep.js",
    line: /parseStoredKey\(row\.api_key\)|stored: row\.api_key|plaintext: row\.api_key|plaintextById\.set\(row\.id, row\.api_key\)|valueDigest\(row\.api_key\)|readBack\.get\(id\)\?\.api_key/,
    why: "the seal/unseal pass: it IS the migration that reads and rewrites every cell",
  },
  {
    file: "servers/gateway/keychain/boot-key.js",
    line: /SELECT api_key FROM providers|parseStoredKey\(row\?\.api_key\)/,
    why: "the boot's §3.2 check: it only asks each cell's SHAPE (parseStoredKey) to decide whether a key may be minted",
  },
  {
    file: "servers/gateway/keychain/provider-key-values.js",
    line: /SELECT id, api_key FROM providers|isProviderKeyEnvelope\(r\.api_key\)|stored: r\.api_key/,
    why: "the HOST-side masking collector: it opens each sealed cell so a key cannot appear in a log or a transcript",
  },
  {
    file: "scripts/lib/live-pi-driver-child.mjs",
    line: /api_key/,
    why: "test harness: builds a scratch registry whose api_key is always NULL, and re-checks it is still NULL",
  },
  {
    file: "scripts/ops/provider-keys-seal-dryrun.mjs",
    line: /api_key/,
    why: "the dry-run tool: reads the cells it digests on a scratch copy, and never prints one",
  },
];

function stripComments(src) {
  // Block comments, then line comments. Good enough for a source scan: a `//` or
  // `/*` inside a string literal can only make this MORE permissive by a few
  // characters, never less.
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:\\])\/\/[^\n]*/g, "$1");
}

function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(join(dir, e.name), out);
      continue;
    }
    if (!e.isFile()) continue;
    if (!/\.(?:js|mjs|cjs)$/.test(e.name)) continue;
    out.push(join(dir, e.name));
  }
  return out;
}

const MEMBER_RE = /\.api_key\b|\?\.api_key\b|\[\s*["']api_key["']\s*\]/;
/** `const { api_key } = row` / `const { api_key: k } = row` — a read without the dot. */
const DESTRUCTURE_RE = /\{[^{}\n]*\bapi_key\b[^{}\n]*\}\s*=/;
/** `api_key: …` on a line that also speaks about the providers table. */
const COLON_RE = /\bapi_key\s*:/;

/** Every `providers` + `api_key` statement string: `api_key` near a SQL verb and `providers`. */
function sqlHits(src) {
  const hits = [];
  const re = /\bapi_key\b/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const from = Math.max(0, m.index - 400);
    const window = src.slice(from, m.index + 400);
    if (!/\bproviders\b/.test(window)) continue;
    if (!/\b(SELECT|INSERT|UPDATE|DELETE|REPLACE)\b/.test(window)) continue;
    hits.push({ index: m.index, kind: "sql" });
  }
  return hits;
}

/** The line number (1-based) and text of an index in `src`. */
function lineAt(src, index) {
  const before = src.slice(0, index);
  const line = before.split("\n").length;
  return { line, text: src.split("\n")[line - 1] ?? "" };
}

/**
 * Every raw-cell touch in one file, as `{kind, line, text}`. `destructure` and
 * `row-colon` are the shapes a dot-only scan would miss (review round 1, L3).
 */
function hitsIn(src) {
  const hits = [];
  const push = (index, kind) => hits.push({ index, kind });
  let m;
  MEMBER_RE.lastIndex = 0;
  const memberRe = new RegExp(MEMBER_RE.source, "g");
  while ((m = memberRe.exec(src)) !== null) push(m.index, "member");
  const destructureRe = new RegExp(DESTRUCTURE_RE.source, "g");
  while ((m = destructureRe.exec(src)) !== null) push(m.index, "destructure");
  const colonRe = new RegExp(COLON_RE.source, "g");
  while ((m = colonRe.exec(src)) !== null) {
    const from = Math.max(0, m.index - 400);
    const window = src.slice(from, m.index + 400);
    // A row image of the providers table, not a config object or an HTML option.
    if (!/\bproviders\b/.test(window)) continue;
    if (/["']\s*api_key\s*["']\s*:/.test(window.slice(0, 200)) && !/\bapi_key\b\s*,/.test(window)) continue;
    push(m.index, "row-colon");
  }
  for (const hit of sqlHits(src)) push(hit.index, hit.kind);
  return hits;
}

/** The reviewed entries for one repo-relative file. */
const entriesFor = (rel) => ALLOW.filter((entry) => entry.file === rel);

/** Does any reviewed line pattern for this file match the offending line? */
function allowed(rel, text) {
  return entriesFor(rel).some((entry) => entry.line.test(text));
}

function scan() {
  const violations = [];
  for (const tree of TREES) {
    for (const file of walk(join(ROOT, tree))) {
      const rel = relative(ROOT, file).split(sep).join("/");
      const src = stripComments(readFileSync(file, "utf8"));
      for (const hit of hitsIn(src)) {
        const { line, text } = lineAt(src, hit.index);
        if (allowed(rel, text)) continue;
        violations.push(`${rel}:${line} [${hit.kind}] ${text.trim().slice(0, 140)}`);
      }
    }
  }
  return [...new Set(violations)].sort();
}

test("no product file reads providers.api_key directly outside the reviewed lines", () => {
  const violations = scan();
  assert.deepEqual(violations, [],
    `unreviewed raw providers.api_key read(s):\n  ${violations.join("\n  ")}\n` +
    "Use providerRowToObject (servers/shared/provider-row.js) or upsertProvider; if the read is legitimate, " +
    "add a {file, line, why} entry to ALLOW in this test naming the LINE it allows.");
});

test("the reviewed list is honest: every entry still matches a real hit, and the guard is not vacuous", () => {
  const seen = [];
  for (const tree of TREES) {
    for (const file of walk(join(ROOT, tree))) {
      const rel = relative(ROOT, file).split(sep).join("/");
      const src = stripComments(readFileSync(file, "utf8"));
      for (const hit of hitsIn(src)) {
        const { line, text } = lineAt(src, hit.index);
        if (allowed(rel, text)) seen.push(`${rel}:${line}`);
      }
    }
  }
  for (const entry of ALLOW) {
    const matches = seen.filter((s) => s.startsWith(entry.file + ":"));
    assert.ok(matches.length > 0,
      `${entry.file} (${entry.line}) matches nothing any more — fix or remove the ALLOW entry`);
  }
  // The guard really detects every pattern (a canary, so a regexp typo cannot
  // make every scan pass).
  const canary = stripComments([
    'const k = row.api_key;',
    'const q = "SELECT api_key FROM providers";',
    'const { api_key } = row;',
    'const image = { id: r.id, api_key: r.key };',
    '// row.api_key',
  ].join("\n"));
  const kinds = new Set(hitsIn(canary).map((h) => h.kind));
  for (const kind of ["member", "sql", "destructure", "row-colon"]) {
    assert.equal(kinds.has(kind), true, `the ${kind} pattern matches`);
  }
  assert.equal(hitsIn(stripComments("// row.api_key\n/* row.api_key */\n")).length, 0, "comments are stripped");
  // …and a comment naming the column is not a read.
  assert.equal(hitsIn(stripComments("// providers.api_key: a peer sends one\n")).length, 0);
});