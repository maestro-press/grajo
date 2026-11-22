/**
 * FTS5 shadow tables are INDEX STRUCTURE, not rows.
 *
 * The gate (scripts/schema-migration-dryrun.sh) failed a genuine no-op run against
 * a real crow.db: `user_version 9 -> 9`, no schema change, no lost table — but
 *
 *     sources_fts_data: 52 -> 53
 *     sources_fts_idx: 50 -> 51
 *     ^^^ STOP — unexplained row loss
 *
 * and it called a GAIN "row loss". Those two tables are the fts5 index's own
 * segment/term b-trees (`sources_fts` is external-content over research_sources).
 * init-db's uuid backfill — `UPDATE research_sources SET uuid = … WHERE uuid IS
 * NULL` inside addUuidColumn() — fires the `sources_au` trigger, which issues
 * ('delete', …) plus a real insert into sources_fts. That rewrites index segments
 * (one more _data blob, one more _idx term row) while every DOCUMENT stays put:
 * `sources_fts`, `_docsize` and `_content` counts do not move.
 *
 * So the gate must (1) never STOP on `<vtab>_data`/`_idx`/`_config`, report their
 * deltas in their own informational section instead, keep the per-document tables
 * (the vtab itself, `_content`, `_docsize`) under the STOP rule, label a decrease
 * "row loss" and an increase "unexplained row gain"; and (2) run fts5's own
 * `integrity-check` per virtual table and report it (a failure is a STOP).
 *
 * That check is a STRUCTURAL tripwire, not a content comparison: probed against
 * this SQLite, a content row missing from the index, a stale index entry, a stale
 * content row and even an absent content table all return "ok" (and the shadow
 * tables are read-only from SQL, so no fixture can break an index page). So the
 * test below asserts the check RUNS for both index shapes — including the
 * external-content one — and its STOP branch is defensive.
 *
 * Fixtures are spawned through the real script with DRYRUN_INIT_SCRIPT, the same
 * seam tests/schema-dryrun-column-diff.test.js uses.
 *
 * Two follow-on review nits are covered below:
 * 1. `USING fts5vocab(...)` is a DIFFERENT module (a term/row inspector over an
 *    existing fts5 table), so `lower(sql) LIKE '%using fts5%'` mis-classified it
 *    as an fts5 index: the integrity-check loop then inserted 'integrity-check'
 *    into it, which sqlite refuses ("table ... may not be modified") — a false
 *    STOP on a healthy DB. Discovery must match the fts5 module followed by '('
 *    only, and the vocab table must stay an ordinary table (never checked).
 * 2. The discovery queries sent errors to /dev/null, so a FAILED query read as
 *    "no FTS5 virtual tables" — the cleanest possible-looking DB. A non-zero
 *    sqlite3 exit now prints a warning and STOPs. Triggered here with a source
 *    file that is not a database at all (cheap: any garbage bytes make the
 *    discovery query fail with sqlite exit 26 / SQLITE_NOTADB).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../node_modules/better-sqlite3/lib/index.js";

const repoRoot = new URL("..", import.meta.url).pathname;
const gateScript = join(repoRoot, "scripts", "schema-migration-dryrun.sh");
const bsqlite = join(repoRoot, "node_modules", "better-sqlite3", "lib", "index.js");

const dir = mkdtempSync(join(tmpdir(), "dryrun-fts-"));
const fixtureDb = join(dir, "fixture.db");
// An fts5 table WITH an fts5vocab table over it (nit 1), and a file that is not a
// database at all (nit 2).
const vocabDb = join(dir, "vocab-fixture.db");
const notADb = join(dir, "not-a-database.db");

/** Migrations act on the COPY the gate hands them via CROW_DB_PATH. */
function writeMigration(name, sql) {
  const path = join(dir, `${name}.mjs`);
  writeFileSync(path, `
    import Database from ${JSON.stringify(bsqlite)};
    const db = new Database(process.env.CROW_DB_PATH);
    db.exec(${JSON.stringify(sql)});
    db.close();
  `);
  return path;
}

const ftsMaintenanceScript = writeMigration("migrate-fts-maintenance", `
  INSERT INTO docs_fts(docs_fts) VALUES('optimize');
  INSERT INTO notes_fts(notes_fts) VALUES('optimize');
`);
const noopScript = writeMigration("migrate-fts-noop", "");
const deleteWidgetScript = writeMigration("migrate-delete-widget", "DELETE FROM widgets WHERE id = 1;");
const insertWidgetScript = writeMigration("migrate-insert-widget", "INSERT INTO widgets (name) VALUES ('delta');");
const deleteNoteDocScript = writeMigration("migrate-delete-note-doc", "DELETE FROM notes_fts WHERE rowid = 2;");
const deleteDocScript = writeMigration("migrate-delete-doc", "DELETE FROM docs WHERE id = 2;");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function runGate(initScript, db = fixtureDb) {
  return spawnSync("bash", [gateScript, "fixture", db], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, DRYRUN_INIT_SCRIPT: initScript },
  });
}

/**
 * docs: an EXTERNAL-CONTENT fts5 index (sources_fts's shape — no _content table,
 *   a _docsize table), fed by the same insert/delete/update triggers init-db
 *   installs. Three documents inserted in three separate transactions so the index
 *   really holds three segments, which 'optimize' visibly merges.
 * notes_fts: a CONTENTFUL fts5 index — has _content AND _docsize, one row per
 *   document, so it exercises the "document count" half of the rule.
 */
const FIXTURE_SCHEMA = `
  CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);
  CREATE TABLE docs (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT);
  CREATE VIRTUAL TABLE docs_fts USING fts5(title, body, content=docs, content_rowid=id);
  CREATE TRIGGER docs_ai AFTER INSERT ON docs BEGIN
    INSERT INTO docs_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
  END;
  CREATE TRIGGER docs_ad AFTER DELETE ON docs BEGIN
    INSERT INTO docs_fts(docs_fts, rowid, title, body) VALUES ('delete', old.id, old.title, old.body);
  END;
  CREATE TRIGGER docs_au AFTER UPDATE ON docs BEGIN
    INSERT INTO docs_fts(docs_fts, rowid, title, body) VALUES ('delete', old.id, old.title, old.body);
    INSERT INTO docs_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
  END;
  CREATE VIRTUAL TABLE notes_fts USING fts5(title, body);
`;

const DOCS = [
  ["alpha one", "the quick brown fox"],
  ["beta two", "the quick brown fox jumps"],
  ["gamma three", "the brown fox sleeps"],
];

let fixtureHash;
let vocabHash;

/**
 * docs + docs_fts: the external-content shape of a real crow.db.
 * docs_vocab: `USING fts5vocab('docs_fts', 'row')` — a vocabulary view over the
 *   same index, i.e. a sqlite_master 'table' whose SQL contains 'using fts5'
 *   but is NOT an fts5 table. The old detection matched it, then tried to run
 *   `INSERT INTO docs_vocab(docs_vocab) VALUES('integrity-check')`, which sqlite
 *   answers with "table docs_vocab may not be modified".
 */
const VOCAB_FIXTURE_SCHEMA = `
  CREATE TABLE docs (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT);
  CREATE VIRTUAL TABLE docs_fts USING fts5(title, body, content=docs, content_rowid=id);
  CREATE VIRTUAL TABLE docs_vocab USING fts5vocab('docs_fts', 'row');
`;

before(() => {
  const db = new Database(fixtureDb);
  db.exec(FIXTURE_SCHEMA);
  db.exec("INSERT INTO widgets (name) VALUES ('alpha'), ('beta'), ('gamma')");
  const insDoc = db.prepare("INSERT INTO docs (title, body) VALUES (?, ?)");
  for (const [title, body] of DOCS) insDoc.run(title, body); // one segment each
  const insNote = db.prepare("INSERT INTO notes_fts (title, body) VALUES (?, ?)");
  insNote.run("note a", "hello world");
  insNote.run("note b", "hello again");
  db.pragma("user_version = 1");
  db.close();
  fixtureHash = sha256(fixtureDb);

  const vdb = new Database(vocabDb);
  vdb.exec(VOCAB_FIXTURE_SCHEMA);
  vdb.exec("INSERT INTO docs (title, body) VALUES ('alpha', 'hello world'), ('beta', 'hello again')");
  vdb.exec("INSERT INTO docs_fts(docs_fts) VALUES('rebuild')");
  vdb.pragma("user_version = 1");
  vdb.close();
  vocabHash = sha256(vocabDb);

  // 40 lines of text: sqlite reads the header, fails, exits 26 (SQLITE_NOTADB).
  writeFileSync(notADb, "this is not a sqlite database, it is a text file\n".repeat(40));
});

after(() => rmSync(dir, { recursive: true, force: true }));

test("FTS maintenance only ('optimize'): gate PASSES, shadow deltas are informational", () => {
  const r = runGate(ftsMaintenanceScript);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /FTS5 index structure \(not rows\)/,
    "the gate needs a dedicated FTS5 index-structure section");
  // 'optimize' merges the fixture's three segments: the b-trees shrink, no
  // document moves. Before the fix this printed "STOP — unexplained row loss".
  assert.match(r.stdout, /docs_fts_data: \d+ -> \d+/,
    `a <vtab>_data delta belongs in the informational section\n${r.stdout}`);
  assert.match(r.stdout, /docs_fts_idx: \d+ -> \d+/,
    `a <vtab>_idx delta belongs in the informational section\n${r.stdout}`);
  assert.match(r.stdout, /informational — segment\/term b-tree bookkeeping/);
  assert.doesNotMatch(r.stdout, /STOP/, `no STOP for index structure\n${r.stdout}`);
  assert.match(r.stdout, /DRY-RUN GATE PASSED/);
  assert.equal(sha256(fixtureDb), fixtureHash, "gate must never mutate the source DB");
});

test("the per-document FTS tables (vtab, _content, _docsize) stay under the STOP rule", () => {
  const r = runGate(ftsMaintenanceScript);
  // Index structure moved, documents did not: the informational section must not
  // swallow the tables that hold one row per document.
  assert.doesNotMatch(r.stdout, /docs_fts_docsize: /,
    "external-content _docsize is one row per document — not index structure");
  assert.doesNotMatch(r.stdout, /notes_fts_content: /,
    "a contentful index's _content is one row per document — not index structure");
  assert.doesNotMatch(r.stdout, /notes_fts_docsize: /,
    "a contentful index's _docsize is one row per document — not index structure");
  // …and fts5's own check runs, and passes, on both shapes.
  assert.match(r.stdout, /FTS5 integrity-check/);
  assert.match(r.stdout, /docs_fts: ok/, `external-content integrity-check must run\n${r.stdout}`);
  assert.match(r.stdout, /notes_fts: ok/, `contentful integrity-check must run\n${r.stdout}`);
  assert.match(r.stdout, /docs_fts_data: \d+ -> \d+/, "the external-content index really moved");
});

test("deleting a row from an ordinary table: STOP labelled 'row loss'", () => {
  const r = runGate(deleteWidgetScript);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /widgets: 3 -> 2 \(row loss\)/,
    `the delta must be labelled as loss\n${r.stdout}`);
  assert.match(r.stdout, /STOP — unexplained ROW LOSS/);
  assert.match(r.stdout, /DRY-RUN GATE FAILED/);
  assert.equal(sha256(fixtureDb), fixtureHash, "gate must never mutate the source DB");
});

test("inserting a row into an ordinary table: STOP labelled 'row gain', not loss", () => {
  const r = runGate(insertWidgetScript);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /widgets: 3 -> 4 \(unexplained row gain\)/,
    `a GAIN must be labelled a gain, not "row loss"\n${r.stdout}`);
  assert.match(r.stdout, /STOP — unexplained ROW GAIN/);
  assert.doesNotMatch(r.stdout, /row loss/i, `a gain is not row loss\n${r.stdout}`);
  assert.match(r.stdout, /DRY-RUN GATE FAILED/);
  assert.equal(sha256(fixtureDb), fixtureHash, "gate must never mutate the source DB");
});

test("deleting an FTS document: STOP (the vtab, _content and _docsize counts all moved)", () => {
  const r = runGate(deleteNoteDocScript);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  // A document left the index with no ordinary table involved at all: only the
  // per-document fts5 tables changed, and they are not index structure.
  assert.match(r.stdout, /notes_fts: 2 -> 1 \(row loss\)/, r.stdout);
  assert.match(r.stdout, /notes_fts_content: 2 -> 1 \(row loss\)/, r.stdout);
  assert.match(r.stdout, /notes_fts_docsize: 2 -> 1 \(row loss\)/, r.stdout);
  assert.match(r.stdout, /STOP — unexplained ROW LOSS/);
  assert.match(r.stdout, /DRY-RUN GATE FAILED/);
});

test("deleting a row whose trigger maintains the index: still a STOP", () => {
  const r = runGate(deleteDocScript);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /docs: 3 -> 2 \(row loss\)/, r.stdout);
  assert.match(r.stdout, /docs_fts: 3 -> 2 \(row loss\)/, r.stdout);
  assert.match(r.stdout, /STOP — unexplained ROW LOSS/);
});

test("a no-op on a healthy DB with FTS tables: no STOP, everything reported clean", () => {
  const r = runGate(noopScript);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /FTS5 index structure \(not rows\)/);
  assert.match(r.stdout, /none — FTS5 index structure unchanged/);
  assert.match(r.stdout, /docs_fts: ok/);
  assert.match(r.stdout, /notes_fts: ok/);
  assert.doesNotMatch(r.stdout, /STOP/);
  assert.match(r.stdout, /DRY-RUN GATE PASSED/);
  assert.equal(sha256(fixtureDb), fixtureHash, "gate must never mutate the source DB");
});

// ── nit 1: fts5vocab is not an fts5 table ────────────────────────────────────
test("an fts5vocab table is not integrity-checked and does not STOP a no-op run", () => {
  const r = runGate(noopScript, vocabDb);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  // The real fts5 table is still discovered and checked…
  assert.match(r.stdout, /docs_fts: ok/, `the fts5 table is still checked\n${r.stdout}`);
  // …and the vocabulary table is not: `INSERT INTO docs_vocab(docs_vocab)
  // VALUES('integrity-check')` is refused by sqlite, which used to be a STOP.
  assert.doesNotMatch(r.stdout, /docs_vocab: /,
    `a fts5vocab table must never be integrity-checked\n${r.stdout}`);
  assert.doesNotMatch(r.stdout, /may not be modified/, r.stdout);
  assert.doesNotMatch(r.stdout, /STOP/, `'using fts5vocab' is not 'using fts5('\n${r.stdout}`);
  assert.match(r.stdout, /DRY-RUN GATE PASSED/);
  assert.equal(sha256(vocabDb), vocabHash, "gate must never mutate the source DB");
});

// ── nit 2: a failed discovery query must never read as "no FTS5 tables" ──────
test("a discovery query that FAILS is a STOP, not 'no FTS5 virtual tables'", () => {
  const r = runGate(noopScript, notADb);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}\n${r.stdout}\n${r.stderr}`);
  // Both copies are probed, so both failures are named — with sqlite's own reason.
  assert.match(r.stdout, /FTS5 virtual-table discovery FAILED on the pre-migration copy/,
    `the pre-copy failure must be reported\n${r.stdout}`);
  assert.match(r.stdout, /FTS5 virtual-table discovery FAILED on the post-migration copy/,
    `the post-copy failure must be reported\n${r.stdout}`);
  assert.match(r.stdout, /not a database/, "sqlite's diagnostic is carried through, not discarded");
  assert.match(r.stdout, /STOP — FTS5 virtual-table discovery FAILED/,
    "a failed discovery disables the index classification and the check — it must STOP");
  assert.match(r.stdout, /unknown — the FTS5 virtual-table discovery query FAILED/,
    "the FTS sections must not claim there are no FTS5 tables");
  assert.doesNotMatch(r.stdout, /no FTS5 virtual tables in this DB/,
    "an error must never be reported as an empty result");
  assert.match(r.stdout, /DRY-RUN GATE FAILED/);
});