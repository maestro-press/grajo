/**
 * A source's uuid is written WITH the row, by every runtime insert path.
 *
 * scripts/init-db.js adds `uuid` as a nullable column and backfills NULLs on its next run, but
 * sync and cross-peer sharing key on the uuid, so a row that stays uuid-less until an init-db run
 * is a row those paths cannot see. There are three runtime inserts that create a source:
 *
 *   1. crow_add_source            (servers/research/server.js)
 *   2. insertSharedSource         (servers/sharing/shared-source-insert.js, an inbound share)
 *   3. applyProjectCloneBundle    (servers/sharing/clone-bundle.js, a project clone)
 *
 * The static test walks servers/ and scripts/ for every `INSERT ... INTO research_sources` that
 * names the table literally, and fails when that INSERT's OWN column list never names uuid, so a
 * fourth path added later cannot slip in unnoticed. It reads only the column list (or the `names`
 * array that builds a dynamic one), never the surrounding file: a uuid import or a comment near
 * the statement is not evidence that the row gets one. The rest runs each of the three against a
 * real init-db database.
 *
 * What this guard does NOT see: writers whose table name is itself interpolated
 * (`INSERT INTO ${table} ...`) — the Trash restore (servers/shared/history/api.js), instance-sync's
 * wire apply, and the sync-conflict restore all build the statement that way, so no column list is
 * there to read. Those paths are covered by behaviour, not by this scan.
 *
 * One of them writes a row it did not build: restoring a deleted source from the Trash
 * (servers/shared/history/api.js). Its version may carry the row's own uuid, and it keeps that
 * one; a version with no uuid (a snapshot of a row an older insert path left uuid-less) gets a
 * fresh one, so a restored source is whole too. That case has its own test below.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import Database from "better-sqlite3";

const ROOT = join(import.meta.dirname, "..");
const HOME = mkdtempSync(join(tmpdir(), "crow-src-uuid-"));
const DATA = join(HOME, ".crow", "data");
mkdirSync(DATA, { recursive: true });
process.env.HOME = HOME;
process.env.CROW_HOME = join(HOME, ".crow");
process.env.CROW_DATA_DIR = DATA;
process.env.CROW_DB_PATH = join(DATA, "crow.db");
after(() => rmSync(HOME, { recursive: true, force: true }));

execFileSync(process.execPath, ["scripts/init-db.js"], { cwd: ROOT, env: process.env, stdio: "pipe" });
const CORE = join(DATA, "crow.db");

const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { createProjectServer } = await import("../servers/research/server.js");
const { OWNER } = await import("../servers/research/actor.js");
const { createDbClient } = await import("../servers/db.js");
const { insertSharedSource } = await import("../servers/sharing/shared-source-insert.js");
const { createCloneBundleHelpers } = await import("../servers/sharing/clone-bundle.js");
const { run: runItemVersions, id: MIGRATION_0024 } = await import("../scripts/migrations/0024-item-versions.mjs");
const { run: runSources, id: MIGRATION_0026 } = await import("../scripts/migrations/0026-item-versions-sources.mjs");
const { withWriteContext } = await import("../servers/shared/history/write-context.js");
const { restoreFromTrash } = await import("../servers/shared/history/trash.js");

const UUID_RE = /^[0-9a-f]{32}$/;
const text = (r) => (r.content || []).map((c) => c.text).join("\n");
const idOf = (r) => Number(text(r).match(/\(id: (\d+)/)[1]);

function sourceRow(id) {
  const d = new Database(CORE, { readonly: true });
  try { return d.prepare("SELECT * FROM research_sources WHERE id = ?").get(id); } finally { d.close(); }
}

/** The single source a clone bundle put in `projectId` (the clone imports exactly one here). */
function clonedSourceRow(projectId) {
  const d = new Database(CORE, { readonly: true });
  try { return d.prepare("SELECT * FROM research_sources WHERE project_id = ?").get(projectId); } finally { d.close(); }
}

// ── the static guard ────────────────────────────────────────────────────────

// One-off importers and the schema/migration rails own their own shape; everything else that
// writes a source is runtime product code.
const SKIP_DIRS = new Set(["node_modules", "tests"]);
const SKIP_PATHS = new Set([
  "scripts/ops",
  "scripts/migrations",
  "scripts/init-db.js",
]);
const INSERT_SOURCE_RE = /INSERT\s+INTO\s+research_sources\b/g;

/** Index of the `)` that closes the `(` at `open`, or -1. */
function matchingParen(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "(") depth++;
    else if (src[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

/** Index of the `]` that closes the `[` at `open`, or -1. */
function matchingBracket(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "[") depth++;
    else if (src[i] === "]" && --depth === 0) return i;
  }
  return -1;
}

/**
 * The text of the column list's literal part: every `${...}` interpolation removed, so what is
 * left is only the column names the statement itself spells out.
 */
function withoutInterpolations(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "$" && text[i + 1] === "{") {
      let depth = 0;
      for (; i < text.length; i++) {
        if (text[i] === "{") depth++;
        else if (text[i] === "}" && --depth === 0) break;
      }
      continue;
    }
    out += text[i];
  }
  return out;
}

/**
 * The nearest `const names = [ ... ];` array literal that starts before `from`, or null. This is
 * how crow_add_source builds its column list, so its INSERT's column list is an interpolation and
 * the names have to be read where they are written.
 */
function namesArrayBefore(src, from) {
  const start = src.lastIndexOf("const names = [", from);
  if (start === -1) return null;
  const open = src.indexOf("[", start);
  const close = open === -1 ? -1 : matchingBracket(src, open);
  return close === -1 ? null : src.slice(start, close + 1);
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const rel = relative(ROOT, full).split("\\").join("/");
    if (SKIP_PATHS.has(rel)) continue;
    const st = statSync(full);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue;
      walk(full, out);
    } else if (name.endsWith(".js") || name.endsWith(".mjs")) {
      out.push(full);
    }
  }
  return out;
}

test("every INSERT INTO research_sources in product code names uuid", () => {
  const offenders = [];
  const sites = [];
  for (const root of ["servers", "scripts"]) {
    for (const file of walk(join(ROOT, root))) {
      const src = readFileSync(file, "utf8");
      const rel = relative(ROOT, file).split("\\").join("/");
      for (const m of src.matchAll(INSERT_SOURCE_RE)) {
        const line = src.slice(0, m.index).split("\n").length;
        sites.push(`${rel}:${line}`);
        const site = `${rel}:${line}`;

        // The statement's OWN column list: from the first `(` after the table name to the `)`
        // that closes it. Only this text counts — not the file around it.
        const open = src.indexOf("(", m.index + m[0].length);
        const close = open === -1 ? -1 : matchingParen(src, open);
        if (close === -1) {
          offenders.push(`${site} (no parenthesised column list found after the table name)`);
          continue;
        }
        const columns = src.slice(open + 1, close);
        const literal = withoutInterpolations(columns);
        if (/\buuid\b/.test(literal)) continue; // named in the column list itself

        if (!columns.includes("${")) {
          offenders.push(`${site} (column list: ${literal.replace(/\s+/g, " ").trim()})`);
          continue;
        }
        // The column list is built at runtime. crow_add_source's is a `names` array just above
        // the INSERT; read that, and fail loudly when nothing checkable is there.
        const names = namesArrayBefore(src, m.index);
        if (!names) {
          offenders.push(`${site} (column list is built dynamically and could not be checked)`);
        } else if (!/["']uuid["']/.test(names)) {
          offenders.push(
            `${site} (dynamic column list from \`const names = [...]\` names no "uuid": ` +
            `${names.replace(/\s+/g, " ").trim()})`,
          );
        }
      }
    }
  }
  assert.equal(
    offenders.length,
    0,
    `these research_sources INSERTs do not name uuid in their own column list, so the row is ` +
    `stored uuid-less until the next init-db run: ${offenders.join(", ")}`,
  );
  // The guard must not pass vacuously: the three known paths are still here.
  assert.ok(sites.length >= 3, `expected at least 3 research_sources INSERT sites, found ${sites.length}: ${sites.join(", ")}`);
  for (const known of ["servers/research/server.js", "servers/sharing/shared-source-insert.js", "servers/sharing/clone-bundle.js"]) {
    assert.ok(sites.some((s) => s.startsWith(`${known}:`)), `the guard should see ${known}: ${sites.join(", ")}`);
  }
});

// ── 1. crow_add_source ──────────────────────────────────────────────────────

async function clientFor() {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const server = createProjectServer(CORE, {
    actor: OWNER,
    // No test here adds a url, so the fetch seam must never be reached.
    fetchPage: async () => { throw new Error("this test must not fetch a page"); },
  });
  await server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  return client;
}

test("crow_add_source stores a fresh uuid with the row", async () => {
  const client = await clientFor();
  const add = (title) => client.callTool({
    name: "crow_add_source",
    arguments: { title, source_type: "book", citation_apa: `${title}. (2026).` },
  });
  const first = await add("Uuid probe one");
  const second = await add("Uuid probe two");
  assert.ok(!first.isError, text(first));
  assert.ok(!second.isError, text(second));
  const a = sourceRow(idOf(first));
  const b = sourceRow(idOf(second));
  assert.match(a.uuid, UUID_RE, `stored uuid is ${JSON.stringify(a.uuid)}`);
  assert.match(b.uuid, UUID_RE, `stored uuid is ${JSON.stringify(b.uuid)}`);
  assert.notEqual(a.uuid, b.uuid, "two inserts get two uuids");
});

// ── 2. insertSharedSource ───────────────────────────────────────────────────

test("insertSharedSource stores a fresh uuid with the row", async () => {
  const db = createDbClient(CORE);
  const id1 = await insertSharedSource(db, { title: "Shared one", source_type: "web_article", url: "https://example.com/one", citation: "C" });
  const id2 = await insertSharedSource(db, { title: "Shared two", source_type: "web_article", url: "https://example.com/two", citation: "C" });
  const a = sourceRow(id1);
  const b = sourceRow(id2);
  assert.match(a.uuid, UUID_RE, `stored uuid is ${JSON.stringify(a.uuid)}`);
  assert.match(b.uuid, UUID_RE, `stored uuid is ${JSON.stringify(b.uuid)}`);
  assert.notEqual(a.uuid, b.uuid, "two inserts get two uuids");
});

// ── 3. applyProjectCloneBundle ──────────────────────────────────────────────

function cloneBundle(slug, sources) {
  return {
    bundle_version: 1,
    project: { name: `Uuid clone ${slug}`, slug, description: null, type: "general", tags: null },
    sources,
    notes: [], audit_log: [], backends: [], file_manifest: [],
    origin_instance_id: "test-origin",
    snapshot_at: new Date().toISOString(),
  };
}

const minimalSource = (id, title) => ({
  id, title, source_type: "web_article", url: `https://example.com/${id}`, citation_apa: "C",
});

test("a cloned source without a uuid gets one; one that came with a uuid keeps it", async () => {
  const db = createDbClient(CORE);
  const { applyProjectCloneBundle } = createCloneBundleHelpers({ db });

  const first = await applyProjectCloneBundle(cloneBundle("uuid-clone-a", [minimalSource(5, "Cloned no uuid")]), null);
  const second = await applyProjectCloneBundle(cloneBundle("uuid-clone-b", [minimalSource(5, "Cloned no uuid either")]), null);
  const a = clonedSourceRow(first.project_id);
  const b = clonedSourceRow(second.project_id);
  assert.match(a.uuid, UUID_RE, `stored uuid is ${JSON.stringify(a.uuid)}`);
  assert.match(b.uuid, UUID_RE, `stored uuid is ${JSON.stringify(b.uuid)}`);
  assert.notEqual(a.uuid, b.uuid, "two clones get two uuids");

  // A bundle source that carries a uuid is that row's identity: keep it byte for byte.
  const kept = "0123456789abcdef0123456789abcdef";
  const third = await applyProjectCloneBundle(
    cloneBundle("uuid-clone-c", [{ ...minimalSource(7, "Cloned with uuid"), uuid: kept }]),
    null,
  );
  assert.equal(clonedSourceRow(third.project_id).uuid, kept);
});

// ── 4. the Trash restore (servers/shared/history/api.js) ─────────────────────

/** The owner at their dashboard, the author history-sources.test.js uses. */
const HIST_OWNER = { authorKind: "owner", authorId: "abcd1234", jobId: "session:abcd1234" };

/** A store with the two history migrations applied and recorded, as that file builds one. */
function historyStore() {
  const dir = mkdtempSync(join(tmpdir(), "src-uuid-restore-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    cwd: ROOT,
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: "" },
    stdio: "pipe",
  });
  const dbPath = join(dir, "crow.db");
  runItemVersions({ dbPath, log: () => {} });
  const outcome = runSources({ dbPath, log: () => {} });
  assert.equal(outcome.applied, true, `0026 applies to a real store: ${JSON.stringify(outcome)}`);
  const book = new Database(dbPath);
  try {
    book.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, sha TEXT)");
    for (const id of [MIGRATION_0024, MIGRATION_0026]) {
      book.prepare("INSERT OR REPLACE INTO schema_migrations (id, applied_at) VALUES (?, ?)").run(id, new Date().toISOString());
    }
  } finally {
    book.close();
  }
  return { dir, dbPath };
}

test("a restored source gets a uuid when its version has none, and keeps the one it had", async () => {
  const { dir, dbPath } = historyStore();
  const db = createDbClient(dbPath);
  // The history paths resolve their store from the environment; point it at this store
  // for the duration, exactly as tests/history-sources.test.js does per fixture.
  const env = { data: process.env.CROW_DATA_DIR, dbPath: process.env.CROW_DB_PATH, sync: process.env.CROW_DISABLE_INSTANCE_SYNC };
  process.env.CROW_DATA_DIR = dir;
  process.env.CROW_DB_PATH = "";
  process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
  const insertSource = (fields) => {
    const columns = Object.keys(fields);
    return withWriteContext(HIST_OWNER, () =>
      db.execute({
        sql: `INSERT INTO research_sources (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
        args: columns.map((c) => fields[c]),
      }),
    );
  };
  const deleteAndRestore = async (id) => {
    await withWriteContext(HIST_OWNER, () => db.execute({ sql: "DELETE FROM research_sources WHERE id = ?", args: [id] }));
    const restored = await restoreFromTrash(db, { itemType: "research_source", itemId: id }, HIST_OWNER);
    assert.ok(restored.newVersionId, "a deleted source is restorable from the Trash");
    const { rows } = await db.execute({ sql: "SELECT * FROM research_sources WHERE id = ?", args: [id] });
    return rows[0];
  };

  try {
    // A source written by a path that sets no uuid: its version has uuid NULL, so the
    // re-created row has to get one — otherwise it stays uuid-less until init-db runs.
    const noUuid = await insertSource({ title: "No uuid when written", source_type: "web_article", citation_apa: "C" });
    const bare = await deleteAndRestore(Number(noUuid.lastInsertRowid));
    assert.match(bare.uuid, UUID_RE, `a restored uuid-less source got ${JSON.stringify(bare.uuid)}`);

    // A source that carried a uuid keeps it byte for byte: the version stores it, and it is
    // this row's identity for sync and cross-peer sharing.
    const kept = "fedcba9876543210fedcba9876543210";
    const withUuid = await insertSource({
      title: "Written with a uuid",
      source_type: "web_article",
      citation_apa: "C",
      uuid: kept,
    });
    const back = await deleteAndRestore(Number(withUuid.lastInsertRowid));
    assert.equal(back.uuid, kept, "the version's uuid is the restored row's uuid");
  } finally {
    db.close();
    process.env.CROW_DATA_DIR = env.data;
    if (env.dbPath === undefined) delete process.env.CROW_DB_PATH;
    else process.env.CROW_DB_PATH = env.dbPath;
    if (env.sync === undefined) delete process.env.CROW_DISABLE_INSTANCE_SYNC;
    else process.env.CROW_DISABLE_INSTANCE_SYNC = env.sync;
    rmSync(dir, { recursive: true, force: true });
  }
});