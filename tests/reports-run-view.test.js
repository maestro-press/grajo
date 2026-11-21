// The report run page (R2-1): /dashboard/project/<slug>/reports/<id>/runs/<runId>.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR under a temp dir, so nothing can
// touch a real Crow data dir), real report / run / report_versions rows, the artifacts tables from the
// bundle's own init-tables, and the panel's handler driven directly with a fake request, a fake response
// and a layout that escapes the page title the way servers/gateway/dashboard/shared/layout.js does. No
// HTTP server, no browser: every assertion is about the markup these reads produce.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-run-view-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
delete process.env.CROW_GATEWAY_URL;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const panel = (await import("../servers/gateway/dashboard/panels/report-run.js")).default;
const { frameDocument, FRAME_SANDBOX } = await import("../servers/gateway/dashboard/panels/report-run/html.js");
const {
  BACK_TO_PROJECT_LINE, LINKS_IN_RUN_HEADING, RUN_VIEW_MISSING_LINE, VERSION_NOT_AVAILABLE_LINE,
} = await import("../servers/gateway/reports/email/copy.js");
const { initArtifactsTables } = await import("../bundles/artifacts/server/init-tables.js");
const { primeSecretValues } = await import("../servers/shared/secret-values.js");

const open = [];
let copied = 0;

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

/* ------------------------------------------------------------------- the harness */

async function freshDb() {
  const dir = join(root, "t" + (++copied));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

/** Two live projects, one report in each, and one run of each report. */
async function base(db) {
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'garden', 'Garden')",
    args: [],
  });
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (2, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'kitchen', 'Kitchen')",
    args: [],
  });
  await db.execute({
    sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, created_at, updated_at)
          VALUES ('rep-1', 1, 'owner', 'bot-1', 'Weekly listings', 1, 1)`,
    args: [],
  });
  await db.execute({
    sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, created_at, updated_at)
          VALUES ('rep-2', 2, 'owner', 'bot-1', 'Kitchen list', 1, 1)`,
    args: [],
  });
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES ('run-1', 'rep-1', 'manual', 'owner', 'ok', 1)`,
    args: [],
  });
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES ('run-2', 'rep-2', 'manual', 'owner', 'ok', 1)`,
    args: [],
  });
}

/** The artifact tables, one document artifact with version 2, and the run's version row for it. */
async function withVersion(db, {
  markdown = "# Weekly listings\n\n- one",
  allowedLinks = ["https://ok.example.com/x"],
  artifactId = "art-1",
  n = 2,
  runId = "run-1",
  reportId = "rep-1",
} = {}) {
  await initArtifactsTables(db);
  await db.execute({
    sql: "INSERT OR IGNORE INTO artifacts (id, title, type, current_version) VALUES (?, 'Weekly listings', 'document', ?)",
    args: [artifactId, n],
  });
  await db.execute({
    sql: `INSERT INTO artifact_versions (artifact_id, n, state, files_json, source_json, size, content_hash, made_by)
          VALUES (?, ?, 'current', '[]', ?, 0, 'hash', 'user')`,
    args: [artifactId, n, JSON.stringify({ markdown, title: "Weekly listings" })],
  });
  await db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES (?, ?, ?, ?, 'manual', ?, 1)`,
    args: [artifactId, n, reportId, runId, JSON.stringify(allowedLinks)],
  });
}

/** A fake response: the panel sets a status, sets headers and hands the page back. */
function fakeRes() {
  return {
    statusCode: 200,
    headersSent: false,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    set(name, value) { this.headers[String(name).toLowerCase()] = String(value); return this; },
    type() { return this; },
    send(body) { this.body = body; this.headersSent = true; return this; },
    redirect() { return this; },
    append() { return this; },
  };
}

/** A request as the router would hand it over: the path's own segments, no browser around it. */
function fakeReq(params = { slug: "garden", id: "rep-1", runId: "run-1" }, extra = {}) {
  return { method: "GET", params, query: {}, body: {}, headers: {}, ...extra };
}

/** A db that writes down every SQL string it is handed, then reads through to the real one. */
function recordingDb(db) {
  const sql = [];
  return {
    sql,
    execute(statement) {
      sql.push(typeof statement === "string" ? statement : String(statement?.sql ?? ""));
      return db.execute(statement);
    },
  };
}

/** The tables this panel must not read at all when the owner gate refuses. */
const GATED_TABLES = ["reports", "report_runs", "report_versions", "project_spaces", "artifact_versions"];

/** The layout as layout.js renders it: the page title is escaped into the header heading. */
const layout = ({ title, content }) => `<html><body><h2>${String(title ?? "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")}</h2>${content}</body></html>`;

/** Drive the panel as the owner: the owner check is injected, so the reads are what is under test. */
async function view(db, params = { slug: "garden", id: "rep-1", runId: "run-1" }) {
  const res = fakeRes();
  const html = await panel.handler(fakeReq(params), res, { db, layout, lang: "en", ownerCheck: async () => true });
  return { status: res.statusCode, html: html ?? res.body ?? "", headers: res.headers };
}

/** Drive the panel with a request and an options object of the caller's own (gate refusals). */
async function raw(db, req, opts = {}) {
  const res = fakeRes();
  const html = await panel.handler(req, res, { db, layout, lang: "en", ...opts });
  return { status: res.statusCode, html: html ?? res.body ?? "", sent: res.body, headers: res.headers };
}

/** The srcdoc attribute's value, as it sits in the page (still HTML-escaped). */
const srcdocOf = (html) => (html.match(/<iframe[^>]*\bsrcdoc="([^"]*)"/) || [])[1] ?? null;

/* ------------------------------------------------------------ the owner gate (before any read) */

test("no dashboard session and the real owner check: 404 with nothing read", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  await db.execute({
    sql: "UPDATE report_runs SET status = 'failed', error_text = 'The source timed out on Tuesday.' WHERE id = 'run-1'",
    args: [],
  });
  const recorded = recordingDb(db);
  // No `ownerCheck`: the panel's own default, isLocalPasswordSessionOn.
  const { status, sent, html } = await raw(recorded, fakeReq());
  assert.equal(status, 404);
  assert.equal(sent, "Not found", "the same plain answer the widgets page gives");
  const allSql = recorded.sql.join("\n").toLowerCase();
  for (const table of GATED_TABLES) {
    assert.ok(!allSql.includes(table), `no statement names ${table} before the owner verdict`);
  }
  assert.ok(!html.includes("Weekly listings"), "no report title in the answer");
  assert.ok(!html.includes("The source timed out on Tuesday."), "no run error text in the answer");
});

test("a signed peer call carrying a dashboard session is refused the same way", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  const recorded = recordingDb(db);
  const { status, sent, html } = await raw(recorded, fakeReq(undefined, {
    crossHostAuth: true,
    dashboardSession: "a-session-token-the-owner-never-minted",
  }));
  assert.equal(status, 404);
  assert.equal(sent, "Not found");
  const allSql = recorded.sql.join("\n").toLowerCase();
  for (const table of GATED_TABLES) {
    assert.ok(!allSql.includes(table), `no statement names ${table} on a refused peer call`);
  }
  assert.ok(!html.includes("Weekly listings"));
});

test("an owner check that answers a truthy value which is not true is refused: 404 with nothing read", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  const recorded = recordingDb(db);
  const { status, sent, html } = await raw(recorded, fakeReq(), { ownerCheck: async () => "yes" });
  assert.equal(status, 404);
  assert.equal(sent, "Not found", "only a strict true opens the page");
  const allSql = recorded.sql.join("\n").toLowerCase();
  for (const table of GATED_TABLES) {
    assert.ok(!allSql.includes(table), `no statement names ${table} on a truthy non-true owner verdict`);
  }
  assert.ok(!html.includes("Weekly listings"), "no report title in the answer");
  assert.equal(recorded.sql.length, 0, "no read at all");
});

test("every answer of this panel is no-store: the refusal, the 404 page and the page", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);

  const refused = await raw(db, fakeReq());
  assert.equal(refused.status, 404);
  assert.equal(refused.headers["cache-control"], "no-store", "the gate refusal");

  const page = await view(db);
  assert.equal(page.status, 200);
  assert.equal(page.headers["cache-control"], "no-store", "the page itself");

  const missing = await view(db, { slug: "nowhere", id: "rep-1", runId: "run-1" });
  assert.equal(missing.status, 404);
  assert.ok(missing.html.includes(RUN_VIEW_MISSING_LINE));
  assert.equal(missing.headers["cache-control"], "no-store", "the page's own 404");
});

test("an injected owner still gets the page", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  const { status, html } = await view(db);
  assert.equal(status, 200);
  assert.ok(html.includes("Weekly listings"), "the report's title");
  assert.ok(html.includes(`sandbox="${FRAME_SANDBOX}"`), "the document in its own frame");
  assert.ok(html.includes(LINKS_IN_RUN_HEADING), "and the run's links listed under it");
});

/* ------------------------------------------------------------------------ the tests */

test("a slug this instance does not have is a 404 page", async () => {
  const db = await freshDb();
  await base(db);
  const { status, html } = await view(db, { slug: "nowhere", id: "rep-1", runId: "run-1" });
  assert.equal(status, 404);
  assert.ok(html.includes(RUN_VIEW_MISSING_LINE), "the plain sentence");
  assert.ok(!html.includes("srcdoc"), "no document");
});

test("a report of another project is a 404, even under its own project's slug pair", async () => {
  const db = await freshDb();
  await base(db);
  // rep-1 belongs to garden; ask for it under kitchen.
  const { status, html } = await view(db, { slug: "kitchen", id: "rep-1", runId: "run-1" });
  assert.equal(status, 404);
  assert.ok(html.includes(RUN_VIEW_MISSING_LINE));
});

test("a run of another report is a 404", async () => {
  const db = await freshDb();
  await base(db);
  // run-2 is kitchen's; ask for it under garden's report.
  const { status, html } = await view(db, { slug: "garden", id: "rep-1", runId: "run-2" });
  assert.equal(status, 404);
  assert.ok(html.includes(RUN_VIEW_MISSING_LINE));
});

test("the page shows the title, the status, the version and the frame with exactly the two sandbox tokens", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  const { status, html } = await view(db);
  assert.equal(status, 200);
  assert.ok(html.includes("Weekly listings"), "the report's title");
  assert.ok(html.includes("This run is ok"), "the run's status, as a plain line");
  assert.ok(html.includes("Version 2"), "the version the run wrote");
  assert.ok(html.includes(`sandbox="${FRAME_SANDBOX}"`));
  assert.equal(FRAME_SANDBOX, "allow-popups allow-popups-to-escape-sandbox");
  assert.ok(!/allow-scripts|allow-same-origin|allow-forms|allow-top-navigation/.test(html),
    "no other sandbox token, on the frame or anywhere else in the page");
  assert.ok(!html.includes("<script"), "no script on the page beyond what the layout adds");
  assert.ok(html.includes(BACK_TO_PROJECT_LINE));
  assert.ok(html.includes('href="/dashboard/project/garden"'), "the back link is the project home");
});

test("the frame's policy is its own, inside the srcdoc", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  const { html } = await view(db);
  const srcdoc = srcdocOf(html);
  assert.ok(srcdoc, "the frame carries the document as srcdoc");
  assert.ok(srcdoc.includes("default-src 'none'"), "the CSP meta is inside the document");
  assert.ok(srcdoc.includes("style-src 'unsafe-inline'"));
  assert.ok(srcdoc.includes("img-src data:"));
});

test("a markdown link in the version is inert inside the srcdoc", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db, {
    markdown: "# Weekly listings\n\nSee [the list](https://inline.example.com/page) for more.",
    allowedLinks: ["https://ok.example.com/x"],
  });
  const { html } = await view(db);
  const srcdoc = srcdocOf(html);
  assert.ok(srcdoc.includes("the list"), "the link's text is still there");
  assert.ok(!srcdoc.includes("href"), "no href survives into the frame");
  assert.ok(!html.includes('href="https://inline.example.com/page"'), "and the page does not link it either");

  // The stripping rule itself, on a document that carries an anchor: the tag stays, the href does not.
  const doc = frameDocument('[a link](https://inline.example.com/page)');
  assert.ok(doc.includes("a link"));
  assert.ok(!doc.includes("href"));
});

test("the allowed links are listed on the page, not in the frame", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db, { allowedLinks: ["https://ok.example.com/x", "http://also.example.com/y?z=1"] });
  const { html } = await view(db);
  assert.ok(html.includes(LINKS_IN_RUN_HEADING));
  assert.ok(html.includes(
    '<a href="https://ok.example.com/x" rel="noopener noreferrer" target="_blank">https://ok.example.com/x</a>',
  ), "an allowed link: absolute, new tab, no opener");
  assert.ok(html.includes('target="_blank"'), "and the second one too");
  const srcdoc = srcdocOf(html);
  assert.ok(!srcdoc.includes("ok.example.com"), "the list is outside the frame");
});

test("a javascript: URL in the recorded links is not listed", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db, {
    allowedLinks: ["javascript:alert(1)", "https://ok.example.com/x", "data:text/html,<b>x</b>"],
  });
  const { html } = await view(db);
  assert.ok(!html.includes("javascript:"), "not as an href, not as text");
  assert.ok(!html.includes("data:text/html"), "and no data: URL either");
  assert.ok(html.includes('href="https://ok.example.com/x"'), "the real link is still there");
});

test("a run's error text is redacted before it is shown", async () => {
  const secret = "tok-9f3c1b7d2e";
  primeSecretValues([secret]);
  const db = await freshDb();
  await base(db);
  await db.execute({
    sql: "UPDATE report_runs SET status = 'failed', error_text = ? WHERE id = 'run-1'",
    args: [`Couldn't reach https://api.example.com/items?token=${secret}`],
  });
  const { html } = await view(db);
  assert.ok(html.includes("This run failed"));
  assert.ok(!html.includes(secret), "the secret value never reaches the page");
  assert.ok(html.includes("[redacted]"));
  assert.ok(html.includes("Couldn&#39;t reach") || html.includes("Couldn't reach"));
});

test("a failed run with no version shows the status and the error, and no frame", async () => {
  const db = await freshDb();
  await base(db);
  await db.execute({
    sql: "UPDATE report_runs SET status = 'failed', error_text = 'The source timed out.' WHERE id = 'run-1'",
    args: [],
  });
  const { status, html } = await view(db);
  assert.equal(status, 200);
  assert.ok(html.includes("This run failed"));
  assert.ok(html.includes("The source timed out."));
  assert.ok(!html.includes("srcdoc"), "no document to show");
  assert.ok(!html.includes("Version "), "no version line either");
});

test("a version whose artifact row is gone says so instead of failing", async () => {
  const db = await freshDb();
  await base(db);
  await withVersion(db);
  await db.execute({ sql: "DELETE FROM artifact_versions WHERE artifact_id = 'art-1'", args: [] });
  const { status, html } = await view(db);
  assert.equal(status, 200);
  assert.ok(html.includes("Version 2"), "the run's version is still named");
  assert.ok(html.includes(VERSION_NOT_AVAILABLE_LINE));
  assert.ok(!html.includes("srcdoc"), "and no empty frame");
});

test("a report title carrying markup is escaped", async () => {
  const db = await freshDb();
  await base(db);
  await db.execute({
    sql: "UPDATE reports SET title = ? WHERE id = 'rep-1'",
    args: ["<script>alert(1)</script> Weekly"],
  });
  await withVersion(db);
  const { status, html } = await view(db);
  assert.equal(status, 200);
  assert.ok(!html.includes("<script>alert(1)</script>"), "the raw tag never reaches the page");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "escaped, in the title and the heading");
  assert.ok(!html.includes("srcdoc=\"<script"), "and not inside the frame attribute either");
});