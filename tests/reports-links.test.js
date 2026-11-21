// Where a report email's link points: the link kind a recipient's comment tier earns, and the URL.
//
// Harness: a real init-db'd scratch crow.db (so `project_spaces` is the real table, with its own slug
// column) copied per test, with the project rows a report names written by hand. Nothing here sends
// anything: this module is two reads and one string.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-links-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  baseUrlOf, commentTierOf, isAbsoluteHttpUrl, linkFor, projectSlug, publicLinkFor, reportPagePath,
} = await import("../servers/gateway/reports/links.js");

const PROJECT = 7;
const BASE = "https://crow.example.ts.net";
const REPORT_ID = "rpt-0123456789abcdef";
const RUN_ID = "rrn-0123456789abcdef";

const open = [];

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

let n = 0;

async function freshDb() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

async function addProject(db, { id = PROJECT, slug = "weekly-listings" } = {}) {
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", slug, slug],
  });
}

function reportRow(over = {}) {
  return {
    id: REPORT_ID,
    project_id: PROJECT,
    comment_tier_default: "c",
    ...over,
  };
}

function runRow(over = {}) {
  return { id: RUN_ID, reportId: REPORT_ID, status: "ok", ...over };
}

function recipientRow(over = {}) {
  return { id: "rrc-0123456789abcdef", state: "approved", commentTier: null, ...over };
}

/* ------------------------------------------------------------------------ the URL */

test("tier c gets the dashboard run page, with every odd character encoded", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow(),
    recipient: recipientRow(),
    run: runRow({ id: "rrn-a b/c?d#e" }),
    sendId: null,
    baseUrl: `${BASE}/`,
  });
  assert.deepEqual(link, {
    kind: "dashboard",
    url: `${BASE}/dashboard/project/weekly-listings/reports/${REPORT_ID}/runs/rrn-a%20b%2Fc%3Fd%23e`,
  });
});

test("tier c on a missing project row is no link at all", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow({ project_id: PROJECT + 1 }),
    recipient: recipientRow(),
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(link, null, "a report whose project this instance does not have has no page");
  assert.equal(await projectSlug(db, reportRow({ project_id: null })), null, "no project, no slug");
});

test("tiers a and b have no link kind yet, and that is the seam PR 6a fills", async () => {
  const db = await freshDb();
  await addProject(db);
  for (const tier of ["a", "b"]) {
    assert.equal(await linkFor(db, {
      report: reportRow(),
      recipient: recipientRow({ commentTier: tier }),
      run: runRow(),
      baseUrl: BASE,
    }), null, `tier ${tier}`);
  }
  assert.equal(publicLinkFor(), null, "the public kinds are the one seam this PR leaves closed");
  // The tier a reader has when their own row names none: the report's default, which may itself be a or b.
  assert.equal(await linkFor(db, {
    report: reportRow({ comment_tier_default: "a" }),
    recipient: recipientRow({ commentTier: null }),
    run: runRow(),
    baseUrl: BASE,
  }), null);
});

test("a recipient with no tier of their own takes the report's default", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow({ comment_tier_default: "c" }),
    recipient: recipientRow({ commentTier: null }),
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(link.kind, "dashboard");

  // A stored (snake_case) recipient row reads the same way, and an empty tier is "the report's default".
  const stored = await linkFor(db, {
    report: reportRow(),
    recipient: { id: "rrc-0123456789abcdef", state: "approved", comment_tier: "" },
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(stored.kind, "dashboard");
  assert.equal(commentTierOf(reportRow(), null), "c", "no recipient and no default is tier c");
  assert.equal(commentTierOf(reportRow({ comment_tier_default: "b" }), null), "b");
});

test("with no base URL the answer is the path only, so a caller can refuse to mail it", async () => {
  const db = await freshDb();
  await addProject(db);
  const saved = process.env.CROW_GATEWAY_URL;
  delete process.env.CROW_GATEWAY_URL;
  try {
    const link = await linkFor(db, {
      report: reportRow(),
      recipient: recipientRow(),
      run: runRow(),
      baseUrl: "",
    });
    assert.deepEqual(link, {
      kind: "dashboard",
      url: `/dashboard/project/weekly-listings/reports/${REPORT_ID}/runs/${RUN_ID}`,
    });
    assert.ok(link.url.startsWith("/"), "a path, not a URL");
    assert.equal(isAbsoluteHttpUrl(link.url), false, "a mail client cannot open it");
  } finally {
    if (saved !== undefined) process.env.CROW_GATEWAY_URL = saved;
  }
});

test("the base URL is the caller's, else this instance's own, with trailing slashes trimmed", async () => {
  const db = await freshDb();
  await addProject(db);
  const saved = process.env.CROW_GATEWAY_URL;
  try {
    process.env.CROW_GATEWAY_URL = "https://crow.example.ts.net///";
    assert.equal(baseUrlOf(null), "https://crow.example.ts.net");
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: runRow(), baseUrl: null,
    });
    assert.ok(link.url.startsWith("https://crow.example.ts.net/dashboard/project/"), link.url);
    assert.equal(baseUrlOf("http://127.0.0.1:8080/"), "http://127.0.0.1:8080");
    assert.equal(baseUrlOf(undefined), "https://crow.example.ts.net", "the instance's own wins last");
  } finally {
    if (saved === undefined) delete process.env.CROW_GATEWAY_URL;
    else process.env.CROW_GATEWAY_URL = saved;
  }
});

test("only an absolute http or https URL is a link delivery may mail", () => {
  for (const good of ["https://crow.example.ts.net/x", "http://127.0.0.1:8080/x", " https://a.example/x "]) {
    assert.equal(isAbsoluteHttpUrl(good), true, good);
  }
  for (const bad of ["/dashboard/x", "", null, undefined, 7, "javascript:alert(1)", "mailto:alex@example.com",
    "//crow.example.ts.net/x", "ftp://crow.example.ts.net/x", "not a url"]) {
    assert.equal(isAbsoluteHttpUrl(bad), false, String(bad));
  }
});

/* --------------------------------------------------------------- the report's page */

test("the owner's notice for a report goes to its page, or the reports list", async () => {
  const db = await freshDb();
  await addProject(db);
  assert.equal(await reportPagePath(db, reportRow()), `/dashboard/project/weekly-listings/reports/${REPORT_ID}`);
  assert.equal(await reportPagePath(db, reportRow({ project_id: 999 })), "/dashboard/reports");
  assert.equal(await reportPagePath(db, null), "/dashboard/reports");
});