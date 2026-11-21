// The dashboard base a report email's link and a push notification's click target are built on.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR under a temp dir, so nothing
// can touch a real Crow data dir), real project/report/recipient rows, real `crow_instances` rows keyed
// by a staged instance id, and — for the two sender tests — a stubbed `globalThis.fetch`, so no mail or
// push leaves this file. The run-view test mounts the REAL dashboard router over its own scratch data
// dir and asks it for the link's own path, with and without an owner session.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { actAsServe, serveHeaders } from "./fixtures/serve-peer.mjs";

const root = mkdtempSync(join(tmpdir(), "dashboard-link-base-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { resolveDashboardBase, resolveClickBase } = await import("../servers/gateway/dashboard-link-base.js");
const { linkFor } = await import("../servers/gateway/reports/links.js");
const { deliver } = await import("../servers/gateway/reports/delivery.js");
const { approveRecipient, proposeRecipient } = await import("../servers/gateway/reports/approvals.js");
const { createReport, getReport, updateReportColumns } = await import("../servers/gateway/reports/store.js");
const { isFunnelPublicPath } = await import("../servers/gateway/funnel.js");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 9);
const PROJECT = 7;
const REPORT_ID = "rpt-0123456789abcdef";
const RUN_ID = "rrn-0123456789abcdef";
const T0 = 1_700_000_000_000;

/** The instance id every test's own `crow_instances` row is keyed by (staged, never the real one). */
const LOCAL_ID = "0123456789abcdef0123456789abcdef";
/** The private Serve port the dashboard lives on: the answer a report email has to carry. */
const DASH = "https://crow.example.ts.net:8444";
/** The public Funnel origin: the wrong answer for /dashboard. */
const FUNNEL = "https://crow.example.ts.net";
const SLUG = "weekly-listings";

const ENV_KEYS = [
  "CROW_DASHBOARD_URL", "CROW_GATEWAY_URL", "NTFY_CLICK_BASE_URL",
  "NTFY_TOPIC", "NTFY_HOST", "NTFY_PORT",
  "RESEND_API_KEY", "MPA_EMAIL_FROM", "MPA_EMAIL_TO",
];

const open = [];

/** What `actAsServe()` overwrites (CROW_SERVE_PEER_UIDS); put back when this file is done. */
const savedServePeerUids = process.env.CROW_SERVE_PEER_UIDS;

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
  if (savedServePeerUids === undefined) delete process.env.CROW_SERVE_PEER_UIDS;
  else process.env.CROW_SERVE_PEER_UIDS = savedServePeerUids;
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  // The id this instance's own row is keyed by, so `getOrCreateLocalInstanceId` never mints a fresh one
  // in the middle of a test and every resolution below reads the same row.
  writeFileSync(join(root, "master", "instance-id"), LOCAL_ID);
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

/** Run `fn` with exactly these environment values for the keys it names, restoring everything after. */
async function withEnv(patch, fn) {
  const saved = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  for (const key of ENV_KEYS) delete process.env[key];
  Object.assign(process.env, patch);
  try {
    return await fn();
  } finally {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

/** One `crow_instances` row keyed by `id`, with whatever address the test wants it to advertise. */
async function addInstanceRow(db, id, gatewayUrl) {
  await db.execute({
    sql: `INSERT INTO crow_instances (id, name, crow_id, gateway_url, last_seen_at, status)
          VALUES (?, 'this instance', 'crow-test', ?, datetime('now'), 'active')`,
    args: [id, gatewayUrl],
  });
}

/** This instance's own registry row (the staged id), with whatever address the test wants it to advertise. */
async function addOwnRow(db, gatewayUrl) {
  await addInstanceRow(db, LOCAL_ID, gatewayUrl);
}

async function addProject(db, { id = PROJECT, slug = SLUG } = {}) {
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", slug, slug],
  });
}

function reportRow(over = {}) {
  return { id: REPORT_ID, project_id: PROJECT, comment_tier_default: "c", ...over };
}

function recipientRow(over = {}) {
  return { id: "rrc-0123456789abcdef", state: "approved", commentTier: null, ...over };
}

function approvalsDeps(over = {}) {
  return { loadSeed: () => ({ seed: SEED }), now: () => T0, getSecrets: () => [], ...over };
}

/** One report, one approved tier-c recipient, one finished run: enough for a real `deliver` pass. */
async function deliveryWorld(db) {
  await addProject(db);
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  await updateReportColumns(db, id, {
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  const proposed = await proposeRecipient(db, approvalsDeps(), {
    reportId: id, address: "alex@example.com", displayName: "Alex", commentTier: null, proposedBy: "owner",
  });
  await approveRecipient(db, approvalsDeps(), { recipientId: proposed.id, actor: OWNER });
  const report = await getReport(db, id);
  const run = { id: RUN_ID, reportId: id, trigger: "manual", requestedBy: "owner", status: "ok" };
  return { db, report, run };
}

/** The mail `deliver` builds, captured instead of sent. */
async function deliveredMail(world) {
  const calls = [];
  const counts = await deliver(world.db, {
    approvals: approvalsDeps(),
    now: () => T0,
    getSecrets: () => [],
    notify: async () => null,
    holdVersion: async () => ({}),
    sendMail: async (_db, _deps, input) => { calls.push(input); return { status: "sent" }; },
  }, { report: world.report, run: world.run, live: null, status: "ok", artifactVersion: null });
  return { counts, calls };
}

/** Capture what a sender hands `fetch`, and put the real one back afterwards. */
function captureFetch() {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init: init || {} });
    return { ok: true, status: 200, text: async () => "", body: { cancel: async () => {} } };
  };
  return {
    calls,
    restore() { globalThis.fetch = real; },
    /** The body a JSON sender posted, parsed. */
    json(index = 0) { return JSON.parse(calls[index].init.body); },
  };
}

/* --------------------------------------------------------------- the resolver */

test("CROW_DASHBOARD_URL wins over this instance's own row and over CROW_GATEWAY_URL", async () => {
  const db = await freshDb();
  await addOwnRow(db, DASH);
  const base = await resolveDashboardBase(db, {
    env: { CROW_DASHBOARD_URL: "https://dash.example.ts.net:8443", CROW_GATEWAY_URL: FUNNEL },
    localInstanceId: LOCAL_ID,
  });
  assert.equal(base, "https://dash.example.ts.net:8443");
});

test("with CROW_DASHBOARD_URL unset, this instance's own gateway_url wins over CROW_GATEWAY_URL", async () => {
  const db = await freshDb();
  await addOwnRow(db, DASH);
  const base = await resolveDashboardBase(db, {
    env: { CROW_GATEWAY_URL: FUNNEL },
    localInstanceId: LOCAL_ID,
  });
  assert.equal(base, DASH, "the private Serve port, not the Funnel origin");
});

test("an own row that is loopback, a wildcard bind or not a URL falls through to CROW_GATEWAY_URL", async () => {
  for (const own of [
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://127.1.2.3:3001",
    "http://[::1]:3001",
    "http://0.0.0.0:3001",
    "http://[::]:3001",
    "ftp://crow.example.ts.net",
    "not a url",
    "",
  ]) {
    const db = await freshDb();
    await addOwnRow(db, own);
    const base = await resolveDashboardBase(db, {
      env: { CROW_GATEWAY_URL: FUNNEL },
      localInstanceId: LOCAL_ID,
    });
    assert.equal(base, FUNNEL, own);
  }
});

test("a row this instance does not have falls through to CROW_GATEWAY_URL", async () => {
  const db = await freshDb();
  assert.equal(await resolveDashboardBase(db, {
    env: { CROW_GATEWAY_URL: FUNNEL },
    localInstanceId: LOCAL_ID,
  }), FUNNEL);
});

test("an unusable CROW_DASHBOARD_URL falls through to the own row", async () => {
  for (const bad of ["ftp://x", "not a url", "/dashboard", "", "   ", "http://0.0.0.0:3001"]) {
    const db = await freshDb();
    await addOwnRow(db, DASH);
    const base = await resolveDashboardBase(db, {
      env: { CROW_DASHBOARD_URL: bad, CROW_GATEWAY_URL: FUNNEL },
      localInstanceId: LOCAL_ID,
    });
    assert.equal(base, DASH, JSON.stringify(bad));
  }
});

test("nothing usable anywhere is an empty base, not a guess", async () => {
  const db = await freshDb();
  assert.equal(await resolveDashboardBase(db, { env: {}, localInstanceId: LOCAL_ID }), "");
  assert.equal(await resolveDashboardBase(db, {
    env: { CROW_DASHBOARD_URL: "nope", CROW_GATEWAY_URL: "ftp://x" },
    localInstanceId: LOCAL_ID,
  }), "");
});

test("a null db skips the own-row step and answers from the environment", async () => {
  for (const db of [null, undefined]) {
    assert.equal(await resolveDashboardBase(db, {
      env: { CROW_GATEWAY_URL: FUNNEL },
      localInstanceId: LOCAL_ID,
    }), FUNNEL);
    assert.equal(await resolveDashboardBase(db, {
      env: { CROW_DASHBOARD_URL: DASH },
      localInstanceId: LOCAL_ID,
    }), DASH);
    assert.equal(await resolveDashboardBase(db, { env: {}, localInstanceId: LOCAL_ID }), "");
  }
});

test("trailing slashes are trimmed, and a path on the base survives", async () => {
  const db = await freshDb();
  assert.equal(await resolveDashboardBase(db, {
    env: { CROW_DASHBOARD_URL: "https://crow.example.ts.net:8444///" },
    localInstanceId: LOCAL_ID,
  }), "https://crow.example.ts.net:8444");
  assert.equal(await resolveDashboardBase(db, {
    env: { CROW_DASHBOARD_URL: "https://crow.example.ts.net:8444/crow/" },
    localInstanceId: LOCAL_ID,
  }), "https://crow.example.ts.net:8444/crow");
  await addOwnRow(db, "https://crow.example.ts.net:8444/");
  assert.equal(await resolveDashboardBase(db, { env: {}, localInstanceId: LOCAL_ID }), DASH);
});

test("the click base takes NTFY_CLICK_BASE_URL first, trimmed, else the dashboard base", async () => {
  const db = await freshDb();
  await addOwnRow(db, DASH);
  assert.equal(await resolveClickBase(db, {
    env: { NTFY_CLICK_BASE_URL: " https://home.example.ts.net ", CROW_DASHBOARD_URL: "https://ignored.example" },
  }), "https://home.example.ts.net");
  assert.equal(await resolveClickBase(db, {
    env: { NTFY_CLICK_BASE_URL: "https://home.example.ts.net:8444//" },
  }), "https://home.example.ts.net:8444");
  for (const blank of ["", "   "]) {
    assert.equal(await resolveClickBase(db, {
      env: { NTFY_CLICK_BASE_URL: blank, CROW_DASHBOARD_URL: DASH },
      localInstanceId: LOCAL_ID,
    }), DASH, JSON.stringify(blank));
  }
  assert.equal(await resolveClickBase(db, { env: {} }), DASH,
    "no override still resolves this instance's own dashboard base");
  const bare = await freshDb();
  assert.equal(await resolveClickBase(bare, { env: {} }), "", "nothing anywhere is still empty");
});

/* ---------------------------------------------------------------- the report link */

test("with no base at all linkFor answers null: never a relative path in an email", async () => {
  const db = await freshDb();
  await addProject(db);
  await withEnv({}, async () => {
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: "",
    });
    assert.equal(link, null);
  });
});

test("an explicit baseUrl still wins over everything the resolver would answer", async () => {
  const db = await freshDb();
  await addProject(db);
  await withEnv({ CROW_DASHBOARD_URL: DASH, CROW_GATEWAY_URL: FUNNEL }, async () => {
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID },
      baseUrl: "https://explicit.example.ts.net:9443///",
    });
    assert.equal(link.kind, "dashboard");
    assert.equal(link.url, `https://explicit.example.ts.net:9443/dashboard/project/${SLUG}/reports/${REPORT_ID}/runs/${RUN_ID}`);
  });
});

test("with no baseUrl linkFor builds on the own row, not on the Funnel origin", async () => {
  const db = await freshDb();
  await addProject(db);
  await addOwnRow(db, DASH);
  await withEnv({ CROW_GATEWAY_URL: FUNNEL }, async () => {
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: null,
    });
    assert.equal(link.url, `${DASH}/dashboard/project/${SLUG}/reports/${REPORT_ID}/runs/${RUN_ID}`);
    assert.ok(!link.url.startsWith(FUNNEL + "/"), "not on the public origin");
  });
});

test("the run view's path is never under a Funnel public prefix", async () => {
  const db = await freshDb();
  await addProject(db);
  await addOwnRow(db, DASH);
  await withEnv({ CROW_GATEWAY_URL: FUNNEL }, async () => {
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: null,
    });
    const path = new URL(link.url).pathname;
    // The gateway's own allowlist function (servers/gateway/funnel.js), on the link's PATH: it is a
    // path allowlist, so a whole URL would never answer anything but "not public".
    assert.equal(isFunnelPublicPath(path), false, `${path} is a private path`);
    assert.ok(path.startsWith("/dashboard/"), path);
    // The same function says yes to a public path, so the assertion above is not vacuous.
    assert.equal(isFunnelPublicPath("/blog"), true, "/blog is public by the same function");
  });
});

test("linkFor honours a passed localInstanceId: the own row of THAT id is the base", async () => {
  const db = await freshDb();
  const OTHER_ID = "fedcba9876543210fedcba9876543210";
  const OTHER = "https://peer.example.ts.net:8555";
  await addProject(db);
  await addOwnRow(db, DASH);
  await addInstanceRow(db, OTHER_ID, OTHER);
  await withEnv({ CROW_GATEWAY_URL: FUNNEL }, async () => {
    // The caller's id decides which registry row is read, not the staged instance-id file.
    const theirs = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: null,
      localInstanceId: OTHER_ID,
    });
    assert.equal(theirs.url, `${OTHER}/dashboard/project/${SLUG}/reports/${REPORT_ID}/runs/${RUN_ID}`);

    // With none passed, the id this instance staged (LOCAL_ID) is the row that answers.
    const own = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: null,
    });
    assert.equal(own.url, `${DASH}/dashboard/project/${SLUG}/reports/${REPORT_ID}/runs/${RUN_ID}`);
  });
});

/* ------------------------------------------------------------- the email it builds */

test("the report email carries the dashboard base, not the Funnel origin", async () => {
  const db = await freshDb();
  const world = await deliveryWorld(db);
  await addOwnRow(db, DASH);
  await withEnv({ CROW_GATEWAY_URL: FUNNEL }, async () => {
    const { counts, calls } = await deliveredMail(world);
    assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
    assert.equal(calls.length, 1);
    const url = `${DASH}/dashboard/project/${SLUG}/reports/${world.report.id}/runs/${RUN_ID}`;
    assert.ok(calls[0].text.includes(url), calls[0].text);
    assert.ok(calls[0].html.includes(`href="${url}"`), "the html footer links the same door");
    assert.ok(!calls[0].text.includes(`${FUNNEL}/dashboard`), "no Funnel dashboard link");
    assert.equal(isFunnelPublicPath(new URL(url).pathname), false, "the mailed path is not public");
  });
});

/* ------------------------------------------------------------- the real run view */

/** A dashboard-scratch data dir with the rows the run view reads, and this instance's own row. */
async function routerWorld() {
  const dir = join(root, "router-" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  writeFileSync(join(dir, "instance-id"), LOCAL_ID);
  const db = createDbClient(crow);
  open.push(db);
  await addProject(db);
  await addOwnRow(db, DASH);
  await db.execute({
    sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, created_at, updated_at)
          VALUES (?, ?, 'owner', 'bot-1', 'Weekly listings', 1, 1)`,
    args: [REPORT_ID, PROJECT],
  });
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES (?, ?, 'manual', 'owner', 'ok', 1)`,
    args: [RUN_ID, REPORT_ID],
  });
  const { hashToken } = await import("../servers/gateway/dashboard/auth.js");
  await db.execute({
    sql: `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at)
          VALUES (?, 'access', 'dashboard', 'dashboard', datetime('now', '+1 day'), datetime('now'))`,
    args: [hashToken("owner-session")],
  });
  return { dir, db };
}

/** The real dashboard router over `dir`, as the gateway mounts it. */
async function startRouter() {
  const { default: dashboardRouter } = await import("../servers/gateway/dashboard/index.js");
  const { default: express } = await import("express");
  const app = express();
  app.use((req, res, next) => { res.redirectAfterPost = (url) => res.redirect(303, url); next(); });
  app.use(dashboardRouter((req, res, next) => next()));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test("the link's own path opens the run view on the real router with an owner session", async () => {
  const world = await routerWorld();
  const { server, base } = await startRouter();
  const savedDbPath = process.env.CROW_DB_PATH;
  process.env.CROW_DB_PATH = join(world.dir, "crow.db");
  actAsServe();
  try {
    const link = await withEnv({ CROW_GATEWAY_URL: FUNNEL }, async () => linkFor(world.db, {
      report: reportRow({ id: REPORT_ID }), recipient: recipientRow(), run: { id: RUN_ID }, baseUrl: null,
    }));
    const path = new URL(link.url).pathname + new URL(link.url).search;

    const owner = await fetch(base + path, {
      redirect: "manual",
      headers: { ...serveHeaders("operator@example.com"), cookie: "crow_session=owner-session" },
    });
    const ownerBody = await owner.text();
    assert.equal(owner.status, 200, ownerBody.slice(0, 200));
    assert.ok(ownerBody.includes("Weekly listings"), "the run page, not a 404");

    const anonymous = await fetch(base + path, {
      redirect: "manual",
      headers: { ...serveHeaders("operator@example.com") },
    });
    const anonymousBody = await anonymous.text();
    assert.notEqual(anonymous.status, 200);
    assert.ok(!anonymousBody.includes("Weekly listings"), "no report content without a session");
  } finally {
    if (savedDbPath === undefined) delete process.env.CROW_DB_PATH;
    else process.env.CROW_DB_PATH = savedDbPath;
    server.close();
  }
});

/* ----------------------------------------------------------------- the senders */

test("the email sender's click link: NTFY_CLICK_BASE_URL, then the own row, then CROW_GATEWAY_URL", async () => {
  const db = await freshDb();
  await addOwnRow(db, DASH);
  const { sendEmailNotification } = await import("../servers/gateway/push/email.js");
  const mailEnv = {
    RESEND_API_KEY: "re_test", MPA_EMAIL_FROM: "reports@example.com", MPA_EMAIL_TO: "alex@example.com",
  };

  const capture = captureFetch();
  try {
    // The override wins.
    await withEnv({ ...mailEnv, NTFY_CLICK_BASE_URL: "https://home.example.ts.net:8444", CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendEmailNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db });
    });
    assert.ok(capture.json(0).text.includes("https://home.example.ts.net:8444/dashboard/reports"));

    // No override: this instance's own row beats the Funnel origin.
    await withEnv({ ...mailEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendEmailNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db });
    });
    assert.ok(capture.json(1).text.includes(`${DASH}/dashboard/reports`), capture.json(1).text);
    assert.ok(!capture.json(1).text.includes(`${FUNNEL}/dashboard`));

    // No row and no override: CROW_GATEWAY_URL is the last word.
    const bare = await freshDb();
    await withEnv({ ...mailEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendEmailNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db: bare });
    });
    assert.ok(capture.json(2).text.includes(`${FUNNEL}/dashboard/reports`));

    // An absolute url is passed through unchanged.
    await withEnv({ ...mailEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendEmailNotification({
        title: "Weekly listings", body: "ready", url: "https://elsewhere.example/page", priority: "high", db,
      });
    });
    assert.ok(capture.json(3).text.includes("https://elsewhere.example/page"));
    assert.ok(!capture.json(3).text.includes(`${FUNNEL}/dashboard`));
  } finally {
    capture.restore();
  }
});

test("the ntfy sender's click link uses the same order, and leaves an absolute url alone", async () => {
  const db = await freshDb();
  await addOwnRow(db, DASH);
  const { sendNtfyNotification } = await import("../servers/gateway/push/ntfy.js");
  const ntfyEnv = { NTFY_TOPIC: "crow-test", NTFY_HOST: "127.0.0.1", NTFY_PORT: "2586" };

  const capture = captureFetch();
  try {
    await withEnv({ ...ntfyEnv, NTFY_CLICK_BASE_URL: "https://home.example.ts.net:8444", CROW_GATEWAY_URL: FUNNEL }, async () => {
      const r = await sendNtfyNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db });
      assert.equal(r.ok, true);
    });
    assert.equal(capture.calls[0].init.headers["X-Click"], "https://home.example.ts.net:8444/dashboard/reports");

    await withEnv({ ...ntfyEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendNtfyNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db });
    });
    assert.equal(capture.calls[1].init.headers["X-Click"], `${DASH}/dashboard/reports`);

    const bare = await freshDb();
    await withEnv({ ...ntfyEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendNtfyNotification({ title: "Weekly listings", body: "ready", url: "/dashboard/reports", priority: "high", db: bare });
    });
    assert.equal(capture.calls[2].init.headers["X-Click"], `${FUNNEL}/dashboard/reports`);

    await withEnv({ ...ntfyEnv, CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendNtfyNotification({ title: "Weekly listings", body: "ready", url: "https://elsewhere.example/page", priority: "high", db });
    });
    assert.equal(capture.calls[3].init.headers["X-Click"], "https://elsewhere.example/page");
  } finally {
    capture.restore();
  }
});

test("a sender called without a db still answers from the environment", async () => {
  const { sendNtfyNotification } = await import("../servers/gateway/push/ntfy.js");
  const capture = captureFetch();
  try {
    await withEnv({ NTFY_TOPIC: "crow-test", NTFY_HOST: "127.0.0.1", NTFY_PORT: "2586", CROW_GATEWAY_URL: FUNNEL }, async () => {
      await sendNtfyNotification({ title: "Weekly listings", url: "/dashboard/reports", priority: "high" });
    });
    assert.equal(capture.calls[0].init.headers["X-Click"], `${FUNNEL}/dashboard/reports`);
  } finally {
    capture.restore();
  }
});