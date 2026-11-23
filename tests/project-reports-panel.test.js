/**
 * Crow Recurring Reports, task 9b: a project's Reports list and one report's page.
 *
 * Two harnesses in one file:
 *   - the real dashboard router (dashboardAuth, csrfMiddleware, the panel dispatch, the shell, the
 *     slug-scoped scope) over a scratch CROW_DATA_DIR and a scratch CROW_HOME, with real report rows in
 *     real tables. Requests carry Serve's headers so isAllowedNetwork admits them, and the owner is a
 *     session row with the plain `dashboard` scope the local password login mints; a guest session is a
 *     `dashboard onhost` login, which reads the reduced page, and a peer sign-in session (scope
 *     `dashboard sso src:peer-1`, as tests/reports-schedule-route.test.js mints one) is refused outright;
 *   - the page's own markup, data block and client run in linkedom + node:vm with fetch stubbed (as
 *     tests/project-services-client.test.js does), for the two "posts to the owner route" checks.
 *
 * Nothing here touches ~/.crow, and no request leaves this machine.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { parseHTML } from "linkedom";
import { actAsServe, serveHeaders } from "./fixtures/serve-peer.mjs";
import { fromLaptop } from "./helpers/off-box.js";

actAsServe();

const dir = mkdtempSync(join(tmpdir(), "project-reports-page-"));
process.env.CROW_DATA_DIR = dir;
const HOME = join(dir, "home");
process.env.CROW_HOME = HOME;
mkdirSync(HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
delete process.env.CROW_SERVICES_UI;
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.PIBOT_PI_CLI = "/nonexistent/pi-never-spawned-by-this-file.js";
const DB_FILE = join(dir, "crow.db");
writeFileSync(join(dir, "instance-id"), "instance-project-reports");
writeFileSync(join(HOME, "installed.json"), JSON.stringify([]));
const REPO = new URL("..", import.meta.url).pathname;

const OWNER = "owner-sess";
const GUEST = "guest-sess";
const PEER = "peer-sess";
const GARDEN = 1;
const KITCHEN = 2;
const LISTINGS = "rpt-0000000000000001";
const DRAFT = "rpt-0000000000000002";
const ELSEWHERE = "rpt-0000000000000003";
const PAUSED = "rpt-0000000000000004";
const UTC_ONE = "rpt-0000000000000005";
const LIVE_STALE = "rpt-0000000000000006";
const RUN_OK = "rrn-0000000000000001";
const RUN_LATE = "rrn-0000000000000002";
const RUN_FAILED = "rrn-0000000000000003";
const RUN_PREVIEW = "rrn-0000000000000004";
const SENDER_ACCOUNT = "ma-0000000000000001";
const SENDER_ADDRESS = "hello@example.com";
const RECIPIENT = "person@example.com";
const PROPOSED = "newperson@example.com";
const MISSING_LINE = "This project isn't here";
const NEXT_RUN = "2099-01-15T09:00:00.000Z";

let server;
let base;
let MODE;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  const { hashToken } = await import("../servers/gateway/dashboard/auth.js");
  const { createDbClient } = await import("../servers/db.js");
  const { initArtifactsTables } = await import("../bundles/artifacts/server/init-tables.js");
  const db = createDbClient();
  try {
    await db.execute({
      sql: "INSERT INTO project_spaces (id, slug, name, type, status, archived_at) VALUES (?, ?, ?, 'general', 'active', NULL)",
      args: [GARDEN, "garden", "Garden"],
    });
    await db.execute({
      sql: "INSERT INTO project_spaces (id, slug, name, type, status, archived_at) VALUES (?, ?, ?, 'general', 'active', NULL)",
      args: [KITCHEN, "kitchen", "Kitchen"],
    });
    await db.execute({
      sql: "INSERT INTO project_spaces (id, slug, name, type, status, archived_at) VALUES (3, 'attic', 'Attic', 'general', 'archived', '2026-01-01 00:00:00')",
      args: [],
    });
    // The owner's own password session, a login from this machine (a reader, never the owner), and a
    // session a paired instance minted through SSO (the shape tests/reports-schedule-route.test.js uses).
    await db.execute({
      sql: "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) VALUES (?, 'access', 'dashboard', 'dashboard', datetime('now','+1 day'), '2026-06-01 00:00:00')",
      args: [hashToken(OWNER)],
    });
    await db.execute({
      sql: "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) VALUES (?, 'access', 'dashboard', 'dashboard onhost', datetime('now','+1 day'), '2026-06-01 00:00:00')",
      args: [hashToken(GUEST)],
    });
    await db.execute({
      sql: "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) VALUES (?, 'access', 'dashboard', 'dashboard sso src:peer-1', datetime('now','+1 day'), '2026-06-01 00:00:00')",
      args: [hashToken(PEER)],
    });
    // The mail account the live report sends from.
    await db.execute({
      sql: `INSERT INTO mail_accounts (id, address, label, provider, imap_host, imap_port, smtp_host, smtp_port, created_at, updated_at)
            VALUES ('ma-0000000000000001', ?, 'main', 'other', 'imap.example.com', 993, 'smtp.example.com', 465, 1, 1)`,
      args: [SENDER_ADDRESS],
    });
    // The report rows: a live one with a schedule, a draft, one in another project, a paused one with a
    // reason and a usable preview, and a second live one in UTC.
    const recipe = JSON.stringify({
      blocks: [
        { id: "intro", type: "text", settings: { heading: "This week", content: "Five new listings." } },
        { id: "source", type: "fetch", settings: { url: "https://example.com/items", api_key: "not-for-the-page" } },
      ],
    });
    const report = (id, projectId, title, status, extra = {}) => db.execute({
      sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, status, recipe_json, recipe_rev,
              delivery_mode, comment_tier_default, comment_visibility, ai_commentary, pause_reason,
              sender_account_id, created_at, updated_at)
            VALUES (?, ?, 'owner', 'casa', ?, ?, ?, ?, ?, 'c', 'own', ?, ?, ?, ?, ?)`,
      args: [
        id, projectId, title, status, extra.recipe || recipe, extra.recipeRev ?? 1,
        extra.delivery || "email_link", extra.ai ?? 0, extra.pauseReason ?? null,
        extra.sender ?? null, extra.createdAt || 1, 1,
      ],
    });
    await report(LISTINGS, GARDEN, "Weekly listings", "live", { sender: "ma-0000000000000001", createdAt: 5 });
    await report(DRAFT, GARDEN, "A draft report", "draft", { recipeRev: 0, createdAt: 4 });
    await report(ELSEWHERE, KITCHEN, "Kitchen list", "draft", { recipeRev: 0, createdAt: 3 });
    await report(PAUSED, GARDEN, "Paused report", "paused", { recipeRev: 0, pauseReason: "The recipe changed. Check it and go live again.", createdAt: 2 });
    await report(UTC_ONE, GARDEN, "UTC report", "live", { recipeRev: 0, createdAt: 1 });
    // Live status, a schedule whose window is ahead, and no seal: the approval does not verify.
    await report(LIVE_STALE, GARDEN, "A stale live report", "live", { recipeRev: 0, createdAt: 6 });
    // The schedules: the live ones are on, the draft has none.
    const schedule = (reportId, cron, tz) => db.execute({
      sql: "INSERT INTO schedules (task, cron_expression, tz, enabled, next_run) VALUES (?, ?, ?, 1, ?)",
      args: [`report:${reportId}`, cron, tz, NEXT_RUN],
    });
    await schedule(LISTINGS, "0 9 * * 1", "Asia/Tokyo");
    await schedule(UTC_ONE, "0 9 * * 1", "UTC");
    await schedule(LIVE_STALE, "0 9 * * 1", "UTC");
    // Point the reports at their own schedule rows.
    await db.execute({
      sql: "UPDATE reports SET schedule_id = (SELECT id FROM schedules WHERE task = ?) WHERE id = ?",
      args: [`report:${LISTINGS}`, LISTINGS],
    });
    await db.execute({
      sql: "UPDATE reports SET schedule_id = (SELECT id FROM schedules WHERE task = ?) WHERE id = ?",
      args: [`report:${UTC_ONE}`, UTC_ONE],
    });
    await db.execute({
      sql: "UPDATE reports SET schedule_id = (SELECT id FROM schedules WHERE task = ?) WHERE id = ?",
      args: [`report:${LIVE_STALE}`, LIVE_STALE],
    });
    // The recipients: one approved, one proposed.
    await db.execute({
      sql: `INSERT INTO report_recipients (id, report_id, address, display_name, comment_tier, state, proposed_by, created_at)
            VALUES ('rrc-0000000000000001', ?, ?, NULL, 'b', 'approved', 'owner', 1)`,
      args: [LISTINGS, RECIPIENT],
    });
    await db.execute({
      sql: `INSERT INTO report_recipients (id, report_id, address, display_name, comment_tier, state, proposed_by, created_at)
            VALUES ('rrc-0000000000000002', ?, ?, NULL, NULL, 'proposed', 'bot:casa', 2)`,
      args: [LISTINGS, PROPOSED],
    });
    // The runs: a manual ok run with a version, a late scheduled run with an unknown send, a failed one.
    const run = (id, reportId, trigger, status, extra = {}) => db.execute({
      sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, late, started_at, ended_at,
              status, recipe_rev, error_text, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        id, reportId, trigger, extra.requestedBy || "owner", extra.late ?? 0,
        extra.startedAt ?? 1767603600000, extra.endedAt ?? 1767603660000, status,
        extra.recipeRev ?? null, extra.errorText ?? null, extra.createdAt || 1,
      ],
    });
    await run(RUN_OK, LISTINGS, "manual", "ok", { createdAt: 3 });
    await run(RUN_LATE, LISTINGS, "schedule", "ok", { requestedBy: "schedule", late: 1, createdAt: 2 });
    await run(RUN_FAILED, LISTINGS, "schedule", "failed", { requestedBy: "schedule", errorText: "Couldn't reach the listings page.", createdAt: 1 });
    await run(RUN_PREVIEW, PAUSED, "preview", "ok", { recipeRev: 0, createdAt: 1 });
    // The send log: one went, one is unknown, so the schedule run offers "Send to the rest".
    const send = (id, runId, recipientId, status) => db.execute({
      sql: `INSERT INTO report_sends (id, run_id, report_id, recipient_id, attempt, account_id, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 'ma-0000000000000001', ?, 1, 1)`,
      args: [id, runId, LISTINGS, recipientId, status],
    });
    await send("rsd-0000000000000001", RUN_LATE, "rrc-0000000000000001", "sent");
    await send("rsd-0000000000000002", RUN_LATE, "rrc-0000000000000002", "unknown");
    // The artifacts: one version the first run wrote, and one that retention pruned.
    await initArtifactsTables(db);
    await db.execute({
      sql: "INSERT INTO artifacts (id, title, type, current_version) VALUES ('art-1', 'Weekly listings', 'document', 2)",
      args: [],
    });
    await db.execute({
      sql: `INSERT INTO artifact_versions (artifact_id, n, state, files_json, source_json, size, content_hash, made_by)
            VALUES ('art-1', 2, 'current', '[]', ?, 0, 'hash', 'user')`,
      args: [JSON.stringify({ markdown: "# Weekly listings\n\n- one", title: "Weekly listings" })],
    });
    await db.execute({
      sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
            VALUES ('art-1', 2, ?, ?, 'manual', '[]', 1)`,
      args: [LISTINGS, RUN_OK],
    });
    await db.execute({
      sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
            VALUES ('art-2', 7, ?, ?, 'schedule', '[]', 1)`,
      args: [LISTINGS, RUN_LATE],
    });
    // The two live reports are approved the way the product does it: one saved revision, a fresh nonce
    // and the live-set seal over the fields the page's own approvals reader builds. The scratch HOME
    // holds the keychain key, so the page verifies them through the real path. The stale report above
    // keeps no seal, which is a live report whose approval does not verify.
    const { createKeychainKey } = await import("../servers/gateway/keychain/key.js");
    const { approvalSeal, newApprovalNonce } = await import("../servers/gateway/reports/seal.js");
    const { liveSetFor } = await import("../servers/gateway/reports/approvals.js");
    const { buildApprovalsDeps } = await import("../servers/gateway/reports/approvals-deps.js");
    const { getReport: readReport } = await import("../servers/gateway/reports/store.js");
    const { canonicalJson, recipeHash, sourcesHash } = await import("../servers/gateway/reports/recipe-hash.js");
    const { blockRegistry } = await import("../servers/gateway/reports/blocks/index.js");
    const seed = createKeychainKey().seed;
    const approvalsDeps = buildApprovalsDeps();
    for (const id of [LISTINGS, UTC_ONE]) {
      const head = await readReport(db, id);
      const recipe = JSON.parse(head.recipe_json);
      const hash = recipeHash(recipe);
      const sources = sourcesHash(recipe, blockRegistry);
      await db.execute({
        sql: `INSERT INTO report_recipe_revisions (report_id, rev, recipe_json, recipe_hash, sources_hash, author_kind, created_at)
              VALUES (?, 1, ?, ?, ?, 'owner', 1)`,
        args: [id, canonicalJson(recipe), hash, sources],
      });
      await db.execute({
        sql: "UPDATE reports SET recipe_rev = 1, recipe_hash = ?, sources_hash = ?, live_rev = 1, live_nonce = ? WHERE id = ?",
        args: [hash, sources, newApprovalNonce(), id],
      });
      const row = await readReport(db, id);
      const fields = await liveSetFor(db, approvalsDeps, row, { modelRef: "" });
      await db.execute({
        sql: "UPDATE reports SET live_seal = ? WHERE id = ?",
        args: [approvalSeal("live", fields, seed), id],
      });
    }
  } finally {
    db.close();
  }

  const mode = await import("../servers/gateway/dashboard/shell/mode.js");
  MODE = mode.cookieName(mode.MODE_COOKIE);
  const { default: dashboardRouter } = await import("../servers/gateway/dashboard/index.js");
  const { default: express } = await import("express");
  const app = express();
  app.use((req, res, next) => {
    res.redirectAfterPost = (url) => res.redirect(303, url);
    // `x-test-crosshost: 1` stands in for the gateway's cross-host verifier, which marks a request
    // carrying a peer's signature with req.crossHostAuth before the dashboard router.
    if (req.headers["x-test-crosshost"] === "1") req.crossHostAuth = { ok: true };
    next();
  });
  app.use(express.json({ limit: "1mb" }));
  app.use(dashboardRouter((req, res, next) => next()));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = "http://127.0.0.1:" + server.address().port;
});

after(() => {
  server?.closeAllConnections?.();
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

const NET = serveHeaders("operator@example.com");
const cookieHeader = (jar) => Object.entries(jar).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("; ");

/** One page as the owner (or as a guest or a peer sign-in, with `session`) sees it. */
async function get(path, { session = OWNER, mode = "new", crossHost = false } = {}) {
  const headers = { ...NET, cookie: cookieHeader({ crow_session: session, [MODE]: mode }) };
  if (crossHost) headers["x-test-crosshost"] = "1";
  const r = await fetch(base + path, { redirect: "manual", headers });
  return { status: r.status, location: r.headers.get("location"), cache: r.headers.get("cache-control"), body: await r.text() };
}

const listPath = (slug = "garden") => `/dashboard/project/${slug}/reports`;
const pagePath = (id, slug = "garden") => `/dashboard/project/${slug}/reports/${id}`;

/** The inert JSON block the panel hands the client, parsed, or null when the page carries none. */
function dataBlockOf(body) {
  const at = body.indexOf("data-rp-data>");
  if (at < 0) return null;
  const from = at + "data-rp-data>".length;
  return JSON.parse(body.slice(from, body.indexOf("</script>", from)));
}

/** The panel's own markup, style block removed: from its root element to the end of <main> (where its
 *  script would sit). The CSS is not markup: it names classes the reduced page never uses. */
function panelOf(body) {
  const start = body.indexOf('<div class="rp"');
  if (start < 0) return "";
  const end = body.indexOf("</main>", start);
  return body.slice(start, end > start ? end : body.length).replace(/<style>[\s\S]*?<\/style>/g, "");
}

/* ------------------------------------------------------------------ the server pages */

test("list shows next run in report tz", async () => {
  const r = await get(listPath());
  assert.equal(r.status, 200);
  assert.equal(r.cache, "no-store", "a page that names reports is never cached");
  assert.match(r.body, /Weekly listings/);
  // 09:00 UTC is 18:00 in the report's own zone (Asia/Tokyo), and the zone is named beside it.
  const tokyo = r.body.slice(r.body.indexOf("Weekly listings"));
  assert.match(tokyo.slice(0, 900), /Next run: [^<]*6:00 PM/);
  assert.match(tokyo.slice(0, 900), /GMT\+9|JST/);
  // The same instant, read in the other report's zone, is a different time on the same page.
  assert.match(r.body, /Next run: [^<]*9:00 AM UTC/);
  // A draft shows its status in the next-run place instead of a time.
  assert.match(r.body, /rp-row-text[\s\S]*?A draft report[\s\S]*?<span class="rp-meta">Draft<\/span>/);
});

test("a live report whose approval does not verify shows no next run", async () => {
  const list = await get(listPath());
  const start = list.body.indexOf("A stale live report");
  assert.ok(start > 0, "the report is on the list");
  const card = list.body.slice(start, list.body.indexOf("</li>", start));
  assert.ok(!card.includes("Next run:"), "a report whose seal does not verify names no time");
  assert.match(card, /<span class="rp-meta">Paused<\/span>/, "it carries the word a paused report does");
  // The same report's own page says it in the next-run place, beside its live chip.
  const page = await get(pagePath(LIVE_STALE));
  assert.equal(page.status, 200);
  assert.match(page.body, /rp-chip--live/);
  assert.match(page.body, /<p class="rp-next">Paused<\/p>/);
});

test("a paused report shows its reason under its name, and the list keeps its buttons for the owner", async () => {
  const r = await get(listPath());
  assert.equal(r.status, 200);
  assert.match(r.body, /The recipe changed\. Check it and go live again\./);
  assert.match(r.body, /data-rp-action="pause" data-rp-report="rpt-0000000000000001"/);
  assert.match(r.body, /data-rp-action="resume" data-rp-report="rpt-0000000000000004"/);
  // The approved recipient's count, and never an address.
  assert.match(r.body, /Recipients: 1/);
  assert.ok(!r.body.includes(RECIPIENT), "an address is not on the list page");
  // "Open latest" points at the run whose version is still there.
  assert.match(r.body, new RegExp(`href="/dashboard/project/garden/reports/${LISTINGS}/runs/${RUN_OK}"`));
});

test("non-owner sees no write buttons", async () => {
  for (const path of [listPath(), pagePath(LISTINGS)]) {
    const r = await get(path, { session: GUEST });
    assert.equal(r.status, 200, `${path} still renders`);
    const start = r.body.indexOf('<div class="rp"');
    assert.ok(start > 0, `${path}: the page is there`);
    const end = r.body.indexOf("</main>", start);
    const panel = r.body.slice(start, end > start ? end : r.body.length);
    assert.match(panel, /Weekly listings/, "the report's name is there");
    assert.ok(!panel.includes("<button"), `${path}: no button in the page`);
    assert.ok(!panel.includes("<form"), `${path}: no form in the page`);
    assert.ok(!r.body.includes("data-rp-action"), `${path}: nothing for the client to wire`);
    assert.ok(!r.body.includes("data-rp-data"), `${path}: no client data block`);
    assert.ok(!r.body.includes("/dashboard/api/reports"), `${path}: no API path either`);
    assert.ok(!r.body.includes("data-rp-status"), `${path}: no status line`);
    assert.ok(!r.body.includes(RECIPIENT), `${path}: no recipient address`);
    assert.ok(!r.body.includes(PROPOSED), `${path}: no proposed address`);
    assert.ok(!r.body.includes(SENDER_ADDRESS), `${path}: no sender account`);
    assert.ok(!r.body.includes("Recipients:"), `${path}: no recipient count`);
    assert.ok(!panel.includes("<input"), `${path}: no schedule input`);
    assert.ok(!panel.includes("Steps"), `${path}: no step list`);
    if (path === pagePath(LISTINGS)) {
      assert.ok(panel.includes("Run history"), `${path}: the history is still there`);
      assert.match(panel, /Version 2/, `${path}: the version text is there for a reader`);
      assert.ok(!panel.includes(`/runs/${RUN_OK}"`), `${path}: but not as a link (the run view is the owner's)`);
    }
  }
});

test("a peer sign-in session gets 404 with no data", async () => {
  for (const path of [listPath(), pagePath(LISTINGS), pagePath(PAUSED), listPath("nowhere")]) {
    const r = await get(path, { session: PEER });
    assert.equal(r.status, 404, path);
    assert.equal(r.cache, "no-store", `${path}: the refusal is never cached`);
    assert.equal(r.body, "Not found", `${path}: the whole answer is the refusal`);
    assert.ok(!r.body.includes("Weekly listings"), `${path}: no report title`);
    assert.ok(!r.body.includes("Paused report"), `${path}: no paused report's name`);
    assert.ok(!r.body.includes("Garden"), `${path}: no project name`);
    assert.ok(!r.body.includes(MISSING_LINE), `${path}: and no project page either`);
  }
  // The guest login from this machine still gets its page: the refusal is the peer scope, not a session.
  assert.equal((await get(listPath(), { session: GUEST })).status, 200);
});

test("a crossHostAuth request gets 404", async () => {
  for (const path of [listPath(), pagePath(LISTINGS)]) {
    const r = await get(path, { crossHost: true });
    assert.equal(r.status, 404, path);
    assert.equal(r.cache, "no-store", path);
    assert.equal(r.body, "Not found", path);
    assert.ok(!r.body.includes("Weekly listings"), `${path}: no report title`);
    assert.ok(!r.body.includes("Garden"), `${path}: no project name`);
  }
  // A direct call, with the mark a signing gate sets on the request: the same refusal, and no page.
  const { default: panel } = await import("../servers/gateway/dashboard/panels/project-reports.js");
  const { isLocalPasswordSessionOn } = await import("../servers/gateway/dashboard/local-session.js");
  const { createDbClient } = await import("../servers/db.js");
  const db = createDbClient();
  try {
    const seen = { status: 0, body: null, headers: {} };
    const res = {
      set(k, v) { seen.headers[k] = v; return this; },
      status(n) { seen.status = n; return this; },
      type() { return this; },
      send(body) { seen.body = body; return this; },
      redirect() { throw new Error("a refused request is never answered with a page"); },
    };
    const req = fromLaptop({
      method: "GET",
      params: { slug: "garden", id: LISTINGS },
      dashboardSession: OWNER,
      crossHostAuth: { ok: true },
      crowMode: { mode: "new" },
    });
    const out = await panel.handler(req, res, { db, lang: "en", layout: () => "page" });
    assert.equal(out, null);
    assert.equal(seen.status, 404);
    assert.equal(seen.body, "Not found");
    assert.equal(seen.headers["Cache-Control"], "no-store");
    // The same session without the peer mark is the owner, so the mark is what turned it away.
    assert.equal(await isLocalPasswordSessionOn(db, fromLaptop({ dashboardSession: OWNER })), true);
  } finally {
    db.close();
  }
});

test("the member page has no pause reason, no error text, no sender, no addresses", async () => {
  const secrets = [
    "The recipe changed.", // the paused report's pause_reason
    "reach the listings page", // the failed run's error text
    SENDER_ADDRESS, RECIPIENT, PROPOSED,
    "Sends from:", "Recipients:",
    "https://example.com/items", "This week", // a recipe block's settings
    "data-rp-preview", "rp-banner",
  ];
  for (const path of [listPath(), pagePath(LISTINGS), pagePath(PAUSED)]) {
    const r = await get(path, { session: GUEST });
    assert.equal(r.status, 200, path);
    const panel = panelOf(r.body);
    assert.ok(panel.length > 0, `${path}: the page is there`);
    for (const secret of secrets) assert.ok(!panel.includes(secret), `${path}: no ${secret}`);
    assert.ok(!panel.includes("<script"), `${path}: no script from the panel`);
    assert.equal(dataBlockOf(r.body), null, `${path}: no data block for a reader`);
    assert.ok(!panel.includes("<button") && !panel.includes("<form"), `${path}: nothing to press`);
    assert.ok(!panel.includes("<input"), `${path}: no schedule inputs`);
  }
  // What a reader may see is still there: the name, the chips, the result words and the trigger labels.
  const panel = panelOf((await get(pagePath(LISTINGS), { session: GUEST })).body);
  assert.match(panel, /Weekly listings/);
  assert.match(panel, /rp-chip--live/);
  assert.match(panel, /Started by you/, "the label of the run the owner started");
  assert.match(panel, /Scheduled/, "the label of the scheduled run");
  assert.match(panel, /Run history/);
  assert.ok(!panel.includes('class="rp-run-error"'), "no error line");
  assert.ok(!panel.includes("rp-sends"), "no send counts");
  assert.ok(!panel.includes("expired"), "no expired word for a reader");
  assert.ok(!panel.includes("/runs/"), "no link into the run view");
});

test("the owner page shows the pause reason and the error text", async () => {
  const paused = await get(pagePath(PAUSED));
  assert.equal(paused.status, 200);
  assert.match(panelOf(paused.body), /The recipe changed\. Check it and go live again\./);
  assert.match(panelOf((await get(listPath())).body), /The recipe changed\./);
  const failed = panelOf((await get(pagePath(LISTINGS))).body);
  assert.match(failed, /reach the listings page/);
  assert.match(failed, /class="rp-run-error"/);
});

test("history links to artifact versions", async () => {
  const r = await get(pagePath(LISTINGS));
  assert.equal(r.status, 200);
  const href = `/dashboard/project/garden/reports/${LISTINGS}/runs/${RUN_OK}`;
  assert.match(r.body, new RegExp(`<a class="rp-version" href="${href}">Version 2</a>`));
  // The linked page is the run view this link opens: it still answers.
  const runView = await get(href);
  assert.equal(runView.status, 200);
  assert.match(runView.body, /Weekly listings/);
  assert.match(runView.body, /Version 2/);
  // The row that holds an unknown send offers the owner the rest.
  assert.match(r.body, new RegExp(`data-rp-action="send-rest" data-rp-report="${LISTINGS}" data-rp-run="${RUN_LATE}"`));
  assert.match(r.body, /1 sent, 1 unknown/);
  // A failed run's error line is on the page, escaped.
  assert.match(r.body, /Couldn&#39;t reach the listings page\.|Couldn't reach the listings page\./);
});

test("history shows expired for a pruned version", async () => {
  const r = await get(pagePath(LISTINGS));
  assert.equal(r.status, 200);
  assert.match(r.body, /rp-version--expired">expired</);
  assert.ok(!r.body.includes(`/runs/${RUN_LATE}"`), "an expired version links nowhere");
});

test("only a run with an unknown send offers Send to the rest", async () => {
  const r = await get(pagePath(LISTINGS));
  assert.equal(r.status, 200);
  assert.ok(r.body.includes(`data-rp-run="${RUN_LATE}"`), "the run with the unknown send offers the rest");
  assert.ok(!r.body.includes(`data-rp-run="${RUN_OK}"`), "the ok run sent everything it meant to");
  assert.ok(!r.body.includes(`data-rp-run="${RUN_FAILED}"`), "the failed run holds no unknown send");
  const offered = r.body.match(/data-rp-action="send-rest"/g) || [];
  assert.equal(offered.length, 1, "one button, for the one run that needs it");
});

test("pause banner shows pause_reason above the controls with Check and go live again", async () => {
  const r = await get(pagePath(PAUSED));
  assert.equal(r.status, 200);
  assert.match(r.body, /The recipe changed\. Check it and go live again\./);
  assert.match(r.body, /data-rp-action="go-live"[^>]*>Check and go live again</);
  const banner = r.body.indexOf('<div class="rp-banner"');
  const controls = r.body.indexOf('<section class="rp-section rp-controls"');
  assert.ok(banner > -1, "the banner is on the page");
  assert.ok(controls > -1, "and so is the controls row");
  assert.ok(controls > banner, "the banner is above the controls");
  // The paused report has a usable preview, so the client goes live with that run and not a new one.
  assert.match(r.body, new RegExp(`data-rp-preview="${RUN_PREVIEW}"`));
});

test("the sender shows beside go-live for the owner, and a report with none says so", async () => {
  const live = await get(pagePath(LISTINGS));
  assert.match(live.body, /Sends from: hello@example\.com/);
  const draft = await get(pagePath(DRAFT));
  assert.equal(draft.status, 200);
  const goLive = draft.body.indexOf('data-rp-action="go-live"');
  const sender = draft.body.indexOf("No sending account chosen yet.");
  assert.ok(goLive > 0 && sender > goLive, "the sender sits after the go-live control");
  assert.ok(draft.body.indexOf("rp-controls") > 0, "in the controls row");
  // The go-live button carries the sender the page showed: the empty string when the report has none.
  assert.match(draft.body, /data-rp-action="go-live"[^>]*data-rp-sender=""/);
});

test("a go-live button carries the report's sender account id", async () => {
  const { createDbClient } = await import("../servers/db.js");
  const db = createDbClient();
  try {
    // The draft with a sender is what the owner's own go-live offers, so give it one for this read.
    await db.execute({ sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?", args: [SENDER_ACCOUNT, DRAFT] });
  } finally {
    db.close();
  }
  try {
    const page = await get(pagePath(DRAFT));
    assert.equal(page.status, 200);
    assert.match(page.body, new RegExp(`data-rp-action="go-live"[^>]*data-rp-sender="${SENDER_ACCOUNT}"`));
    // A reader's page carries no button at all, so the id never reaches one.
    const reader = await get(pagePath(DRAFT), { session: GUEST });
    assert.ok(!reader.body.includes(SENDER_ACCOUNT), "no sender account id for a reader");
  } finally {
    const db2 = createDbClient();
    try {
      await db2.execute({ sql: "UPDATE reports SET sender_account_id = NULL WHERE id = ?", args: [DRAFT] });
    } finally {
      db2.close();
    }
  }
});

test("the data block carries the words of the page's own language", async () => {
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  const { createDbClient } = await import("../servers/db.js");
  const keys = [
    "projectReports.previewStarted",
    "projectReports.error.generic",
    "projectReports.error.goLiveNeeded",
  ];
  const db = createDbClient();
  try {
    await writeSetting(db, "language", "es");
    const es = dataBlockOf((await get(pagePath(LISTINGS))).body);
    assert.ok(es, "the owner's page carries the client's data block");
    assert.equal(es.lang, "es");
    for (const key of keys) {
      assert.equal(es.strings[key], t(key, "es"), `${key} is Spanish on the Spanish page`);
      assert.notEqual(t(key, "es"), t(key, "en"), `${key} is really translated`);
    }
  } finally {
    await writeSetting(db, "language", "en");
    db.close();
  }
  const en = dataBlockOf((await get(pagePath(LISTINGS))).body);
  assert.ok(en, "and the English page carries its own");
  assert.equal(en.lang, "en");
  for (const key of keys) assert.equal(en.strings[key], t(key, "en"));
});

test("the report page reads out the recipe, the settings and the recipient states, never a secret", async () => {
  const r = await get(pagePath(LISTINGS));
  assert.equal(r.status, 200);
  assert.match(r.body, /This week/);
  assert.match(r.body, /https:\/\/example\.com\/items/);
  assert.ok(!r.body.includes("not-for-the-page"), "a settings key that names a secret is not rendered");
  assert.match(r.body, /Email with a link/);
  assert.match(r.body, /Who sees comments/);
  assert.match(r.body, /Each person sees only their own/);
  assert.match(r.body, /AI commentary/);
  assert.match(r.body, /Off/);
  assert.match(r.body, new RegExp(PROPOSED));
  assert.match(r.body, /data-rp-action="approve"/);
  assert.match(r.body, /data-rp-action="revoke"/);
  assert.match(r.body, /id="history"/);
});

test("the approved recipient offers Revoke links, and a reader's page offers nothing", async () => {
  const ownerPage = await get(pagePath(LISTINGS));
  assert.equal(ownerPage.status, 200);
  assert.match(
    ownerPage.body,
    /data-rp-action="revoke-links" data-rp-report="rpt-0000000000000001" data-rp-recipient="rrc-0000000000000001" data-rp-name="person@example\.com">Revoke links</,
    "the row carries the control, the recipient and the name its confirmation uses",
  );
  assert.equal((ownerPage.body.match(/data-rp-action="revoke-links"/g) || []).length, 1,
    "one control, for the one approved recipient");
  // The proposal waiting for an answer has no links: it offers Approve and Refuse instead.
  const proposedRow = ownerPage.body.slice(ownerPage.body.indexOf(PROPOSED));
  assert.ok(!proposedRow.slice(0, 400).includes("revoke-links"), "a proposed recipient has no links to revoke");

  for (const path of [pagePath(LISTINGS), listPath()]) {
    const reader = await get(path, { session: GUEST });
    assert.equal(reader.status, 200, path);
    assert.ok(!reader.body.includes("revoke-links"), `${path}: no control for a reader`);
    assert.ok(!reader.body.includes("Revoke links"), `${path}: and not its words either`);
    assert.ok(!reader.body.includes("data-rp-name"), `${path}: no name handed to a client either`);
  }
});

test("only an approved recipient's row offers Revoke links", () => {
  const page = (state, over = {}) => projectReportPageHtml({
    project: PROJECT,
    owner: true,
    report: {
      id: LISTINGS, title: "Weekly listings", status: "live", live: true, pauseReason: null,
      nextRunText: null, schedule: null, deliveryMode: "email_link", commentTierDefault: "c",
      commentVisibility: "own", commentWindowRuns: 4, aiCommentary: false, recipe: [], sender: null,
      steps: [], hosts: [], preview: null, runs: [],
      recipients: [{
        id: "rrc-0000000000000001", address: "alex@example.com", displayName: "Alex", state, tier: "b",
      }],
      ...over,
    },
  }, "en");
  for (const state of ["proposed", "refused", "revoked"]) {
    assert.ok(!page(state).includes("revoke-links"), `${state}: no links to revoke`);
  }
  const approved = page("approved");
  assert.match(approved,
    /data-rp-action="revoke-links"[^>]*data-rp-recipient="rrc-0000000000000001"[^>]*data-rp-name="Alex"/,
    "the confirmation names the person by their display name when the row has one");
  assert.match(approved, />Revoke links</);
  // A row with no display name names the address, which is all the page knows about that person.
  const unnamed = page("approved", {
    recipients: [{ id: "rrc-0000000000000001", address: "alex@example.com", displayName: null, state: "approved", tier: "b" }],
  });
  assert.match(unnamed, /data-rp-name="alex@example\.com"/);
});

test("the settings section reads out how many recent runs keep comments open", async () => {
  const r = await get(pagePath(LISTINGS));
  assert.equal(r.status, 200);
  const panel = panelOf(r.body);
  // The report's own column (4 by default), in the read-only row after the visibility row.
  assert.match(panel, /Comments stay open for the last 4 reports/);
  const settings = panel.slice(panel.indexOf('<section class="rp-section" id="settings">'));
  const visibility = settings.indexOf("Each person sees only their own");
  const windowRow = settings.indexOf("Comments stay open for the last 4 reports");
  assert.ok(visibility > -1 && windowRow > visibility, "the row sits after the visibility row");
  assert.ok(!settings.slice(0, windowRow).includes("<input"), "it is read-only, like every other row");
  // The number is the report's own: a view that carries another one prints that one.
  const page = projectReportPageHtml({
    project: PROJECT,
    owner: true,
    report: {
      id: LISTINGS, title: "Weekly listings", status: "draft", live: false, pauseReason: null,
      nextRunText: null, schedule: null, deliveryMode: "email_link", commentTierDefault: "c",
      commentVisibility: "own", commentWindowRuns: 7, aiCommentary: false, recipe: [], sender: null,
      recipients: [], steps: [], hosts: [], preview: null, runs: [],
    },
  }, "en");
  assert.match(page, /Comments stay open for the last 7 reports/);
});

test("the Spanish page says the revoke links control and the comment window in Spanish", async () => {
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  const { createDbClient } = await import("../servers/db.js");
  const db = createDbClient();
  try {
    await writeSetting(db, "language", "es");
    const body = (await get(pagePath(LISTINGS))).body;
    assert.match(body, />Revocar enlaces</);
    assert.match(body, /Los comentarios siguen abiertos en los últimos 4 informes/);
    const strings = dataBlockOf(body)?.strings || {};
    assert.equal(strings["projectReports.recipients.revokeLinksConfirm"],
      t("projectReports.recipients.revokeLinksConfirm", "es"), "the confirmation is Spanish too");
    assert.equal(strings["projectReports.recipients.linksRevoked"],
      t("projectReports.recipients.linksRevoked", "es"));
  } finally {
    await writeSetting(db, "language", "en");
    db.close();
  }
});

test("an unknown slug and an unknown report id are the project's missing page", async () => {
  for (const path of [listPath("nowhere"), listPath("attic"), pagePath(LISTINGS, "nowhere"), pagePath(ELSEWHERE), pagePath("rpt-ffffffffffffffff")]) {
    const r = await get(path);
    assert.equal(r.status, 404, path);
    assert.ok(r.body.includes(MISSING_LINE), path);
    assert.equal(r.cache, "no-store");
  }
});

test("classic mode goes to the projects page", async () => {
  for (const path of [listPath(), pagePath(LISTINGS)]) {
    const r = await get(path, { mode: "classic" });
    assert.equal(r.status, 302, path);
    assert.equal(r.location, "/dashboard/projects");
  }
});

test("the project home's head nav carries the Reports link, always", async () => {
  const r = await get("/dashboard/project/garden");
  assert.equal(r.status, 200);
  assert.match(r.body, /<a class="ph-link ph-reports" href="\/dashboard\/project\/garden\/reports">Reports<\/a>/);
  assert.match(r.body, /ph-reports[^>]*>Reports<\/a><a class="ph-link ph-services" href="\/dashboard\/project\/garden\/services">Services<\/a>/, "Reports sits next to Services");
  process.env.CROW_SERVICES_UI = "0";
  try {
    const off = await get("/dashboard/project/garden");
    assert.match(off.body, /ph-reports[^>]*>Reports<\/a>/, "the Reports link is not behind the services flag");
    assert.ok(!off.body.includes("/dashboard/project/garden/services"), "with the flag off, no Services link");
  } finally {
    delete process.env.CROW_SERVICES_UI;
  }
});

/* -------------------------------------------------------------------- the client */

const CLIENT_HTML = (await import("../servers/gateway/dashboard/panels/project-reports/client.js")).projectReportsClientJs();
const CLIENT_DATA_SCRIPT = (await import("../servers/gateway/dashboard/panels/project-reports/client.js")).projectReportsDataScript;
const CLIENT_JS = CLIENT_HTML.slice(CLIENT_HTML.indexOf("<script>") + "<script>".length, CLIENT_HTML.lastIndexOf("</script>"));
const { projectReportsListHtml, projectReportPageHtml } = await import("../servers/gateway/dashboard/panels/project-reports/html.js");
const { translations, t } = await import("../servers/gateway/dashboard/shared/i18n.js");

const PROJECT = { id: GARDEN, slug: "garden", name: "Garden" };

function listView() {
  return {
    project: PROJECT,
    owner: true,
    reports: [{
      id: LISTINGS, title: "Weekly listings", status: "live", live: true, pauseReason: null,
      schedule: null, nextRunText: null, lastRun: null, latestRun: null, recipientCount: 1,
    }],
  };
}

function reportView() {
  return {
    project: PROJECT,
    owner: true,
    report: {
      id: LISTINGS, title: "Weekly listings", status: "live", live: true, pauseReason: null,
      nextRunText: null, schedule: { cron: "0 9 * * 1", tz: "UTC", nextRunText: null },
      deliveryMode: "email_link", commentTierDefault: "c", commentVisibility: "own", aiCommentary: false,
      recipe: [], sender: { address: SENDER_ADDRESS }, senderAccountId: SENDER_ACCOUNT, recipients: [], steps: [], hosts: [],
      preview: null,
      runs: [{
        id: RUN_LATE, trigger: "schedule", status: "ok", late: false, timeText: "Jan 15, 2030, 9:00 AM UTC",
        errorText: null, version: null, sends: { sent: 1, unknown: 1, failed: 0, pending: 0 }, canSendRest: true,
      }],
    },
  };
}

/** A report at the point where the page offers Go live: a draft with a usable preview. */
function goLiveView({ senderAccountId = "", sender = null } = {}) {
  const view = reportView();
  view.report.status = "draft";
  view.report.live = false;
  view.report.sender = sender;
  view.report.senderAccountId = senderAccountId;
  view.report.preview = { runId: RUN_PREVIEW };
  return view;
}

function boot({ html, fetchImpl }) {
  const { window, document } = parseHTML(`<html><body class="shell"><main>${html}</main></body></html>`);
  const calls = [];
  let reloads = 0;
  const location = { href: "https://crow.example.ts.net" + listPath(), reload() { reloads++; } };
  window.location = location;
  // The server-bound CSRF token, as /csrf-client.js exposes it on the page.
  window.crowCsrf = () => "csrf-abc";
  const fetchStub = (url, init = {}) => {
    calls.push({ url: String(url), method: init.method, headers: init.headers || {}, body: init.body ?? null });
    const answer = fetchImpl ? fetchImpl(String(url), init) : { status: 200, body: { ok: true } };
    if (answer instanceof Error) return Promise.reject(answer);
    return Promise.resolve({
      status: answer.status,
      ok: answer.status >= 200 && answer.status < 300,
      json: () => (answer.body === undefined ? Promise.reject(new Error("no json")) : Promise.resolve(answer.body)),
    });
  };
  const consoleStub = { log() {}, warn() {}, error() {} };
  const ctx = vm.createContext({ window, document, location, fetch: fetchStub, URL, console: consoleStub });
  vm.runInContext(CLIENT_JS, ctx);
  const click = (el) => el.dispatchEvent(new window.Event("click", { bubbles: true }));
  const submit = (form) => form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
  return { window, document, click, submit, settle, calls, reloads: () => reloads };
}

test("run now posts to the owner route", async () => {
  const view = listView();
  const s = boot({ html: projectReportsListHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 202, body: { requested: true } }) });
  const btn = s.document.querySelector(`[data-rp-action="run-now"][data-rp-report="${LISTINGS}"]`);
  assert.ok(btn, "the owner's Run now is on the page");
  s.click(btn);
  await s.settle();
  assert.equal(s.calls.length, 1);
  assert.equal(s.calls[0].method, "POST");
  assert.equal(s.calls[0].url, `/dashboard/api/reports/${LISTINGS}/run-now`);
  assert.equal(s.calls[0].headers["X-Crow-Csrf"], "csrf-abc");
  assert.equal(s.calls[0].headers["Content-Type"], "application/json");
  assert.equal(s.reloads(), 1, "a run that was asked for re-renders the page");
});

test("send to the rest posts to the owner route", async () => {
  const view = reportView();
  const s = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 201, body: { created: [], skipped: [] } }) });
  const btn = s.document.querySelector(`[data-rp-action="send-rest"][data-rp-run="${RUN_LATE}"]`);
  assert.ok(btn, "the run with an unknown send offers the rest");
  assert.equal(btn.textContent, "Send to the rest");
  s.click(btn);
  await s.settle();
  assert.equal(s.calls.length, 1);
  assert.equal(s.calls[0].method, "POST");
  assert.equal(s.calls[0].url, `/dashboard/api/reports/${LISTINGS}/runs/${RUN_LATE}/send-rest`);
  assert.equal(s.calls[0].headers["X-Crow-Csrf"], "csrf-abc");
  assert.equal(s.reloads(), 1);
});

test("go live posts the sender the page showed", async () => {
  const view = goLiveView({ senderAccountId: SENDER_ACCOUNT, sender: { address: SENDER_ADDRESS } });
  const s = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 200, body: { report: {} } }) });
  const btn = s.document.querySelector(`[data-rp-action="go-live"][data-rp-report="${LISTINGS}"]`);
  assert.ok(btn, "the draft's Go live is on the page");
  assert.equal(btn.getAttribute("data-rp-sender"), SENDER_ACCOUNT, "the button carries the sender the page showed");
  s.click(btn);
  await s.settle();
  assert.equal(s.calls.length, 1);
  assert.equal(s.calls[0].method, "POST");
  assert.equal(s.calls[0].url, `/dashboard/api/reports/${LISTINGS}/go-live`);
  assert.equal(s.calls[0].headers["X-Crow-Csrf"], "csrf-abc");
  assert.deepEqual(JSON.parse(s.calls[0].body), {
    previewRunId: RUN_PREVIEW,
    expectedSenderAccountId: SENDER_ACCOUNT,
  });
  assert.equal(s.reloads(), 1, "a go-live that landed re-renders the page");
});

test("revoke links asks first, then posts to the recipient's link route and says it is done", async () => {
  const view = reportView();
  view.report.recipients = [{
    id: "rrc-0000000000000001", address: "alex@example.com", displayName: "Alex", state: "approved", tier: "b",
  }];
  const s = boot({
    html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"),
    fetchImpl: () => ({ status: 200, body: { ok: true, revoked: 1 } }),
  });
  const asked = [];
  s.window.confirm = (text) => { asked.push(text); return true; };
  const btn = s.document.querySelector('[data-rp-action="revoke-links"]');
  assert.ok(btn, "the approved recipient's control is on the page");
  assert.equal(btn.textContent, "Revoke links");
  s.click(btn);
  await s.settle();
  assert.deepEqual(asked,
    [translations["projectReports.recipients.revokeLinksConfirm"].en.replace("{name}", "Alex")],
    "the confirmation is the page's own sentence, naming the person");
  assert.equal(s.calls.length, 1);
  assert.equal(s.calls[0].method, "POST");
  assert.equal(s.calls[0].url, `/dashboard/api/reports/${LISTINGS}/recipients/rrc-0000000000000001/link/revoke`);
  assert.equal(s.calls[0].headers["X-Crow-Csrf"], "csrf-abc");
  assert.equal(s.document.querySelector("[data-rp-status]").textContent,
    translations["projectReports.recipients.linksRevoked"].en);
  assert.equal(s.reloads(), 1, "a revoke that landed re-renders the page");
});

test("a declined revoke links confirmation posts nothing and keeps the page", async () => {
  const view = reportView();
  view.report.recipients = [
    { id: "rrc-0000000000000001", address: "alex@example.com", displayName: null, state: "approved", tier: "b" },
  ];
  const s = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en") });
  const asked = [];
  s.window.confirm = (text) => { asked.push(text); return false; };
  s.click(s.document.querySelector('[data-rp-action="revoke-links"]'));
  await s.settle();
  assert.deepEqual(asked,
    [translations["projectReports.recipients.revokeLinksConfirm"].en.replace("{name}", "alex@example.com")],
    "a recipient with no display name is named by their address");
  assert.equal(s.calls.length, 0, "nothing was sent");
  assert.equal(s.reloads(), 0);
});

test("go live with no sender posts the empty sender", async () => {
  const view = goLiveView({ senderAccountId: "", sender: null });
  const s = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 200, body: { report: {} } }) });
  const btn = s.document.querySelector(`[data-rp-action="go-live"][data-rp-report="${LISTINGS}"]`);
  assert.ok(btn, "the draft's Go live is on the page");
  assert.equal(btn.getAttribute("data-rp-sender"), "", "the button says the report has no sender");
  s.click(btn);
  await s.settle();
  assert.equal(s.calls.length, 1);
  assert.equal(s.calls[0].url, `/dashboard/api/reports/${LISTINGS}/go-live`);
  assert.deepEqual(JSON.parse(s.calls[0].body), {
    previewRunId: RUN_PREVIEW,
    expectedSenderAccountId: "",
  });
});

test("a 409 conflict on go live shows the API message", async () => {
  const conflict = "That report changed while this request was in flight. Try again.";
  const view = goLiveView({ senderAccountId: "" });
  const s = boot({
    html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"),
    fetchImpl: () => ({ status: 409, body: { error: "conflict", message: conflict } }),
  });
  s.click(s.document.querySelector(`[data-rp-action="go-live"][data-rp-report="${LISTINGS}"]`));
  await s.settle();
  const line = s.document.querySelector("[data-rp-status]");
  assert.equal(line.textContent, conflict, "the API's own sentence, not the generic line");
  assert.notEqual(line.textContent, translations["projectReports.error.generic"].en);
  assert.ok(line.classList.contains("rp-status--error"));
  assert.equal(s.reloads(), 0, "a refused go-live keeps the page");
});

test("the client's failures: the API's own sentence, the go-live line, then the generic one", async () => {
  const cases = [
    [{ status: 409, body: { error: "conflict", message: "That report changed while this request was in flight. Try again." } }, "That report changed while this request was in flight. Try again."],
    [{ status: 409, body: { error: "go_live_needed", message: "Preview and go live again." } }, translations["projectReports.error.goLiveNeeded"].en],
    [{ status: 500, body: { error: "internal" } }, translations["projectReports.error.generic"].en],
    [new Error("offline"), translations["projectReports.error.generic"].en],
  ];
  for (const [answer, copy] of cases) {
    const view = listView();
    const s = boot({ html: projectReportsListHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => answer });
    s.click(s.document.querySelector('[data-rp-action="pause"]'));
    await s.settle();
    const line = s.document.querySelector("[data-rp-status]");
    assert.equal(line.textContent, copy);
    assert.ok(line.classList.contains("rp-status--error"));
    assert.equal(s.reloads(), 0);
  }
});

test("preview says it started; a pause that lands re-renders; the schedule form PUTs the cron and zone", async () => {
  const view = reportView();
  const preview = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 202, body: { requested: true } }) });
  preview.click(preview.document.querySelector('[data-rp-action="preview"]'));
  await preview.settle();
  assert.equal(preview.calls[0].url, `/dashboard/api/reports/${LISTINGS}/preview`);
  assert.equal(preview.calls[0].method, "POST");
  assert.equal(preview.document.querySelector("[data-rp-status]").textContent, translations["projectReports.previewStarted"].en);
  assert.equal(preview.reloads(), 0, "a preview is not a page change");

  const pause = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 200, body: { report: {} } }) });
  pause.click(pause.document.querySelector('[data-rp-action="pause"]'));
  await pause.settle();
  assert.equal(pause.calls[0].url, `/dashboard/api/reports/${LISTINGS}/pause`);
  assert.equal(pause.reloads(), 1);

  const save = boot({ html: projectReportPageHtml(view, "en") + CLIENT_DATA_SCRIPT(view, "en"), fetchImpl: () => ({ status: 200, body: { report: {} } }) });
  const form = save.document.querySelector("[data-rp-schedule]");
  form.querySelector("[data-rp-cron]").value = "30 7 * * 2";
  form.querySelector("[data-rp-tz]").value = "Europe/Madrid";
  save.submit(form);
  await save.settle();
  assert.equal(save.calls[0].method, "PUT");
  assert.equal(save.calls[0].url, `/dashboard/api/reports/${LISTINGS}/schedule`);
  assert.equal(save.calls[0].headers["X-Crow-Csrf"], "csrf-abc");
  assert.deepEqual(JSON.parse(save.calls[0].body), { cron: "30 7 * * 2", tz: "Europe/Madrid" });
  assert.equal(save.reloads(), 1);
});

test("no backtick in client.js, and the client source uses no template placeholders", () => {
  const src = readFileSync(join(REPO, "servers/gateway/dashboard/panels/project-reports/client.js"), "utf8");
  assert.ok(!src.includes("`"), "the client's own file carries no backtick");
  assert.ok(!CLIENT_HTML.includes("`"), "nor does the script it emits");
  assert.ok(!CLIENT_JS.includes("${"), "no dollar-brace sequence either");
  for (const bad of ["localStorage", "sessionStorage", "indexedDB", "console.", "innerHTML", "outerHTML", "document.write"]) {
    assert.ok(!CLIENT_JS.includes(bad), `the client never uses ${bad}`);
  }
  assert.match(CLIENT_JS, /"X-Crow-Csrf": csrf\(\)/);
});

test("every projectReports key has English and Spanish, and a different Spanish", () => {
  const keys = Object.keys(translations).filter((k) => k.startsWith("projectReports."));
  assert.ok(keys.length >= 50, `the block is there (${keys.length} keys)`);
  for (const key of keys) {
    const row = translations[key];
    assert.ok(row && typeof row.en === "string" && row.en.length > 0, `${key} has English`);
    assert.ok(typeof row.es === "string" && row.es.length > 0, `${key} has Spanish`);
    assert.notEqual(row.es, row.en, `${key} is really translated`);
  }
  // The list and the report page are rendered from those keys alone: no UI sentence is written here.
  for (const key of ["projectReports.pageTitle", "projectReports.pause", "projectReports.goLive", "projectReports.sendRest"]) {
    assert.ok(translations[key], key);
  }
});

test("the fixed wording is what the page says", () => {
  // These sentences are inlined here on purpose: a wording change has to fail here, not drift silently.
  assert.deepEqual(translations["projectReports.status.live"], { en: "Live", es: "En vivo" });
  assert.deepEqual(translations["projectReports.tier.a"], {
    en: "Comment through a private link", es: "Comentar con un enlace privado",
  });
  assert.deepEqual(translations["projectReports.tier.b"], {
    en: "Reply to the email to comment", es: "Responder al correo para comentar",
  });
  assert.deepEqual(translations["projectReports.tier.c"], {
    en: "Only Crow users can comment", es: "Solo los usuarios de Crow pueden comentar",
  });
  assert.deepEqual(translations["projectReports.goLive"], {
    en: "Approve and go live", es: "Aprobar y publicar",
  });
  assert.deepEqual(translations["projectHome.reports"], { en: "Reports", es: "Informes" });
  // No tier key says a letter any more: the words say what the tier does.
  for (const tier of ["a", "b", "c"]) {
    assert.ok(!/Tier|Nivel/.test(translations[`projectReports.tier.${tier}`].en), tier);
    assert.ok(!/Tier|Nivel/.test(translations[`projectReports.tier.${tier}`].es), tier);
  }
});

test("an escaped title and a pause reason are text, never markup", async () => {
  const { projectReportsListHtml: listHtml } = await import("../servers/gateway/dashboard/panels/project-reports/html.js");
  const view = {
    project: { id: GARDEN, slug: "garden", name: "Garden" },
    owner: true,
    reports: [{
      id: LISTINGS, title: "<script>alert(1)</script>", status: "paused", live: false, pauseReason: "<b>changed</b>",
      schedule: null, nextRunText: null, lastRun: null, latestRun: null, recipientCount: null,
    }],
  };
  const html = listHtml(view, "en");
  assert.ok(!html.includes("<script>alert(1)</script>"));
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(html.includes("&lt;b&gt;changed&lt;/b&gt;"));
  assert.ok(!html.includes("<b>changed</b>"));
});

test("a paused report's reason is the owner's line, not a reader's", () => {
  const paused = {
    id: PAUSED, title: "Paused report", status: "paused", live: false,
    pauseReason: "The recipe changed. Check it and go live again.",
    schedule: null, nextRunText: null, lastRun: null, latestRun: null, recipientCount: null,
  };
  const ownerHtml = projectReportsListHtml({ project: PROJECT, owner: true, reports: [paused] }, "en");
  assert.ok(ownerHtml.includes("The recipe changed."), "the owner reads why it stopped");
  const readerHtml = projectReportsListHtml({ project: PROJECT, owner: false, reports: [paused] }, "en");
  assert.ok(!readerHtml.includes("The recipe changed."), "a reader is told nothing about it");
  assert.ok(!readerHtml.includes('class="rp-reason"'));
});

test("a pause banner needs a paused report, not a leftover reason", () => {
  const base = {
    id: LISTINGS, title: "Weekly listings", nextRunText: null, schedule: null,
    deliveryMode: "email_link", commentTierDefault: "c", commentVisibility: "own", aiCommentary: false,
    recipe: [], sender: null, recipients: [], steps: [], hosts: [], preview: null, runs: [],
  };
  const page = (status, live) => projectReportPageHtml({
    project: PROJECT,
    owner: true,
    report: { ...base, status, live, pauseReason: "An old reason." },
  }, "en");
  for (const status of ["live", "draft"]) {
    assert.ok(!page(status, status === "live").includes('<div class="rp-banner"'), `${status}: no banner`);
  }
  assert.ok(page("paused", false).includes('<div class="rp-banner"'), "a paused report with a reason shows it");
});

/** The Schedule section's own next-run line (the <p> before the cron form), for one page body. */
function scheduleLineOf(html) {
  const start = html.indexOf('<section class="rp-section" id="schedule">');
  assert.ok(start > 0, "the owner's page has a schedule section");
  const section = html.slice(start, html.indexOf("</section>", start));
  return section.slice(0, section.indexOf("<form"));
}

test("the schedule section names a report's state unless it has no schedule at all", () => {
  const SCHEDULE = { cron: "0 9 * * 1", tz: "Asia/Tokyo", nextRunText: null };
  const page = (report) => projectReportPageHtml({
    project: PROJECT,
    owner: true,
    report: {
      id: LISTINGS, title: "Weekly listings", status: "draft", live: false, pauseReason: null,
      nextRunText: null, schedule: null,
      deliveryMode: "email_link", commentTierDefault: "c", commentVisibility: "own", aiCommentary: false,
      recipe: [], sender: null, recipients: [], steps: [], hosts: [], preview: null, runs: [],
      ...report,
    },
  }, "en");
  const line = (report) => scheduleLineOf(page(report));

  // A draft that HAS a schedule row is not a report with no schedule: no next run is named for it (it is
  // not running), so it reads the word the list row shows beside it.
  const draft = line({ status: "draft", live: false, schedule: SCHEDULE });
  assert.match(draft, /<p class="rp-meta">Draft<\/p>/, "a draft with a schedule says Draft");
  assert.ok(!draft.includes("No schedule yet."), "and never that it has no schedule");

  // A report with no schedule row at all keeps the old sentence.
  assert.match(line({ status: "draft", live: false, schedule: null }), /<p class="rp-meta">No schedule yet\.<\/p>/);

  // A live report whose approval verifies and whose window is ahead reads the time, and never a word.
  const live = line({
    status: "live", live: true, schedule: { ...SCHEDULE, nextRunText: "Jan 15, 2099, 9:00 AM GMT+9" },
    nextRunText: "Jan 15, 2099, 9:00 AM GMT+9",
  });
  assert.match(live, /<p class="rp-meta">Next run: Jan 15, 2099, 9:00 AM GMT\+9<\/p>/);
  assert.ok(!live.includes("No schedule yet."), "a live report with a future window names its time");

  // A paused report with a schedule reads the paused word, and a live one whose seal does not verify the
  // same word (the list row's rule), never "No schedule yet.".
  const paused = line({ status: "paused", live: false, schedule: SCHEDULE });
  assert.match(paused, /<p class="rp-meta">Paused<\/p>/);
  assert.ok(!paused.includes("No schedule yet."));
  const stale = line({ status: "live", live: false, schedule: SCHEDULE });
  assert.match(stale, /<p class="rp-meta">Paused<\/p>/, "a live report whose approval does not verify");
});

test("a live report with a schedule row and no next run says what its list row says", () => {
  // A live report whose approval verifies but whose window has passed (or whose row is switched off): no
  // next-run time is named for it, and its list row reads "No schedule yet." rather than the word a report
  // that runs nothing carries. With a schedule row on hand the schedule section must say exactly that too —
  // not "Paused".
  const SCHEDULE = { cron: "0 9 * * 1", tz: "Asia/Tokyo", nextRunText: null };
  const listRow = {
    id: LISTINGS, title: "Weekly listings", status: "live", live: true, pauseReason: null,
    schedule: SCHEDULE, nextRunText: null, lastRun: null, latestRun: null, recipientCount: 1,
  };
  const list = projectReportsListHtml({ project: PROJECT, owner: true, reports: [listRow] }, "en");
  assert.ok(list.includes('<span class="rp-meta">No schedule yet.</span>'), "the list row says No schedule yet.");

  const page = projectReportPageHtml({
    project: PROJECT,
    owner: true,
    report: {
      id: LISTINGS, title: "Weekly listings", status: "live", live: true, pauseReason: null,
      nextRunText: null, schedule: SCHEDULE,
      deliveryMode: "email_link", commentTierDefault: "c", commentVisibility: "own", aiCommentary: false,
      recipe: [], sender: null, recipients: [], steps: [], hosts: [], preview: null, runs: [],
    },
  }, "en");
  const line = scheduleLineOf(page);
  assert.match(line, /<p class="rp-meta">No schedule yet\.<\/p>/, "the schedule section says the same thing");
  assert.ok(!line.includes("Paused"), "never the word a report that runs nothing carries");
});