/**
 * Crow Recurring Reports — the report page's Settings editor, end to end in a headless browser.
 *
 * The page under test is the REAL panel (`dashboard/panels/project-reports.js`): the markup, the inert
 * JSON block and the client script it emits, rendered for an OWNER through `panel.handler` with an
 * injected `ownerCheck` that answers true, and for a member with one that answers false (a
 * 'dashboard onhost' session row, the shape a login on this machine mints, so `viewerOf` says "member").
 * A tiny loopback server serves those two pages (`panel.handler` RETURNS the page — the dashboard shell is
 * what sends it — so the harness sends it, under the status the panel set; it binds on `chrome.bindHost`
 * and names `chrome.pageHost` in its URLs, as the suite's other live tests do). ONE route is stubbed —
 * `PUT /dashboard/api/reports/:id/settings`,
 * which records the request and answers a canned reply per test, because the write path itself (every
 * decision and every seal) lives in `routes/reports-api.js` and is pinned by its own tests. The save
 * reloads the page, so the GET is served again and the answer the client left in sessionStorage has to
 * come back on the fresh page.
 *
 * The rows live in a scratch CROW_DATA_DIR / CROW_HOME made with `scripts/init-db.js`: a live report and a
 * draft in project `garden`. A live report need not be sealed here — the form's own live warning follows
 * `status`, not the seal.
 *
 * Every sentence this file asserts is read from the i18n table (`t(key, "en")`), never typed out, so a
 * copy change is a test change in one place. Nothing here touches ~/.crow and no request leaves this
 * machine (127.0.0.1 only). No Chrome on the box means each test skips, exactly as the other live tests do.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { startHeadlessChrome } from "./fixtures/headless-chrome.mjs";
import { t } from "../servers/gateway/dashboard/shared/i18n.js";

const dir = mkdtempSync(join(tmpdir(), "reports-settings-live-"));
process.env.CROW_DATA_DIR = dir;
const HOME = join(dir, "home");
process.env.CROW_HOME = HOME;
mkdirSync(HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
delete process.env.CROW_SERVICES_UI;
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.PIBOT_PI_CLI = "/nonexistent/pi-never-spawned-by-this-file.js";
writeFileSync(join(dir, "instance-id"), "instance-reports-settings-live");
writeFileSync(join(HOME, "installed.json"), JSON.stringify([]));
const REPO = new URL("..", import.meta.url).pathname;

const GARDEN = 1;
const LIVE = "rpt-0000000000000001";
const DRAFT = "rpt-0000000000000002";
/** A 'dashboard onhost' login: read-only, a member, never the owner (the panel's `viewerOf`). */
const GUEST = "guest-sess";

// The words the page's own client shows, from the one table the server renders with.
const SAVED = t("projectReports.settings.saved", "en");
const SAVED_PAUSED = t("projectReports.settings.savedPaused", "en");
const LIVE_WARNING = t("projectReports.settings.liveWarning", "en");
const WINDOW_RANGE = t("projectReports.settings.windowRange", "en");
const NOTHING_CHANGED = t("projectReports.settings.nothingChanged", "en");
const SENDER_NOT_READY = t("projectReports.settings.senderNotReady", "en");

let db;
let panel;
let server;
let base;
let chrome;
/** The canned answer the stubbed PUT gives, set by each test before it saves. */
let answer = { status: 200, body: {} };
/** Every PUT the page made: `{url, body}` with the body already parsed. */
const recorded = [];

before(async () => {
  try {
    // The browser first: it may be a browser on another host (CROW_CDP_URL), and then the server has to
    // bind where THAT browser can reach it (`bindHost`) and the page's URLs name `pageHost` — the same
    // two the suite's other live tests use. No browser at all means the browser tests skip.
    chrome = await startHeadlessChrome();
    if (!chrome) console.error("[reports-settings-live] no headless Chrome: the browser tests skip");

    execFileSync(process.execPath, ["scripts/init-db.js"], {
      env: { ...process.env }, stdio: "pipe", cwd: REPO, timeout: 300000,
    });
    const { hashToken } = await import("../servers/gateway/dashboard/auth.js");
    const { createDbClient } = await import("../servers/db.js");
    ({ default: panel } = await import("../servers/gateway/dashboard/panels/project-reports.js"));

    db = createDbClient();
    await db.execute({
      sql: "INSERT INTO project_spaces (id, slug, name, type, status, archived_at) VALUES (?, ?, ?, 'general', 'active', NULL)",
      args: [GARDEN, "garden", "Garden"],
    });
    // The member's session row: a login on this machine, which is a reader and never the owner.
    await db.execute({
      sql: "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) VALUES (?, 'access', 'dashboard', 'dashboard onhost', datetime('now','+1 day'), '2026-06-01 00:00:00')",
      args: [hashToken(GUEST)],
    });
    // Two reports of one project: one live (the form warns that a save pauses it) and one draft.
    const recipe = JSON.stringify({
      blocks: [
        { id: "intro", type: "text", settings: { heading: "This week", content: "Five new listings." } },
      ],
    });
    const report = (id, title, status, createdAt) => db.execute({
      sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, status, recipe_json, recipe_rev,
              delivery_mode, comment_tier_default, comment_visibility, ai_commentary,
              sender_account_id, created_at, updated_at)
            VALUES (?, ?, 'owner', 'casa', ?, ?, ?, 0, 'email_link', 'c', 'own', 0, NULL, ?, 1)`,
      args: [id, GARDEN, title, status, recipe, createdAt],
    });
    await report(LIVE, "Weekly listings", "live", 2);
    await report(DRAFT, "A draft report", "draft", 1);

    const app = express();
    app.use(express.json({ limit: "1mb" }));
    // The one stubbed write: the real decision and seal path is routes/reports-api.js's own.
    app.put("/dashboard/api/reports/:id/settings", (req, res) => {
      recorded.push({ url: req.originalUrl, body: req.body });
      res.status(answer.status).json(answer.body);
    });
    app.get("/owner/:id", (req, res) => render(req, res, { id: req.params.id, owner: true }));
    app.get("/member/:id", (req, res) => render(req, res, { id: req.params.id, owner: false }));
    server = app.listen(0, chrome ? chrome.bindHost : "127.0.0.1");
    // A bind that fails must fail the hook, never leave it waiting for a 'listening' that never comes.
    await new Promise((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    base = `http://${chrome ? chrome.pageHost : "127.0.0.1"}:${server.address().port}`;
  } catch (err) {
    // Never let a harness that failed to start keep the run waiting: hand the handles back first.
    console.error("[reports-settings-live] harness setup failed: " + (err && err.message));
    try { server?.closeAllConnections?.(); server?.close(); } catch {}
    try { db?.close(); } catch {}
    if (chrome) await chrome.close().catch(() => {});
    throw err;
  }
});

after(async () => {
  server?.closeAllConnections?.();
  server?.close();
  if (chrome) await chrome.close();
  try { db?.close(); } catch {}
  rmSync(dir, { recursive: true, force: true });
});

/**
 * One report page, exactly as the panel draws it: the real handler with the view decided by the route.
 * The owner's route passes an ownerCheck that answers true; the member's answers false, and the request
 * carries a 'dashboard onhost' session row so `viewerOf` lands on "member" (a reader, read-only).
 *
 * The panel RETURNS its page — the dashboard shell is what sends it; a refusal and the classic redirect
 * answer themselves and return null — so this sends the returned HTML under the status the panel set.
 */
async function render(req, res, { id, owner }) {
  const layout = ({ title, content }) =>
    `<!doctype html><html><head><meta charset="utf-8"><title>${title ? String(title) : ""}</title></head><body>${content}</body></html>`;
  req.crowMode = { mode: "new" };
  req.params = { slug: "garden", id };
  if (!owner) req.dashboardSession = GUEST;
  try {
    const page = await panel.handler(req, res, {
      db,
      layout,
      lang: "en",
      ownerCheck: owner ? async () => true : async () => false,
    });
    if (res.headersSent) return;
    if (typeof page === "string") res.type("html").send(page);
    else res.status(500).type("text").send("harness: the panel answered nothing");
  } catch (err) {
    if (!res.headersSent) res.status(500).type("text").send("harness failure: " + (err && err.message));
  }
}

/* ------------------------------------------------------------------- the browser */

async function tab() {
  const target = await (await fetch(chrome.cdp + "/json/new?about:blank", {
    method: "PUT",
    signal: AbortSignal.timeout(10000),
  })).json();
  const { default: WebSocket } = await import("ws");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the browser's DevTools socket never opened")), 10000);
    ws.once("open", () => { clearTimeout(timer); resolve(); });
    ws.once("error", (err) => { clearTimeout(timer); reject(err); });
  });
  let id = 0;
  // Every call is answered or it gives up: a wedged browser must fail the test, not the whole run.
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const mine = ++id;
    const timer = setTimeout(() => {
      ws.off("message", on);
      reject(new Error(`the browser never answered ${method}`));
    }, 30000);
    const on = (raw) => {
      const m = JSON.parse(raw);
      if (m.id !== mine) return;
      ws.off("message", on);
      clearTimeout(timer);
      m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result || {});
    };
    ws.on("message", on); ws.send(JSON.stringify({ id: mine, method, params }));
  });
  const evalIn = async (expression) => {
    const out = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    return out.exceptionDetails ? { threw: out.exceptionDetails.text } : out.result.value;
  };
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1200, height: 900, deviceScaleFactor: 1, mobile: false });
  return {
    send,
    evalIn,
    close: async () => {
      ws.close();
      await fetch(chrome.cdp + "/json/close/" + target.id, { signal: AbortSignal.timeout(5000) }).catch(() => {});
    },
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    let v;
    try { v = await fn(); } catch {}
    if (v) return v;
    await sleep(100);
  }
  return null;
}

/** The client script's own bound flag: the page it belongs to has rendered and run. */
const BOUND = "(document.querySelector('[data-rp]') || { getAttribute: function () { return null; } })"
  + ".getAttribute('data-rp-bound') === '1'";

/** An element's text, or null while the document in flight does not carry it yet. */
const textOf = (selector) =>
  `(document.querySelector(${JSON.stringify(selector)}) || { textContent: null }).textContent`;

/** Navigate to one page of the harness and wait until the panel's client has bound to it. */
async function open(s, path) {
  await s.send("Page.navigate", { url: base + path });
  const ok = await waitFor(async () => (await s.evalIn(BOUND)) === true);
  assert.ok(ok, `the client bound to ${path}`);
}

/** Wait until one element's text is exactly `expected` (the reload a save does replaces the document). */
async function waitForText(s, selector, expected, ms = 15000) {
  return (await waitFor(async () => (await s.evalIn(textOf(selector))) === expected, ms)) === true;
}

/** The delivery menu as the page rendered it: its current value and every value it offers. */
async function deliveryMenuOf(s) {
  const raw = await s.evalIn(`JSON.stringify({
    current: document.querySelector('[data-rp-setting="delivery_mode"]').getAttribute("data-rp-current"),
    values: [].map.call(document.querySelectorAll('[data-rp-setting="delivery_mode"] option'), function (o) { return o.value; }),
  })`);
  return JSON.parse(raw);
}

/** Move the delivery menu to another value and save; returns the value the test chose. */
async function moveDeliveryAndSave(s) {
  const menu = await deliveryMenuOf(s);
  const moved = menu.values.find((value) => value !== menu.current);
  assert.ok(moved, `the delivery menu offers another value than the rendered one (${JSON.stringify(menu)})`);
  const clicked = await s.evalIn(`(() => {
    var form = document.querySelector('form[data-rp-settings]');
    if (!form) return "no form";
    form.querySelector('[data-rp-setting="delivery_mode"]').value = ${JSON.stringify(moved)};
    var btn = form.querySelector('button[type=submit]');
    if (!btn) return "no button";
    btn.click();
    return "clicked";
  })()`);
  assert.equal(clicked, "clicked", "the Save button was there and was pressed");
  return moved;
}

/* --------------------------------------------------------------------- the tests */

test("a draft report's owner saves a delivery change and a new comment window in one PUT, and the reloaded page says so", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  recorded.length = 0;
  answer = { status: 200, body: { ok: true, report: { id: DRAFT, status: "draft" } } };
  const s = await tab();
  try {
    await open(s, `/owner/${DRAFT}`);
    // A draft is not live, so the form carries no pause warning.
    assert.equal(await s.evalIn("!!document.querySelector('[data-rp-settings-live]')"), false,
      "a draft's form warns nothing");
    assert.equal(await s.evalIn("!!document.querySelector('form[data-rp-settings]')"), true, "the owner's form is there");

    const menu = await deliveryMenuOf(s);
    const moved = menu.values.find((value) => value !== menu.current);
    assert.ok(moved, `the delivery menu offers another value than the rendered one (${JSON.stringify(menu)})`);
    const renderedWindow = Number(await s.evalIn(
      "document.querySelector('[data-rp-setting=\"comment_window_runs\"]').getAttribute('data-rp-current')",
    ));
    assert.ok(Number.isInteger(renderedWindow), "the number box carries the report's own window");
    const nextWindow = renderedWindow === 7 ? 8 : 7;

    const clicked = await s.evalIn(`(() => {
      var form = document.querySelector('form[data-rp-settings]');
      form.querySelector('[data-rp-setting="delivery_mode"]').value = ${JSON.stringify(moved)};
      form.querySelector('[data-rp-setting="comment_window_runs"]').value = ${JSON.stringify(String(nextWindow))};
      var btn = form.querySelector('button[type=submit]');
      if (!btn) return "no button";
      btn.click();
      return "clicked";
    })()`);
    assert.equal(clicked, "clicked");

    assert.ok(await waitFor(() => recorded.length === 1), "one save, one request");
    assert.equal(recorded[0].url, `/dashboard/api/reports/${DRAFT}/settings`, "the report's own settings route");
    // Exactly the two fields that moved, and the number as a number.
    assert.deepEqual(recorded[0].body, { settings: { delivery_mode: moved, comment_window_runs: nextWindow } });
    assert.deepEqual(Object.keys(recorded[0].body.settings).sort(), ["comment_window_runs", "delivery_mode"],
      "nothing else rode along");
    assert.equal(typeof recorded[0].body.settings.comment_window_runs, "number", "the window is a number, not a string");

    // The save reloads the page, and the fresh page shows the answer that was kept for it.
    assert.ok(await waitForText(s, "[data-rp-settings-result]", SAVED), "the reloaded page shows the save's answer");
    assert.equal(await s.evalIn(textOf("[data-rp-settings-result]")), SAVED);
    assert.equal(await s.evalIn("!!document.querySelector('form[data-rp-settings]')"), true, "the page came back with its form");
    assert.equal(await s.evalIn("!!document.querySelector('[data-rp-settings-live]')"), false, "and still no live warning");
    assert.equal(recorded.length, 1, "the reload sent nothing else");
  } finally { await s.close(); }
});

test("a live report's form warns that saving pauses it, and the answer after the reload says it is paused", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  recorded.length = 0;
  answer = { status: 200, body: { ok: true, report: { id: LIVE, status: "paused" } } };
  const s = await tab();
  try {
    await open(s, `/owner/${LIVE}`);
    assert.equal(await s.evalIn(textOf("[data-rp-settings-live]")), LIVE_WARNING,
      "a live report says a save pauses it");
    assert.equal(await s.evalIn("document.querySelector('form[data-rp-settings]').getAttribute('data-rp-live')"), "1",
      "the form knows it was live");

    const moved = await moveDeliveryAndSave(s);
    assert.ok(await waitFor(() => recorded.length === 1), "one save, one request");
    assert.deepEqual(recorded[0].body, { settings: { delivery_mode: moved } },
      "only the field that moved is sent");

    assert.ok(await waitForText(s, "[data-rp-settings-result]", SAVED_PAUSED),
      "the page that comes back says the report is paused until it is approved again");
    assert.equal(await s.evalIn(textOf("[data-rp-settings-result]")), SAVED_PAUSED);
    assert.notEqual(SAVED_PAUSED, SAVED, "the paused sentence is the page's own, not the plain one");
  } finally { await s.close(); }
});

test("a comment window outside 1 to 50 says the range and sends nothing", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  recorded.length = 0;
  answer = { status: 200, body: { ok: true, report: { id: DRAFT, status: "draft" } } };
  const s = await tab();
  try {
    await open(s, `/owner/${DRAFT}`);
    const done = await s.evalIn(`(() => {
      var form = document.querySelector('form[data-rp-settings]');
      if (!form) return "no form";
      // The number box carries min="1", so the browser's own constraint validation would stop the
      // submit before the page's client ever sees it. Turning that off is how the page's own guard
      // (a number the box would let through in another browser, or a set value) is exercised here.
      form.noValidate = true;
      form.querySelector('[data-rp-setting="comment_window_runs"]').value = "0";
      var btn = form.querySelector('button[type=submit]');
      if (!btn) return "no button";
      btn.click();
      return "clicked";
    })()`);
    assert.equal(done, "clicked");
    assert.ok(await waitForText(s, "[data-rp-window-error]", WINDOW_RANGE, 5000), "the range line is shown");
    assert.equal(await s.evalIn(textOf("[data-rp-window-error]")), WINDOW_RANGE);
    assert.equal(await s.evalIn(textOf("[data-rp-settings-result]")), "", "and nothing claims a save");
    await sleep(300);
    assert.equal(recorded.length, 0, "a bad number sends nothing");
  } finally { await s.close(); }
});

test("a save the API refuses because the account cannot send shows the form's own line, and nothing saves", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  recorded.length = 0;
  answer = { status: 409, body: { error: "sender_not_ready" } };
  const s = await tab();
  try {
    await open(s, `/owner/${DRAFT}`);
    // A marker a reload would wipe: this page must stay.
    await s.evalIn("window.__rpStayed = 1");
    const moved = await moveDeliveryAndSave(s);
    assert.ok(await waitFor(() => recorded.length === 1), "the save was attempted");
    assert.deepEqual(recorded[0].body, { settings: { delivery_mode: moved } });

    assert.ok(await waitForText(s, "[data-rp-settings-note]", SENDER_NOT_READY, 5000),
      "the refusal is written above the Save button");
    assert.equal(await s.evalIn(textOf("[data-rp-settings-note]")), SENDER_NOT_READY);
    assert.equal(await s.evalIn(textOf("[data-rp-settings-result]")), "", "no save line");
    const result = await s.evalIn(textOf("[data-rp-settings-result]"));
    assert.ok(!String(result).includes(SAVED) && !String(result).includes(SAVED_PAUSED), "and no saved sentence either");
    assert.equal(await s.evalIn("window.__rpStayed === 1"), true, "a refused save keeps the page");
  } finally { await s.close(); }
});

test("a member's page has no settings form at all, in the browser and in the served HTML", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  const s = await tab();
  try {
    await s.send("Page.navigate", { url: base + `/member/${LIVE}` });
    assert.ok(await waitFor(async () => (await s.evalIn("!!document.querySelector('[data-rp]')")) === true),
      "the reader's page rendered");
    assert.equal(await s.evalIn("!!document.querySelector('form[data-rp-settings]')"), false, "no settings form");
    assert.equal(await s.evalIn("!!document.querySelector('[data-rp-settings]')"), false, "nothing marked as one");
    assert.equal(await s.evalIn("!!document.querySelector('[data-rp-setting]')"), false, "no settings control");
    assert.equal(await s.evalIn("!!document.querySelector('select')"), false, "and no menu");
  } finally { await s.close(); }

  // The same page, read as text. The panel's own style block is not markup — it names the form's selector
  // for the owner's page too — so the words are checked on the markup alone.
  const reader = await fetch(base + `/member/${LIVE}`);
  assert.equal(reader.status, 200);
  const markupOf = (html) => html.replace(/<style>[\s\S]*?<\/style>/g, "");
  const html = markupOf(await reader.text());
  assert.ok(html.includes("data-rp"), "the reader's page is the real page");
  assert.ok(!html.includes("data-rp-settings"), "no settings form for a member");
  assert.ok(!html.includes("data-rp-setting="), "and no settings control");
  assert.ok(!html.includes("/dashboard/api/reports/"), "no API path handed to a reader");
  // The owner's own page does carry it, so the refusal above is the viewer and not the page.
  const ownerPage = markupOf(await (await fetch(base + `/owner/${LIVE}`)).text());
  assert.ok(ownerPage.includes("data-rp-settings"), "the owner's page carries the form");
  assert.ok(ownerPage.includes("data-rp-setting=\"delivery_mode\""), "and its delivery menu");
});

test("a Save with nothing changed says so and sends nothing", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  recorded.length = 0;
  answer = { status: 200, body: { ok: true, report: { id: DRAFT, status: "draft" } } };
  const s = await tab();
  try {
    await open(s, `/owner/${DRAFT}`);
    const clicked = await s.evalIn(`(() => {
      var form = document.querySelector('form[data-rp-settings]');
      if (!form) return "no form";
      var btn = form.querySelector('button[type=submit]');
      if (!btn) return "no button";
      btn.click();
      return "clicked";
    })()`);
    assert.equal(clicked, "clicked");
    assert.ok(await waitForText(s, "[data-rp-settings-result]", NOTHING_CHANGED, 5000),
      "nothing moved, and the form says so");
    assert.equal(await s.evalIn(textOf("[data-rp-settings-result]")), NOTHING_CHANGED);
    await sleep(300);
    assert.equal(recorded.length, 0, "and no request went anywhere");
  } finally { await s.close(); }
});