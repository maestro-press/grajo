/**
 * #72 part 2: web push — the payload plumbing and the service worker's **Stop reminding** action.
 *
 * Two halves, both against the real code:
 *
 *   A. Payload. A fired recurring reminder is the ONLY notification whose push offers the action:
 *      `createNotification` adds the new row's id and `recurring: true` to what it fans out (read from
 *      the `schedules` row, never stored), `deliverNotification` passes them on and `sendPushToAll`
 *      puts them in the JSON together with the two localized words — R2 ("Stop reminding") and R4
 *      ("Stopped. Turn it back on in Schedule.") — resolved server-side from the owner's dashboard
 *      language setting (a service worker has no i18n module). Everything else keeps today's payload,
 *      byte for byte, and no secret ever rides along.
 *
 *      Real database (scripts/init-db.js), the REAL scheduler tick, the REAL `createNotification` /
 *      `deliverNotification` / `sendPushToAll`. The only fake is the transport: `webpush.sendNotification`
 *      is replaced on the `web-push` module object (its default export is the same object the sender
 *      calls through), so what is captured is the exact JSON string a browser would receive.
 *
 *   B. The service worker. `public/sw.js` is a CLASSIC script, so it is evaluated here in a `node:vm`
 *      context with a stubbed `self` — the real `push` and `notificationclick` handlers are driven, and
 *      the two pure helpers (`reminderStop`, `stopOutcome`) are called directly:
 *        - the action is offered only for a recurring reminder payload that carries an id and its words;
 *        - the action fetches the CSRF token (GET /dashboard/csrf, same-origin, redirect: "manual"),
 *          POSTs the part-1 stop route with the `X-Crow-Csrf` header, and on a 2xx `{ ok: true }`
 *          replaces the notification with the R4 words the payload carried;
 *        - a login redirect, a refusal (409 R8 / 403), a non-JSON answer or a network error opens the
 *          reminder instead; a plain tap still opens it.
 */
import { test, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createContext, runInContext } from "node:vm";

const REPO = join(import.meta.dirname, "..");
const SW_PATH = join(REPO, "servers/gateway/public/sw.js");
const SCHEDULE_PAGE = "/dashboard/schedule";

const dir = mkdtempSync(join(tmpdir(), "push-reminder-stop-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

/** The approved copy (#72 R2/R4), byte for byte. */
const COPY = {
  "notif.reminderStop": { en: "Stop reminding", es: "Dejar de recordar" },
  "notif.reminderStoppedToast": { en: "Stopped. Turn it back on in Schedule.", es: "Detenido. Puedes reactivarlo en Agenda." },
};

const iso = (offsetMs) => new Date(Date.now() + offsetMs).toISOString();

let db;
let tickForTest;
let pushes = []; // the JSON each push carried
const SAVED_ENV = {};

/** A web push transport that records the payload instead of sending it. */
async function patchPushTransport() {
  const webpush = (await import("web-push")).default;
  const keys = webpush.generateVAPIDKeys();
  process.env.VAPID_PUBLIC_KEY = keys.publicKey;
  process.env.VAPID_PRIVATE_KEY = keys.privateKey;
  webpush.sendNotification = async (_subscription, payload) => {
    pushes.push(JSON.parse(payload));
    return { statusCode: 201 };
  };
}

/** The off-dashboard channels a fan-out also reaches: switch them off so a test never does I/O. */
const QUIET_CHANNELS = ["NTFY_TOPIC", "NTFY_HOST", "NTFY_PORT", "NTFY_AUTH_TOKEN", "NTFY_CLICK_BASE_URL", "RESEND_API_KEY", "MPA_EMAIL_FROM", "MPA_EMAIL_TO"];

before(async () => {
  for (const n of QUIET_CHANNELS) SAVED_ENV[n] = process.env[n];
  for (const n of QUIET_CHANNELS) delete process.env[n];

  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: "" },
    stdio: "pipe",
    cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  await db.execute({
    sql: "INSERT INTO push_subscriptions (endpoint, keys_json) VALUES (?, ?)",
    args: ["https://push.example.test/sub/1", JSON.stringify({ p256dh: "p", auth: "a" })],
  });

  await patchPushTransport();
  const { initWebPush } = await import("../servers/gateway/push/web-push.js");
  initWebPush(); // VAPID details set → `configured = true`, so the sender runs

  const { _tickForTest, _resetForTest } = await import("../servers/gateway/scheduler.js");
  tickForTest = _tickForTest;
  globalThis.__resetSchedulerForTest = _resetForTest;
});

after(() => {
  try { db.close(); } catch { /* already closed */ }
  for (const n of QUIET_CHANNELS) {
    if (SAVED_ENV[n] === undefined) delete process.env[n];
    else process.env[n] = SAVED_ENV[n];
  }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
});

beforeEach(async () => {
  globalThis.__resetSchedulerForTest();
  pushes = [];
  await db.execute("DELETE FROM notifications");
  await db.execute("DELETE FROM schedule_runs");
  await db.execute("DELETE FROM schedules");
  await db.execute("DELETE FROM dashboard_settings WHERE key = 'language'");
});

afterEach(async () => {
  await db.execute("DELETE FROM dashboard_settings WHERE key = 'language'");
});

async function setLanguage(lang) {
  await db.execute({
    sql: "INSERT INTO dashboard_settings (key, value) VALUES ('language', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    args: [lang],
  });
}

async function seedSchedule({ task = "reminder:water the plants", cron = "0 9 * * *", nextRun = iso(-30_000), enabled = 1 } = {}) {
  const r = await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, next_run, enabled) VALUES (?, ?, ?, ?)",
    args: [task, cron, nextRun, enabled],
  });
  return Number(r.lastInsertRowid);
}

async function notificationsOf(scheduleId) {
  return (await db.execute({ sql: "SELECT * FROM notifications WHERE schedule_id = ?", args: [scheduleId] })).rows;
}

/* ══════════════════════════ A. the push payload ══════════════════════════ */

test("payload: a fired recurring reminder carries its id, the recurring flag and the action words", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  await tickForTest(db);

  const [row] = await notificationsOf(scheduleId);
  assert.ok(row, "the tick fired the reminder");
  assert.equal(pushes.length, 1, "one push");
  const payload = pushes[0];
  assert.equal(payload.id, row.id, "the notification's own row id (lastInsertRowid)");
  assert.equal(payload.recurring, true, "a cron schedule keeps repeating: it can be stopped");
  assert.equal(payload.title, "water the plants", "today's title is untouched");
  assert.equal(payload.body, "water the plants", "today's body is untouched");
  assert.equal(payload.url, `${SCHEDULE_PAGE}?id=crow:${scheduleId}`, "a tap opens the reminder (part 0)");
  assert.equal(payload.stopLabel, COPY["notif.reminderStop"].en, "R2, in the dashboard's language");
  assert.equal(payload.stoppedText, COPY["notif.reminderStoppedToast"].en, "R4, in the dashboard's language");
});

test("payload: a fired one-off reminder carries none of it (nothing repeats, nothing to stop)", async () => {
  const scheduleId = await seedSchedule({ cron: "@once" });
  await tickForTest(db);

  const [row] = await notificationsOf(scheduleId);
  assert.ok(row, "the one-off fired");
  assert.equal(pushes.length, 1, "one push");
  assert.deepEqual(pushes[0], {
    title: "water the plants",
    body: "water the plants",
    url: `${SCHEDULE_PAGE}?id=crow:${scheduleId}`,
  }, "exactly today's payload: no id, no recurring, no words");
});

test("payload: the words follow the dashboard's language setting", async () => {
  await setLanguage("es");
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  await tickForTest(db);

  assert.equal(pushes.length, 1, "one push");
  assert.equal(pushes[0].stopLabel, COPY["notif.reminderStop"].es, "R2 in Spanish");
  assert.equal(pushes[0].stoppedText, COPY["notif.reminderStoppedToast"].es, "R4 in Spanish");
});

test("payload: a missed notice (scheduler:missed, type reminder, a schedule id) carries none of it", async () => {
  const { createNotification } = await import("../servers/shared/notifications.js");
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const sent = [];
  await createNotification(db, {
    title: "Missed reminder: water the plants",
    type: "reminder",
    source: "scheduler:missed",
    schedule_id: scheduleId,
    action_url: `${SCHEDULE_PAGE}?run=7`,
    deliver: async (_db, payload) => { sent.push(payload); },
  });
  assert.equal(sent.length, 1);
  assert.equal(Object.hasOwn(sent[0], "id"), false, "a missed notice is acknowledged on the Schedule page");
  assert.equal(Object.hasOwn(sent[0], "recurring"), false);
});

test("payload: every other notification keeps today's fan-out shape", async () => {
  const { createNotification } = await import("../servers/shared/notifications.js");
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const oneOff = await seedSchedule({ cron: "@once" });
  const cases = [
    ["a system notice naming a schedule", { type: "system", source: "scheduler", schedule_id: scheduleId }],
    ["a one-off reminder (nothing repeats)", { type: "reminder", source: "scheduler", schedule_id: oneOff }],
    ["a reminder with no schedule", { type: "reminder", source: "scheduler" }],
    ["another source", { type: "reminder", source: "media:briefing", schedule_id: scheduleId }],
  ];
  for (const [label, extra] of cases) {
    const sent = [];
    const made = await createNotification(db, {
      title: label, body: "b", action_url: "/dashboard/x",
      ...extra,
      deliver: async (_db, payload) => { sent.push(payload); },
    });
    assert.ok(made, label);
    assert.deepEqual(sent[0], { title: label, body: "b", action_url: "/dashboard/x", priority: "normal", type: extra.type },
      `${label}: today's payload exactly`);
  }
});

test("payload: the grouped re-push path keeps today's payload (no action)", async () => {
  const { upsertGroupedNotification, repushNotificationGroup } = await import("../servers/shared/notifications.js");
  const quiet = async () => {};
  await upsertGroupedNotification(db, {
    groupKey: "test:group", title: (n) => `${n} things`, type: "attention", priority: "normal",
    deliver: quiet,
  });
  // A second item joins the open group (no push yet, count 2 > pushed_count 1), so the re-push fires.
  await upsertGroupedNotification(db, {
    groupKey: "test:group", title: (n) => `${n} things`, type: "attention", priority: "normal",
    deliver: quiet,
  });
  const sent = [];
  await repushNotificationGroup(db, {
    groupKey: "test:group", title: (n) => `${n} things`, deliver: async (_db, payload) => { sent.push(payload); },
  });
  assert.equal(sent.length, 1, "the group re-pushed");
  assert.equal(Object.hasOwn(sent[0], "id"), false);
  assert.equal(Object.hasOwn(sent[0], "recurring"), false);
});

test("payload: nothing secret rides along (no token, no cookie, no header name)", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  await tickForTest(db);
  assert.equal(pushes.length, 1);
  const payload = pushes[0];
  assert.deepEqual(Object.keys(payload).sort(), ["body", "id", "recurring", "stopLabel", "stoppedText", "title", "url"],
    "the payload grows exactly four fields");
  const text = JSON.stringify(payload);
  assert.doesNotMatch(text, /csrf|token|cookie|session/i, "the action fetches the CSRF token itself when tapped");
});

/* ══════════════════════ B. the service worker (sw.js) ══════════════════════ */

/** Evaluate the real sw.js in a vm context with a stubbed service-worker global. */
function harness({ fetchImpl, windows } = {}) {
  const handlers = {};
  const shown = [];
  const opened = [];
  const focused = [];
  const openWindows = windows || [{
    url: "https://crow.example.ts.net/dashboard/",
    focus: async () => { focused.push("focus"); },
    navigate: async (u) => { focused.push(u); },
  }];
  const sandbox = {
    console,
    URL,
    setTimeout,
    Response: { error: () => ({ error: true }) },
    caches: { open: async () => ({ put: async () => {} }), keys: async () => [], delete: async () => true, match: async () => null },
    fetch: fetchImpl || (async () => { throw new Error("no fetch expected in this test"); }),
    self: {
      location: { origin: "https://crow.example.ts.net" },
      addEventListener: (type, fn) => { handlers[type] = fn; },
      skipWaiting: () => {},
      registration: { showNotification: async (title, options) => { shown.push({ title, options }); } },
      clients: {
        claim: async () => {},
        matchAll: async () => openWindows,
        openWindow: async (url) => { opened.push(url); return null; },
      },
    },
  };
  const ctx = createContext(sandbox);
  runInContext(readFileSync(SW_PATH, "utf8"), ctx, { filename: "sw.js" });
  return { ctx, handlers, shown, opened, focused };
}

/** Dispatch a push event; → the promise handed to waitUntil. */
function push(h, payload) {
  let done;
  h.handlers.push({ data: { json: () => payload }, waitUntil: (p) => { done = p; } });
  return done;
}

/** Dispatch a notification click; → the promise handed to waitUntil. */
function click(h, { action, url, reminder, title = "water the plants" }) {
  let done;
  let closed = false;
  const notification = {
    title,
    data: { url, ...(reminder ? { reminder } : {}) },
    close: () => { closed = true; },
  };
  h.handlers.notificationclick({ action, notification, waitUntil: (p) => { done = p; } });
  return { done, wasClosed: () => closed };
}

const ok = (json) => ({ ok: true, redirected: false, type: "basic", json: async () => json });
/** A value built inside the vm has the vm's Object.prototype: compare it as plain JSON. */
const plain = (v) => JSON.parse(JSON.stringify(v));
const status = (code, json) => ({
  ok: code >= 200 && code < 300,
  redirected: false,
  type: "basic",
  json: async () => json,
});
const loginRedirect = () => ({ ok: false, redirected: true, type: "opaqueredirect", json: async () => { throw new Error("no body"); } });
const htmlPage = () => ({ ok: true, redirected: false, type: "basic", json: async () => { throw new SyntaxError("Unexpected token <"); } });

const RECURRING = {
  title: "water the plants",
  body: "water the plants",
  url: `${SCHEDULE_PAGE}?id=crow:3`,
  id: 7,
  recurring: true,
  stopLabel: COPY["notif.reminderStop"].en,
  stoppedText: COPY["notif.reminderStoppedToast"].en,
};

test("sw.js: the action is offered only for a recurring reminder that carries an id and its words", () => {
  const h = harness();
  const { reminderStop } = h.ctx;

  assert.deepEqual(plain(reminderStop(RECURRING)), {
    actions: [{ action: "stop", title: "Stop reminding" }],
    reminder: { id: 7, stoppedText: "Stopped. Turn it back on in Schedule." },
  });
  assert.deepEqual(plain(reminderStop({ ...RECURRING, stopLabel: "Dejar de recordar" }).actions),
    [{ action: "stop", title: "Dejar de recordar" }], "the label is the payload's, never ours");
  for (const [label, payload] of [
    ["a one-off / any other push", { ...RECURRING, recurring: false }],
    ["an old gateway's payload (no flag)", { title: "t", url: "/dashboard", id: 7, stopLabel: "Stop reminding" }],
    ["no id", { ...RECURRING, id: undefined }],
    ["a non-numeric id", { ...RECURRING, id: "seven" }],
    ["a missing label (words could not be resolved)", { ...RECURRING, stopLabel: undefined }],
    ["no payload at all", null],
  ]) {
    assert.equal(reminderStop(payload), null, label);
  }
});

test("sw.js: a stop answer is 'done' only for a 2xx { ok: true }; everything else opens the page", () => {
  const h = harness();
  const { stopOutcome } = h.ctx;
  assert.equal(stopOutcome(ok({ ok: true, key: "notif.reminderStoppedToast" }), { ok: true }), "done");
  assert.equal(stopOutcome(ok({ ok: false }), { ok: false }), "open", "200 but not ok");
  assert.equal(stopOutcome(ok({ error: "changed" }), null), "open", "a non-JSON body");
  assert.equal(stopOutcome(status(409, { ok: false }), { ok: false }), "open", "R8 refusal");
  assert.equal(stopOutcome(status(403, { ok: false }), { ok: false }), "open", "a non-owner session");
  assert.equal(stopOutcome(loginRedirect(), null), "open", "an expired session is a redirect, not a 401");
  assert.equal(stopOutcome({ ...ok({ ok: true }), redirected: true }, { ok: true }), "open", "any redirect");
  assert.equal(stopOutcome(null, null), "open", "a network error");
});

test("sw.js: a plain push is shown exactly as before; a recurring reminder's gains the stop action", async () => {
  const h = harness();
  await push(h, { title: "Hello", body: "there", url: "/dashboard/blog" });
  assert.deepEqual(plain(h.shown[0]), {
    title: "Hello",
    options: {
      body: "there",
      icon: "/icons/crow-icon.svg",
      badge: "/icons/crow-icon.svg",
      data: { url: "/dashboard/blog" },
    },
  }, "no actions, and today's notification data exactly");

  await push(h, RECURRING);
  assert.deepEqual(plain(h.shown[1].options.actions), [{ action: "stop", title: "Stop reminding" }]);
  assert.deepEqual(plain(h.shown[1].options.data), {
    url: RECURRING.url,
    reminder: { id: 7, stoppedText: "Stopped. Turn it back on in Schedule." },
  }, "the id and the post-stop words ride in the notification data");
  assert.equal(h.shown[1].options.body, "water the plants");
});

test("sw.js: the stop action reads the CSRF token and POSTs the part-1 route, then shows R4", async () => {
  const calls = [];
  const h = harness({
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url === "/dashboard/csrf") return ok({ token: "tok-123" });
      return ok({ ok: true, key: "notif.reminderStoppedToast", text: "Stopped. Turn it back on in Schedule." });
    },
  });
  const { done, wasClosed } = click(h, { action: "stop", url: RECURRING.url, reminder: { id: 7, stoppedText: RECURRING.stoppedText } });
  await done;

  assert.equal(calls.length, 2, "the token, then the stop");
  assert.equal(calls[0].url, "/dashboard/csrf", "the token comes from the endpoint, never a cookie");
  assert.equal(calls[0].init.redirect, "manual", "a signed-out session redirects: tell it apart from a refusal");
  assert.equal(calls[0].init.credentials, "same-origin", "the session cookie rides along");
  assert.equal(calls[1].url, "/dashboard/reminders/7/stop", "the part-1 route");
  assert.equal(calls[1].init.method, "POST");
  assert.equal(calls[1].init.redirect, "manual");
  assert.equal(calls[1].init.credentials, "same-origin");
  const header = Object.entries(calls[1].init.headers).find(([k]) => k.toLowerCase() === "x-crow-csrf");
  assert.ok(header, "the CSRF header is sent");
  assert.equal(header[1], "tok-123", "with the token the endpoint just gave");

  assert.equal(wasClosed(), true, "the tapped notification is closed");
  assert.equal(h.opened.length + h.focused.length, 0, "the page is not opened on success");
  assert.equal(h.shown.length, 1, "the notification is replaced");
  assert.equal(h.shown[0].title, "water the plants", "the reminder's own title");
  assert.equal(h.shown[0].options.body, "Stopped. Turn it back on in Schedule.", "R4, the payload's words");
  assert.equal(h.shown[0].options.actions, undefined, "a stopped reminder offers nothing more");
  assert.equal(h.shown[0].options.data.url, RECURRING.url, "a tap on it still opens the reminder");
});

test("sw.js: a signed-out session (a login redirect) opens the reminder instead", async () => {
  const calls = [];
  const h = harness({
    fetchImpl: async (url, init) => { calls.push({ url, init }); return loginRedirect(); },
  });
  const { done } = click(h, { action: "stop", url: RECURRING.url, reminder: { id: 7, stoppedText: "x" } });
  await done;
  assert.equal(calls.length, 1, "the redirect ends it: no POST without a token");
  assert.deepEqual(h.focused, [RECURRING.url, "focus"], "the reminder page opens in the dashboard window");
  assert.equal(h.shown.length, 0);
});

test("sw.js: a non-JSON answer to the token request opens the reminder instead", async () => {
  const h = harness({ fetchImpl: async () => htmlPage() });
  const { done } = click(h, { action: "stop", url: RECURRING.url, reminder: { id: 7, stoppedText: "x" } });
  await done;
  assert.deepEqual(h.focused, [RECURRING.url, "focus"]);
  assert.equal(h.shown.length, 0);
});

test("sw.js: a refusal (R8 / non-owner) opens the reminder instead", async () => {
  const h = harness({
    fetchImpl: async (url) => (url === "/dashboard/csrf" ? ok({ token: "tok" }) : status(409, { ok: false, error: "changed" })),
  });
  const { done } = click(h, { action: "stop", url: RECURRING.url, reminder: { id: 7, stoppedText: "x" } });
  await done;
  assert.deepEqual(h.focused, [RECURRING.url, "focus"]);
  assert.equal(h.shown.length, 0);
});

test("sw.js: a network error opens the reminder instead", async () => {
  const h = harness({ fetchImpl: async () => { throw new TypeError("Failed to fetch"); } });
  const { done } = click(h, { action: "stop", url: RECURRING.url, reminder: { id: 7, stoppedText: "x" } });
  await done;
  assert.deepEqual(h.focused, [RECURRING.url, "focus"]);
  assert.equal(h.shown.length, 0);
});

test("sw.js: a plain tap is unchanged — it opens the reminder, never stops anything", async () => {
  let fetched = 0;
  const h = harness({ fetchImpl: async () => { fetched += 1; return ok({ ok: true }); } });
  const { done } = click(h, { action: undefined, url: RECURRING.url, reminder: { id: 7, stoppedText: "x" } });
  await done;
  assert.equal(fetched, 0, "a tap makes no request");
  assert.deepEqual(h.focused, [RECURRING.url, "focus"], "the reminder opens in the existing dashboard window");

  // No window open: a new one, exactly as before.
  const cold = harness({ windows: [], fetchImpl: async () => { throw new Error("no fetch expected"); } });
  const { done: coldDone } = click(cold, { action: undefined, url: "/dashboard" });
  await coldDone;
  assert.deepEqual(cold.opened, ["/dashboard"]);
});