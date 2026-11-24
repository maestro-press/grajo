/**
 * #72 parts 0 and 1:  a fired reminder links to itself, and the bell's **Done** / **Stop reminding**
 * buttons on such a row (never on a missed/failed notice, whose acknowledgement drives the Schedule
 * problems strip).
 *
 * Everything runs against a REAL scripts/init-db.js database (real `schedules`, `schedule_runs` and
 * `notifications` tables), the REAL scheduler tick, the REAL notifications list route, the REAL
 * reminders routes and the REAL `csrfMiddleware`. The only fakes are the dashboard's session gate
 * (`dashboardAuth` needs a live gateway) and a tiny ntfy server standing in for the push channel.
 *
 * What is pinned:
 *   - part 0: `deliverReminder` links a fired reminder to `/dashboard/schedule?id=crow:<schedule id>`
 *     (the Schedule panel opens that), and with `NTFY_CLICK_BASE_URL` set the ntfy message carries NO
 *     click target (a satellite's tap would land on the home instance, where the id does not exist)
 *     while the bell and web push still link; missed notices keep their own `?run=` link;
 *   - part 1: the list route adds `recurring` (computed from the schedules row, never stored) to the
 *     fired reminder rows ONLY;
 *   - Done dismisses and leaves the schedule alone; Stop pauses a recurring schedule, succeeds on an
 *     already-paused one, and is refused with R8 for a one-off, a `scheduler:missed` notice, another
 *     type, and a deleted schedule — refusing without the owner session, for an SSO session and
 *     without a CSRF token, and leaving the problems strip alone;
 *   - every answer's key and text, and the approved EN/ES copy byte for byte.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { markFromLaptop } from "./helpers/off-box.js";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "reminders-done-stop-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

const OWNER_SESSION = "owner-session-token";
const SSO_SESSION = "sso-session-token";
const hash = (s) => createHash("sha256").update(s).digest("hex");
const iso = (offsetMs) => new Date(Date.now() + offsetMs).toISOString();
const SCHEDULE_PATH = "/dashboard/schedule";

/** The approved copy (the private engineering notes, #72 R1/R2/R3/R4/R8), byte for byte. */
const COPY = {
  "notif.reminderDone": { en: "Done", es: "Hecho" },
  "notif.reminderStop": { en: "Stop reminding", es: "Dejar de recordar" },
  "notif.reminderDoneToast": { en: "Done.", es: "Hecho." },
  "notif.reminderStoppedToast": { en: "Stopped. Turn it back on in Schedule.", es: "Detenido. Puedes reactivarlo en Agenda." },
  "notif.reminderStopRefused": { en: "This reminder has changed. Open Schedule to stop it.", es: "Este recordatorio ha cambiado. Abre Agenda para detenerlo." },
};

let server, base, db;
let csrfFor = () => { throw new Error("the CSRF module is imported in before()"); };
const OWNER = () => ({ cookie: `crow_session=${OWNER_SESSION}`, "x-crow-csrf": csrfFor(OWNER_SESSION) });

async function post(path, headers) {
  const r = await fetch(base + path, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", ...(headers || OWNER()) },
    body: "{}",
  });
  let body = null;
  try { body = await r.json(); } catch { body = null; }
  return { status: r.status, location: r.headers.get("location"), body };
}

async function listBell() {
  const r = await fetch(base + "/api/notifications?unread_only=true&limit=100", { redirect: "manual", headers: OWNER() });
  assert.equal(r.status, 200);
  return (await r.json()).notifications;
}

/** A schedule row. `enabled` matters: a one-off that fired is switched off. */
async function seedSchedule({ task = "reminder:water the plants", cron = "0 9 * * *", nextRun = iso(3_600_000), enabled = 1 } = {}) {
  const r = await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, next_run, enabled) VALUES (?, ?, ?, ?)",
    args: [task, cron, nextRun, enabled],
  });
  return Number(r.lastInsertRowid);
}

/** A notification row, written directly so each case chooses its exact type / source / schedule. */
async function seedNotification({ type = "reminder", source = "scheduler", scheduleId, title = "Water the plants", actionUrl = null } = {}) {
  const r = await db.execute({
    sql: "INSERT INTO notifications (type, source, title, priority, action_url, schedule_id) VALUES (?, ?, ?, 'normal', ?, ?)",
    args: [type, source, title, actionUrl, scheduleId],
  });
  return Number(r.lastInsertRowid);
}

const notif = async (id) => (await db.execute({ sql: "SELECT * FROM notifications WHERE id = ?", args: [id] })).rows[0];
const sched = async (id) => (await db.execute({ sql: "SELECT * FROM schedules WHERE id = ?", args: [id] })).rows[0];
const dismissed = async (id) => Number((await notif(id)).is_dismissed) === 1;

/** A fake ntfy server: what it was sent (title, body, click header). */
async function fakeNtfy() {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      seen.push({ url: req.url, title: req.headers["x-title"], click: req.headers["x-click"], body });
      res.writeHead(200);
      res.end("{}");
    });
  });
  srv.listen(0, "127.0.0.1");
  await new Promise((r) => srv.once("listening", r));
  return { seen, port: srv.address().port, close: () => srv.close() };
}

/** Run `fn` with exactly these NTFY_* / CROW_DASHBOARD_URL values, restoring what was there. */
async function withEnv(vars, fn) {
  const names = ["NTFY_TOPIC", "NTFY_HOST", "NTFY_PORT", "NTFY_AUTH_TOKEN", "NTFY_CLICK_BASE_URL", "CROW_DASHBOARD_URL", "CROW_GATEWAY_URL"];
  const saved = names.map((n) => [n, process.env[n]]);
  try {
    for (const [n, v] of Object.entries(vars)) {
      if (v === undefined) delete process.env[n];
      else process.env[n] = v;
    }
    return await fn();
  } finally {
    for (const [n, v] of saved) {
      if (v === undefined) delete process.env[n];
      else process.env[n] = v;
    }
  }
}

let tickForTest;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: "" },
    stdio: "pipe",
    cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();

  // The dashboard's sessions: one minted by this instance's own password login (the owner), one by a
  // peer's SSO (admitted by dashboardAuth, but not the owner).
  await db.execute({
    sql: `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES
            (?, 'access', 'dashboard', 'dashboard', datetime('now', '+1 day')),
            (?, 'access', 'dashboard', 'dashboard sso src:peer-1', datetime('now', '+1 day'))`,
    args: [hash(OWNER_SESSION), hash(SSO_SESSION)],
  });

  const { _tickForTest, _resetForTest, sweepMissedNotices } = await import("../servers/gateway/scheduler.js");
  tickForTest = _tickForTest;
  globalThis.__resetSchedulerForTest = _resetForTest;
  globalThis.__sweepMissed = sweepMissedNotices;

  const { remindersRouter } = await import("../servers/gateway/routes/reminders.js");
  const { default: notificationsRouter } = await import("../servers/gateway/routes/notifications.js");
  const { csrfMiddleware, csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");
  csrfFor = csrfTokenForSession;
  const { parseCookies } = await import("../servers/gateway/dashboard/auth.js");
  const { default: express } = await import("express");

  // The dashboard's own gate, stubbed exactly as tests/c2c-api.test.js does it: a cookie signs the
  // request in and the client is the owner's laptop (so isLocalPasswordSessionOn's origin rule passes).
  const gate = (req, res, next) => {
    const cookies = parseCookies(req);
    if (!cookies.crow_session) return res.redirect("/dashboard/login");
    req.dashboardSession = cookies.crow_session;
    markFromLaptop(req);
    next();
  };
  const app = express();
  app.use(express.json({ limit: "8kb" }));
  app.use("/dashboard", csrfMiddleware); // the real CSRF rail, in the real order
  app.use(remindersRouter(gate));
  app.use(notificationsRouter(gate));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (server) server.close();
  try { db.close(); } catch { /* already closed */ }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
});

beforeEach(async () => {
  globalThis.__resetSchedulerForTest();
  await db.execute("DELETE FROM notifications");
  await db.execute("DELETE FROM schedule_runs");
  await db.execute("DELETE FROM schedules");
});

/* ─────────────────────────────── part 0: the link ─────────────────────────────── */

test("a fired reminder's notification opens that reminder on the Schedule page", async () => {
  const id = await seedSchedule({ cron: "0 9 * * *", nextRun: iso(-30_000) });
  await tickForTest(db);
  const rows = (await db.execute({ sql: "SELECT * FROM notifications WHERE schedule_id = ?", args: [id] })).rows;
  assert.equal(rows.length, 1, "the tick delivered one reminder");
  assert.equal(rows[0].type, "reminder");
  assert.equal(rows[0].source, "scheduler");
  assert.equal(rows[0].action_url, `${SCHEDULE_PATH}?id=crow:${id}`,
    "the panel opens itself from ?id=crow:<schedule id> (dashboard/panels/schedule.js)");
});

test("with NTFY_CLICK_BASE_URL set the ntfy message carries no click target; the bell link stays", async () => {
  const ntfy = await fakeNtfy();
  try {
    // A satellite: the click base names the HOME instance, where this schedule id does not exist.
    await withEnv({
      NTFY_TOPIC: "crow-test", NTFY_HOST: "127.0.0.1", NTFY_PORT: String(ntfy.port),
      NTFY_CLICK_BASE_URL: "https://crow.example.ts.net", CROW_DASHBOARD_URL: undefined, CROW_GATEWAY_URL: undefined,
    }, async () => {
      const id = await seedSchedule({ nextRun: iso(-30_000) });
      await tickForTest(db);
      assert.equal((await db.execute({ sql: "SELECT action_url FROM notifications WHERE schedule_id = ?", args: [id] })).rows[0].action_url,
        `${SCHEDULE_PATH}?id=crow:${id}`, "the bell and web push still open the reminder");
      assert.equal(ntfy.seen.length, 1, "one ntfy message");
      assert.equal(ntfy.seen[0].click, undefined, "no X-Click header: the tap would land on the home instance");
    });

    // The same box with no override (the normal install): the ntfy message DOES carry the link.
    await withEnv({
      NTFY_TOPIC: "crow-test", NTFY_HOST: "127.0.0.1", NTFY_PORT: String(ntfy.port),
      NTFY_CLICK_BASE_URL: undefined, CROW_DASHBOARD_URL: undefined, CROW_GATEWAY_URL: undefined,
    }, async () => {
      const id = await seedSchedule({ nextRun: iso(-30_000) });
      await tickForTest(db);
      assert.equal(ntfy.seen.length, 2, "a second ntfy message");
      assert.ok(String(ntfy.seen[1].click || "").endsWith(`${SCHEDULE_PATH}?id=crow:${id}`),
        `the click target is the reminder (got ${JSON.stringify(ntfy.seen[1].click)})`);
    });
  } finally {
    ntfy.close();
  }
});

test("a missed notice keeps its own ?run= link (part 0 changes reminders only)", async () => {
  const id = await seedSchedule({ cron: "0 9 * * *", nextRun: iso(-30_000), enabled: 1 });
  await db.execute({
    sql: `INSERT INTO schedule_runs (schedule_id, scheduled_for, ran_at, status, source) VALUES (?, ?, ?, 'missed', 'clock')`,
    args: [id, iso(-3_600_000), iso(-3_500_000)],
  });
  const sent = [];
  await globalThis.__sweepMissed(db, { notify: async (_db, payload) => { sent.push(payload); } });
  assert.equal(sent.length, 1, "one notice for one unacknowledged miss");
  const runId = (await db.execute({ sql: "SELECT id FROM schedule_runs WHERE schedule_id = ?", args: [id] })).rows[0].id;
  assert.equal(sent[0].source, "scheduler:missed");
  assert.equal(sent[0].action_url, `${SCHEDULE_PATH}?run=${runId}`, "the miss still opens its own run");
});

/* ───────────────────── part 1: what the bell list says ───────────────────── */

test("the bell list carries recurring on fired reminder rows only", async () => {
  const recurring = await seedSchedule({ cron: "0 9 * * *" });
  const oneOff = await seedSchedule({ cron: "@once", nextRun: iso(3_600_000), enabled: 0 });
  const orphan = await seedSchedule({ cron: "0 9 * * *" });
  const missed = await seedSchedule({ cron: "0 9 * * *" });

  const nRecurring = await seedNotification({ scheduleId: recurring, title: "Recurring" });
  const nOnce = await seedNotification({ scheduleId: oneOff, title: "One-off" });
  const nOrphan = await seedNotification({ scheduleId: orphan, title: "Deleted schedule" });
  const nMissed = await seedNotification({ type: "reminder", source: "scheduler:missed", scheduleId: missed, title: "Missed" });
  const nSystem = await seedNotification({ type: "system", source: "scheduler", scheduleId: recurring, title: "Paused" });
  await db.execute({ sql: "DELETE FROM schedules WHERE id = ?", args: [orphan] });

  const rows = await listBell();
  const byId = new Map(rows.map((r) => [r.id, r]));
  assert.equal(byId.get(nRecurring).recurring, true, "a cron schedule is recurring");
  assert.equal(byId.get(nOnce).recurring, false, "an @once schedule is not");
  assert.notEqual(byId.get(nOrphan).recurring, true, "a deleted schedule is never recurring");
  assert.equal(Object.hasOwn(byId.get(nMissed), "recurring"), false, "never a missed/failed notice");
  assert.equal(Object.hasOwn(byId.get(nSystem), "recurring"), false, "never another type");
  // The list keeps answering everything else about these rows.
  assert.equal(byId.get(nRecurring).schedule_id, recurring);
  assert.equal(byId.get(nMissed).title, "Missed");
});

test("the bell renders text-only Done / Stop reminding buttons, Stop only when recurring", async () => {
  const { sharedNotifJs } = await import("../servers/gateway/dashboard/shared/notifications.js");
  const en = sharedNotifJs("en");
  assert.ok(en.includes("notif-item-reminder-btn"), "the row's buttons have their own class");
  assert.ok(en.includes("'Done'") && en.includes("'Stop reminding'"), "R1 and R2 come from i18n");
  assert.ok(en.includes("if (n.recurring === true)"), "Stop is drawn only for a recurring schedule");
  assert.ok(en.includes("'/dashboard/reminders/'"), "both verbs POST to the dashboard routes");
  assert.equal(en.includes("innerHTML"), false, "no innerHTML sink anywhere in the bell client");
  // The generated client must PARSE (one stray backtick or brace in the template breaks the whole bell).
  assert.doesNotThrow(() => new Function(en), "the generated bell client parses");
  const es = sharedNotifJs("es");
  assert.ok(es.includes("'Hecho'") && es.includes("'Dejar de recordar'"), "the Spanish copy is rendered too");
  assert.doesNotThrow(() => new Function(es), "and the Spanish one parses");
});

/* ───────────────────────── part 1: Done ───────────────────────── */

test("Done dismisses the reminder row and leaves the schedule running", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const id = await seedNotification({ scheduleId });
  const r = await post(`/dashboard/reminders/${id}/done`);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, key: "notif.reminderDoneToast", text: "Done." });
  assert.equal(await dismissed(id), true, "the same effect as the bell's dismiss");
  assert.equal(Number((await sched(scheduleId)).enabled), 1, "a recurring reminder keeps its schedule");
});

test("Done on a one-off reminder only dismisses it", async () => {
  const scheduleId = await seedSchedule({ cron: "@once", enabled: 0 });
  const id = await seedNotification({ scheduleId });
  const r = await post(`/dashboard/reminders/${id}/done`);
  assert.equal(r.status, 200);
  assert.equal(await dismissed(id), true);
});

/* ───────────────────────── part 1: Stop ───────────────────────── */

test("Stop pauses the recurring schedule and dismisses the row", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const id = await seedNotification({ scheduleId });
  const r = await post(`/dashboard/reminders/${id}/stop`);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, key: "notif.reminderStoppedToast", text: "Stopped. Turn it back on in Schedule." });
  assert.equal(Number((await sched(scheduleId)).enabled), 0, "pauseSchedule, the Schedule page's Pause");
  assert.equal(await dismissed(id), true);
});

test("Stop on an already-paused schedule succeeds (same result, same toast)", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *", enabled: 0 });
  const id = await seedNotification({ scheduleId });
  const r = await post(`/dashboard/reminders/${id}/stop`);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, key: "notif.reminderStoppedToast", text: "Stopped. Turn it back on in Schedule." });
  assert.equal(Number((await sched(scheduleId)).enabled), 0);
  assert.equal(await dismissed(id), true);
});

test("Stop answers R8 for a one-off, a missed notice, another type and a deleted schedule", async () => {
  const once = await seedSchedule({ cron: "@once", enabled: 0 });
  const recurring = await seedSchedule({ cron: "0 9 * * *" });
  const nOnce = await seedNotification({ scheduleId: once });
  const nMissed = await seedNotification({ type: "reminder", source: "scheduler:missed", scheduleId: recurring });
  const nSystem = await seedNotification({ type: "system", source: "scheduler", scheduleId: recurring });
  const nGone = await seedNotification({ scheduleId: recurring });
  await db.execute({ sql: "DELETE FROM schedules WHERE id = ?", args: [recurring] });

  for (const [label, id] of [["a one-off", nOnce], ["a scheduler:missed notice", nMissed], ["another type", nSystem], ["a deleted schedule", nGone]]) {
    const r = await post(`/dashboard/reminders/${id}/stop`);
    assert.equal(r.status, 409, label);
    assert.deepEqual(r.body, { ok: false, error: "changed", key: "notif.reminderStopRefused", text: "This reminder has changed. Open Schedule to stop it." }, label);
    assert.equal(await dismissed(id), false, `${label}: nothing was dismissed`);
  }
  assert.equal(Number((await sched(once)).enabled), 0, "the one-off's own row was never touched");
});

/* ───────────────────── part 1: who may press them ───────────────────── */

test("a request with no session never reaches a route", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const id = await seedNotification({ scheduleId });
  for (const verb of ["done", "stop"]) {
    const r = await post(`/dashboard/reminders/${id}/${verb}`, { cookie: "crow_csrf=stale" });
    assert.equal(r.status, 302, verb);
    assert.equal(r.location, "/dashboard/login", verb);
  }
  assert.equal(await dismissed(id), false);
  assert.equal(Number((await sched(scheduleId)).enabled), 1);
});

test("an SSO session is not the owner: 403 not_owner, nothing written", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const id = await seedNotification({ scheduleId });
  const sso = { cookie: `crow_session=${SSO_SESSION}`, "x-crow-csrf": csrfFor(SSO_SESSION) };
  for (const verb of ["done", "stop"]) {
    const r = await post(`/dashboard/reminders/${id}/${verb}`, sso);
    assert.equal(r.status, 403, verb);
    assert.deepEqual(r.body, { ok: false, error: "not_owner" }, verb);
  }
  assert.equal(await dismissed(id), false);
  assert.equal(Number((await sched(scheduleId)).enabled), 1);
});

test("a non-owner is refused before the id is read: a malformed id is 403, not 404/409", async () => {
  const sso = { cookie: `crow_session=${SSO_SESSION}`, "x-crow-csrf": csrfFor(SSO_SESSION) };
  for (const verb of ["done", "stop"]) {
    for (const bad of ["not-a-number", "0", "12345678901234"]) {
      const r = await post(`/dashboard/reminders/${bad}/${verb}`, sso);
      assert.equal(r.status, 403, `${verb} ${bad}: the same refusal as any other non-owner call`);
      assert.deepEqual(r.body, { ok: false, error: "not_owner" }, `${verb} ${bad}`);
    }
  }
});

test("a state-changing call needs the CSRF token", async () => {
  const scheduleId = await seedSchedule({ cron: "0 9 * * *" });
  const id = await seedNotification({ scheduleId });
  for (const verb of ["done", "stop"]) {
    const r = await post(`/dashboard/reminders/${id}/${verb}`, { cookie: `crow_session=${OWNER_SESSION}` });
    assert.equal(r.status, 403, `${verb}: the real csrfMiddleware refuses it before the route`);
  }
  assert.equal(await dismissed(id), false);
  assert.equal(Number((await sched(scheduleId)).enabled), 1);
});

/* ───────────────────── part 1: the problems strip ───────────────────── */

test("Done and Stop leave the Schedule problems strip alone", async () => {
  const { buildScheduleModel } = await import("../servers/gateway/schedule-catalog.js");
  const missedSchedule = await seedSchedule({ cron: "0 9 * * *" });
  const run = await db.execute({
    sql: `INSERT INTO schedule_runs (schedule_id, scheduled_for, ran_at, status, source) VALUES (?, ?, ?, 'missed', 'clock')`,
    args: [missedSchedule, iso(-3_600_000), iso(-3_500_000)],
  });
  const missedRunId = Number(run.lastInsertRowid);
  const missedNotice = await seedNotification({ type: "reminder", source: "scheduler:missed", scheduleId: missedSchedule });

  const before = await buildScheduleModel(db);
  assert.ok(before.problems.some((p) => p.code === "missed" && p.runId === missedRunId), "the miss is a problem on the strip");

  // A recurring reminder's Stop, and a Done, are elsewhere entirely.
  const recurring = await seedSchedule({ cron: "0 9 * * *" });
  const reminder = await seedNotification({ scheduleId: recurring });
  assert.equal((await post(`/dashboard/reminders/${reminder}/stop`)).status, 200);
  assert.equal((await post(`/dashboard/reminders/${reminder}/done`)).status, 200);

  // The missed notice itself is refused: its acknowledgement is the strip's, never a bell button.
  assert.equal((await post(`/dashboard/reminders/${missedNotice}/stop`)).status, 409);
  assert.equal(await dismissed(missedNotice), false);

  const rows = await listBell();
  assert.equal(Object.hasOwn(rows.find((r) => r.id === missedNotice), "recurring"), false);

  const model = await buildScheduleModel(db);
  const problem = model.problems.find((p) => p.code === "missed" && p.runId === missedRunId);
  assert.ok(problem, "the missed window is still on the strip");
  assert.equal(problem.run.acknowledged_at ?? null, null, "and still unacknowledged");
});

/* ───────────────────── the approved copy ───────────────────── */

test("every key is in en and es with the approved words, byte for byte", async () => {
  const { t, translations } = await import("../servers/gateway/dashboard/shared/i18n.js");
  for (const [key, copy] of Object.entries(COPY)) {
    assert.ok(translations[key], `${key} exists`);
    assert.deepEqual(Object.keys(translations[key]).sort(), ["en", "es"], `${key}: exactly en and es`);
    for (const lang of ["en", "es"]) {
      assert.equal(translations[key][lang], copy[lang], `${key} [${lang}]`);
      assert.equal(t(key, lang), copy[lang], `${key} [${lang}] through t()`);
    }
  }
});

test("the routes' answers use those keys", async () => {
  const src = await import("node:fs").then((fs) => fs.readFileSync(join(REPO, "servers/gateway/routes/reminders.js"), "utf8"));
  for (const key of Object.keys(COPY)) {
    if (key === "notif.reminderDone" || key === "notif.reminderStop") continue; // the button labels are the client's
    assert.ok(src.includes(`"${key}"`), `${key} is what an answer carries`);
  }
});