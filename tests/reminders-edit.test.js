/**
 * #72 part 3: editing a reminder on the Schedule page.
 *
 * The owner opens a reminder's detail and presses **Edit**: the same fields as New schedule (words,
 * the words-or-cron "when", the live Preview) save through a new `editReminder` in
 * servers/gateway/schedule-actions.js beside `createReminder`, with create's own rules (the same
 * parser, the hourly floor, a future time for a one-off). Only a reminder row is editable here; the
 * POST is the owner's own local password session and carries the panel's CSRF field, like every
 * other write on the page.
 *
 * What is pinned:
 *   - the words and the time are saved, a bad "when" is refused with the parser's own hint, a
 *     recurrence faster than hourly is refused, and a row that is not a reminder is refused
 *     (`bad-request`) before anything is parsed;
 *   - one-off ↔ recurring can be switched (the next run is recomputed);
 *   - PAUSE RULE: a reminder the owner paused stays paused (the R7b toast) — while a one-off that
 *     already FIRED is finished, not paused, so moving it to a future time turns it back on (R7);
 *   - the detail pane's Edit button (R5) and the sheet's title (R6) come from i18n, the sheet is
 *     prefilled with the reminder's words and its current schedule, and the save's two answers are
 *     R7 / R7b byte for byte;
 *   - owner-only (no session, an SSO session, a cross-host call), and behind the REAL CSRF rail.
 *
 * Everything runs against a REAL scripts/init-db.js database in a tmpdir (never ~/.crow).
 */
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { parseHTML } from "linkedom";
import { fromLaptop } from "./helpers/off-box.js";

const REPO = join(import.meta.dirname, "..");
const tmpDir = mkdtempSync(join(tmpdir(), "reminders-edit-"));
mkdirSync(join(tmpDir, "home"), { recursive: true });
process.env.CROW_DATA_DIR = tmpDir;
process.env.CROW_HOME = join(tmpDir, "home");
delete process.env.CROW_DB_PATH;

execFileSync(process.execPath, ["scripts/init-db.js"], {
  env: { ...process.env, CROW_DATA_DIR: tmpDir, CROW_DB_PATH: "" },
  stdio: "pipe",
  cwd: REPO,
});

const { createDbClient } = await import("../servers/db.js");
const db = createDbClient();
const { editReminder, createReminder } = await import("../servers/gateway/schedule-actions.js");
const { default: panel, schedulePreview, isOwnerRequest, _setBotGateForTest } = await import("../servers/gateway/dashboard/panels/schedule.js");
const { scheduleClientJs } = await import("../servers/gateway/dashboard/panels/schedule/client.js");
const { translations, t } = await import("../servers/gateway/dashboard/shared/i18n.js");
const { csrfMiddleware, csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");

_setBotGateForTest({ engine: () => "ready", runtimeOn: async () => true });

const MIN = 60_000, HOUR = 3_600_000;
/** Monday 2026-10-26, 15:00 UTC: the unit tests' clock (the panel runs on the real one). */
const NOW = Date.parse("2026-10-26T15:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();
const all = async (sql, args = []) => (await db.execute({ sql, args })).rows;
const sched = async (id) => (await db.execute({ sql: "SELECT * FROM schedules WHERE id = ?", args: [id] })).rows[0];

const SESSION = "owner-session-token";
const SSO_SESSION = "sso-session-token";
const hash = (s) => createHash("sha256").update(s).digest("hex");

after(() => {
  _setBotGateForTest(null);
  try { db.close(); } catch { /* already closed */ }
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
});

beforeEach(async () => {
  await db.batch([
    "DELETE FROM schedules", "DELETE FROM schedule_runs", "DELETE FROM notifications", "DELETE FROM bot_jobs", "DELETE FROM pi_bot_defs",
    "DELETE FROM dashboard_settings WHERE key IN ('instance_timezone','notification_prefs')",
    "DELETE FROM dashboard_settings_overrides WHERE key IN ('instance_timezone','notification_prefs')",
    "DELETE FROM oauth_tokens WHERE client_id = 'dashboard'",
  ]);
  await db.execute({ sql: "INSERT INTO dashboard_settings (key, value) VALUES ('instance_timezone', 'UTC')", args: [] });
  const until = new Date(Date.now() + HOUR).toISOString();
  await db.execute({
    sql: `INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES
            (?, 'access', 'dashboard', 'dashboard', ?),
            (?, 'access', 'dashboard', 'dashboard sso src:peer-1', ?)`,
    args: [hash(SESSION), until, hash(SSO_SESSION), until],
  });
});

/** A schedule row (the shapes the panel and the scheduler produce). */
async function seed(task, cron, nextRun, { tz = null, enabled = 1, lastRun = null, description = null } = {}) {
  const r = await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, next_run, tz, enabled, last_run, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
    args: [task, cron, nextRun, tz, enabled, lastRun, description],
  });
  return Number(r.lastInsertRowid);
}

/* ───────────────────────────── editReminder (the action) ───────────────────────────── */

test("edit saves the words and the new time, and the row stays a reminder", async () => {
  const id = await seed("reminder:take the bins out", "0 7 * * 2", "2026-10-27T07:00:00.000Z");
  const r = await editReminder(db, id, { text: "  put the bins out ", when: "every thursday at 8", tz: "UTC", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.id, id);
  assert.equal(r.paused, false, "R7: the next run moved");
  const row = await sched(id);
  assert.equal(row.task, "reminder:put the bins out");
  assert.equal(row.cron_expression, "0 8 * * 4");
  assert.equal(row.next_run, "2026-10-29T08:00:00.000Z", "the next run is recomputed exactly as create computes it");
  assert.equal(Number(row.enabled), 1);
  assert.equal(row.tz, null, "a zone equal to the instance's is stored as NULL");
  assert.ok(row.updated_at, "updated_at is stamped");
});

test("edit: the browser's zone is stored when it differs from the instance's", async () => {
  const id = await seed("reminder:stand up", "0 9 * * *", "2026-10-27T09:00:00.000Z");
  const r = await editReminder(db, id, { text: "stand up", when: "every weekday at 9", tz: "America/Chicago", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  const row = await sched(id);
  assert.equal(row.tz, "America/Chicago");
  assert.equal(row.cron_expression, "0 9 * * 1-5");
  assert.equal(row.next_run, "2026-10-27T14:00:00.000Z");
});

test("edit refuses a 'when' the parser cannot read, with the parser's own hint, and changes nothing", async () => {
  const id = await seed("reminder:x", "0 9 * * *", "2026-10-27T09:00:00.000Z");
  const bad = await editReminder(db, id, { text: "x", when: "whenever", lang: "en", now: NOW });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "bad-when");
  assert.match(bad.hint, /couldn't tell when/);
  const row = await sched(id);
  assert.deepEqual([row.task, row.cron_expression, row.next_run, Number(row.enabled)], ["reminder:x", "0 9 * * *", "2026-10-27T09:00:00.000Z", 1]);
});

test("edit refuses empty text, text over the cap, and words that name another type (create's rules)", async () => {
  const id = await seed("reminder:x", "0 9 * * *", "2026-10-27T09:00:00.000Z");
  assert.equal((await editReminder(db, id, { text: "   ", when: "every day at 9", lang: "en", now: NOW })).code, "empty-text");
  assert.equal((await editReminder(db, id, { text: "x".repeat(1001), when: "every day at 9", lang: "en", now: NOW })).code, "text-too-long");
  assert.equal((await sched(id)).task, "reminder:x", "nothing was written");
  // "pipeline:" after the reminder prefix is ordinary reminder text, exactly as create treats it.
  const ok = await editReminder(db, id, { text: "reminder:pipeline:buy milk", when: "every day at 9", lang: "en", now: NOW });
  assert.equal(ok.ok, true);
  assert.equal((await sched(id)).task, "reminder:pipeline:buy milk");
});

test("edit refuses a recurring reminder faster than once an hour", async () => {
  const id = await seed("reminder:water", "0 9 * * *", "2026-10-27T09:00:00.000Z");
  const often = await editReminder(db, id, { text: "water", when: "every 15 minutes", lang: "en", now: NOW });
  assert.equal(often.ok, false);
  assert.equal(often.code, "bad-when", "the same code create gives (the parser refuses it first)");
  assert.match(often.hint, /at most once an hour/);
  const raw = await editReminder(db, id, { text: "water", when: "", cron: "*/5 * * * *", lang: "en", now: NOW });
  assert.equal(raw.code, "bad-when");
  const row = await sched(id);
  assert.deepEqual([row.cron_expression, row.next_run], ["0 9 * * *", "2026-10-27T09:00:00.000Z"], "nothing was written");
});

test("edit refuses every row that is not a reminder", async () => {
  const once = [
    ["pipeline:botcron:lab-triage", "0 9 * * *", "2026-10-27T09:00:00.000Z"],
    ["media:briefing", "0 7 * * *", "2026-10-27T07:00:00.000Z"],
    ["report:rpt-0123456789abcdef", "0 9 * * *", "2026-10-27T09:00:00.000Z"],
    ["pipeline:legacy", "0 9 * * *", null],
  ];
  for (const [task, cron, next] of once) {
    const id = await seed(task, cron, next);
    const r = await editReminder(db, id, { text: "hijack", when: "every day at 9", lang: "en", now: NOW });
    assert.equal(r.ok, false, task);
    assert.equal(r.code, "bad-request", task);
    const row = await sched(id);
    assert.deepEqual([row.task, row.cron_expression], [task, cron], `${task}: left alone`);
  }
});

test("edit switches one-off ↔ recurring in both directions", async () => {
  const id = await seed("reminder:call mum", "0 19 * * *", iso(NOW + HOUR));
  let r = await editReminder(db, id, { text: "call mum", when: "tomorrow at 9", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  let row = await sched(id);
  assert.equal(row.cron_expression, "@once");
  assert.equal(row.next_run, "2026-10-27T09:00:00.000Z");
  assert.equal(Number(row.enabled), 1);
  r = await editReminder(db, id, { text: "call mum", when: "every friday at 6pm", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  row = await sched(id);
  assert.equal(row.cron_expression, "0 18 * * 5");
  assert.equal(row.next_run, "2026-10-30T18:00:00.000Z", "back to a recurrence: the next run is recomputed");
  assert.equal(Number(row.enabled), 1);
});

test("a reminder the owner paused stays paused after an edit (R7b)", async () => {
  const id = await seed("reminder:stretch", "0 9 * * *", "2026-10-20T09:00:00.000Z", { enabled: 0 });
  const r = await editReminder(db, id, { text: "stretch", when: "every thursday at 8", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.paused, true, "R7b: it stays paused");
  const row = await sched(id);
  assert.equal(Number(row.enabled), 0, "enabled is untouched: nothing fires");
  assert.equal(row.cron_expression, "0 8 * * 4");
  assert.equal(row.next_run, "2026-10-29T08:00:00.000Z", "the stored next run matches the new schedule (what resume would compute)");

  // A one-off the owner paused BEFORE its time is paused too, not finished.
  const once = await seed("reminder:form", "@once", "2026-10-28T09:00:00.000Z", { enabled: 0 });
  const r2 = await editReminder(db, once, { text: "form", when: "tomorrow at 9", lang: "en", now: NOW });
  assert.equal(r2.paused, true);
  const row2 = await sched(once);
  assert.equal(Number(row2.enabled), 0);
  assert.equal(row2.next_run, "2026-10-27T09:00:00.000Z");
});

test("a one-off that already fired is finished, not paused: the edit turns it back on (R7)", async () => {
  const id = await seed("reminder:dentist", "@once", "2026-10-25T09:00:00.000Z", { enabled: 0, lastRun: "2026-10-25T09:00:06.000Z" });
  const r = await editReminder(db, id, { text: "dentist", when: "tomorrow at 9", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.paused, false, "R7: saved and running again");
  const row = await sched(id);
  assert.equal(Number(row.enabled), 1, "turned back on");
  assert.equal(row.cron_expression, "@once");
  assert.equal(row.next_run, "2026-10-27T09:00:00.000Z");
  assert.equal(row.last_run, "2026-10-25T09:00:06.000Z", "its history is kept");
});

test("a fired one-off edited into a recurrence runs too", async () => {
  const id = await seed("reminder:dentist", "@once", "2026-10-25T09:00:00.000Z", { enabled: 0, lastRun: "2026-10-25T09:00:06.000Z" });
  const r = await editReminder(db, id, { text: "dentist", when: "every monday at 9", lang: "en", now: NOW });
  assert.equal(r.paused, false);
  const row = await sched(id);
  assert.equal(Number(row.enabled), 1);
  assert.equal(row.cron_expression, "0 9 * * 1");
  assert.equal(row.next_run, "2026-11-02T09:00:00.000Z");
});

test("edit of a row that is gone is not-found, and of a stale row the type guard answers", async () => {
  assert.equal((await editReminder(db, 999999, { text: "x", when: "every day at 9", lang: "en", now: NOW })).code, "not-found");
  assert.equal((await editReminder(db, 0, { text: "x", when: "every day at 9", lang: "en", now: NOW })).code, "not-found");
});

/* ───────────────────────────── the panel: the sheet and its POST ───────────────────────────── */

/** Call the handler like the dashboard router does. → { status, html, location } */
async function call({ method = "GET", query = {}, body = {}, lang = "en", session = SESSION } = {}) {
  const out = { status: 200, html: null, location: null };
  const req = fromLaptop({ method, query, body, csrfToken: "tok123", dashboardSession: session || undefined });
  const res = {
    headersSent: false,
    status(n) { out.status = n; return this; },
    set() { return this; },
    json(v) { out.json = v; this.headersSent = true; },
    redirect(a, b) { out.status = typeof a === "number" ? a : 302; out.location = typeof a === "number" ? b : a; this.headersSent = true; },
    redirectAfterPost(url) { out.status = 303; out.location = url; this.headersSent = true; },
  };
  const html = await panel.handler(req, res, { db, layout: (o) => `<title>${o.title}</title>${o.content}`, lang });
  if (html !== undefined) out.html = html;
  return out;
}
const post = (body, opts = {}) => call({ method: "POST", body: { _csrf: "tok123", ...body }, ...opts });
const sheetOf = (html) => (html.match(/<dialog id="sc-edit"[\s\S]*?<\/dialog>/) || [""])[0];
const createSheetOf = (html) => (html.match(/<dialog id="sc-create"[\s\S]*?<\/dialog>/) || [""])[0];
const paneOf = (html) => (html.match(/<div class="sc-detail"[\s\S]*?<div class="sc-d-sec"><b>Next runs/) || [""])[0];

test("a reminder's detail pane offers Edit (R5); a bot routine's and the briefing's do not", async () => {
  const id = await seed("reminder:take the bins out", "0 7 * * 2", iso(Date.now() + HOUR));
  const r = await call({ query: { id: `crow:${id}` } });
  const pane = paneOf(r.html);
  assert.match(pane, /data-sc-edit>Edit</, "R5: the Edit button");
  assert.match(pane, new RegExp(`href="/dashboard/schedule\\?id=crow%3A${id}&amp;edit=1#sc-${id}"`));
  const sheet = sheetOf(r.html);
  assert.match(sheet, />Edit reminder</, "R6: the sheet's title");
  assert.match(sheet, /name="_csrf" value="tok123"/, "every POST form carries the CSRF field");
  assert.match(sheet, /name="text" maxlength="1000" required value="take the bins out"/, "the words are prefilled");
  assert.match(sheet, /name="when" maxlength="200" value="Every Tuesday at 7:00 AM"/, "the current schedule, as words");
  assert.match(sheet, /name="tz" value="UTC" data-sc-tz/, "the reminder's own zone rides the form");
  assert.match(sheet, /value="edit-preview"[^>]*>Preview</, "the existing Preview");
  assert.match(sheet, /value="edit"[^>]*>Save</, "the existing Save");

  await db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('lab-triage', 'Lab triage', '{}', 1)", args: [] });
  const bot = await seed("pipeline:botcron:lab-triage", "0 9 * * *", iso(Date.now() + HOUR), { description: JSON.stringify({ goal: "triage" }) });
  const rb = await call({ query: { id: `crow:${bot}` } });
  assert.doesNotMatch(paneOf(rb.html), /data-sc-edit/, "a bot routine is made in Bot Builder");
  assert.equal(sheetOf(rb.html), "", "and there is no sheet for it");

  const briefing = await seed("media:briefing", "0 7 * * *", iso(Date.now() + HOUR));
  const rf = await call({ query: { id: `crow:${briefing}` } });
  assert.doesNotMatch(paneOf(rf.html), /data-sc-edit/, "the briefing is changed in News");
  assert.equal(sheetOf(rf.html), "");
});

test("?edit=1 opens the sheet; a custom cron prefills the cron field, section open", async () => {
  const id = await seed("reminder:rent", "0 9 1,15 * *", iso(Date.now() + HOUR));
  const r = await call({ query: { id: `crow:${id}`, edit: "1" } });
  const sheet = sheetOf(r.html);
  assert.match(sheet, /<dialog id="sc-edit"[^>]*data-open-on-load/, "opened on load (no JS needed)");
  assert.match(sheet, /name="when" maxlength="200" value=""/, "describeCron cannot word it: the When field stays empty");
  assert.match(sheet, /<details class="sc-adv" open>/, "the cron section starts open");
  assert.match(sheet, /name="cron" maxlength="50" value="0 9 1,15 \* \*"/, "the exact expression");

  // A one-off's time is an absolute instant, not words: both fields start empty, the pane shows it.
  const once = await seed("reminder:dentist", "@once", iso(Date.now() + HOUR));
  const ro = await call({ query: { id: `crow:${once}`, edit: "1" } });
  const so = sheetOf(ro.html);
  assert.match(so, /name="when" maxlength="200" value=""/);
  assert.match(so, /name="cron" maxlength="50" value=""/);
  assert.match(ro.html, /Once · /, "the current time is shown in the pane above");
});

test("the prefilled schedule words read back as the SAME schedule (en and es), so an edit of the words alone never moves the time", async () => {
  const { cronNext } = await import("../servers/shared/schedule-core.js");
  const next = cronNext("0 7 * * 2", "UTC", Date.now());
  const id = await seed("reminder:take the bins out", "0 7 * * 2", iso(next));
  for (const [lang, expected] of [["en", "Every Tuesday at 7:00 AM"], ["es", "Cada martes a las 7:00"]]) {
    const page = await call({ query: { id: `crow:${id}` }, lang });
    const when = sheetOf(page.html).match(/name="when" maxlength="200" value="([^"]*)"/)[1];
    assert.equal(when, expected, `${lang}: the prefill is describeCron's words`);
    const r = await post({ action: "edit", id: String(id), text: "take the bins out", when, tz: "UTC" }, { lang });
    assert.equal(r.status, 303, lang);
    const row = await sched(id);
    assert.equal(row.cron_expression, "0 7 * * 2", `${lang}: the same cron`);
    assert.equal(row.next_run, iso(next), `${lang}: the same next run`);
  }
});

test("edit: a non-empty When wins over the cron field (the edit sheet's rule)", async () => {
  // The sheet prefills the cron field for a schedule describeCron cannot word (When starts empty).
  // The owner then types a time into When and saves: the words must be what is stored.
  const id = await seed("reminder:rent", "0 9 1,15 * *", "2026-11-01T09:00:00.000Z");
  const r = await editReminder(db, id, { text: "rent", when: "every day at 8", cron: "0 9 1,15 * *", lang: "en", now: NOW });
  assert.equal(r.ok, true);
  const row = await sched(id);
  assert.equal(row.cron_expression, "0 8 * * *", "the typed words, not the prefilled expression");
  assert.equal(row.next_run, "2026-10-27T08:00:00.000Z");

  // An empty When leaves the cron field in charge, exactly as the sheet's cron section promises.
  const r2 = await editReminder(db, id, { text: "rent", when: "  ", cron: "0 9 1,15 * *", lang: "en", now: NOW });
  assert.equal(r2.ok, true);
  assert.equal((await sched(id)).cron_expression, "0 9 1,15 * *", "a blank When never overrides the cron field");
});

test("POST edit with both fields filled saves the typed When", async () => {
  const id = await seed("reminder:rent", "0 9 1,15 * *", iso(Date.now() + HOUR));
  const r = await post({ action: "edit", id: String(id), text: "rent", when: "every day at 8", cron: "0 9 1,15 * *", tz: "UTC" });
  assert.equal(r.status, 303);
  assert.match(r.location, /done=edited#/);
  const row = await sched(id);
  assert.equal(row.cron_expression, "0 8 * * *", "the sheet's Save follows the same rule as its client");
  assert.equal(row.task, "reminder:rent");
});

test("the no-JS Preview in the edit sheet reads the same rule as Save", async () => {
  const id = await seed("reminder:rent", "0 9 1,15 * *", iso(Date.now() + HOUR));
  const r = await post({ action: "edit-preview", id: String(id), text: "rent", when: "every day at 8", cron: "0 9 1,15 * *", tz: "UTC" });
  assert.equal(r.status, 422);
  assert.match(r.html, /Every day at 8:00 AM/, "the read-back is the typed words' schedule");
  assert.equal((await sched(id)).cron_expression, "0 9 1,15 * *", "a preview saves nothing");
});

test("POST edit saves the words and the time: 303 to the detail, R7 in it", async () => {
  const id = await seed("reminder:take the bins out", "0 7 * * 2", iso(Date.now() + HOUR));
  const r = await post({ action: "edit", id: String(id), text: "Put the bins out", when: "every thursday at 8", tz: "UTC" });
  assert.equal(r.status, 303);
  assert.equal(r.location, `/dashboard/schedule?id=crow%3A${id}&done=edited#sc-${id}`);
  const row = await sched(id);
  assert.equal(row.task, "reminder:Put the bins out");
  assert.equal(row.cron_expression, "0 8 * * 4");
  assert.ok(Date.parse(row.next_run) > Date.now(), "a future next run");
  assert.equal(Number(row.enabled), 1);
  const d = await call({ query: { id: `crow:${id}`, done: "edited" } });
  assert.match(d.html, /role="status"[^>]*>Saved\. Its next run is shown below\.</, "R7");
  assert.match(d.html, /Every Thursday at 8:00 AM/);
});

test("POST edit on a paused reminder answers R7b and leaves it paused", async () => {
  const id = await seed("reminder:stretch", "0 9 * * *", iso(Date.now() + HOUR), { enabled: 0 });
  const r = await post({ action: "edit", id: String(id), text: "stretch", when: "every day at 10", tz: "UTC" });
  assert.equal(r.status, 303);
  assert.equal(r.location, `/dashboard/schedule?id=crow%3A${id}&done=edited-paused#sc-${id}`);
  const row = await sched(id);
  assert.equal(Number(row.enabled), 0);
  assert.equal(row.cron_expression, "0 10 * * *");
  const d = await call({ query: { id: `crow:${id}`, done: "edited-paused" } });
  assert.match(d.html, /role="status"[^>]*>Saved\. It stays paused\.</, "R7b");
});

test("POST edit turns a fired one-off back on when the new time is in the future", async () => {
  const fired = iso(Date.now() - 2 * HOUR);
  const id = await seed("reminder:dentist", "@once", fired, { enabled: 0, lastRun: fired });
  const r = await post({ action: "edit", id: String(id), text: "dentist", when: "in 20 minutes", tz: "UTC" });
  assert.match(r.location, /done=edited#/);
  const row = await sched(id);
  assert.equal(Number(row.enabled), 1);
  assert.equal(row.cron_expression, "@once");
  assert.ok(Date.parse(row.next_run) > Date.now());
});

test("a refused edit re-renders the sheet (422) with what was typed and the reason", async () => {
  const id = await seed("reminder:water", "0 9 * * *", iso(Date.now() + HOUR));
  const r = await post({ action: "edit", id: String(id), text: "water the plants", when: "every 15 minutes", tz: "Europe/Madrid" });
  assert.equal(r.status, 422);
  const sheet = sheetOf(r.html);
  assert.match(sheet, /data-open-on-load/);
  assert.match(sheet, /value="water the plants"/);
  assert.match(sheet, /value="every 15 minutes"/);
  assert.match(sheet, /value="Europe\/Madrid" data-sc-tz/);
  assert.match(sheet, /role="alert"[^>]*>Reminders repeat at most once an hour/);
  const row = await sched(id);
  assert.equal(row.cron_expression, "0 9 * * *", "nothing was saved");
});

test("the no-JS Preview in the edit sheet reads the typed words back without saving", async () => {
  const id = await seed("reminder:stand up", "0 9 * * *", iso(Date.now() + HOUR));
  const r = await post({ action: "edit-preview", id: String(id), text: "stand up", when: "every weekday at 9", tz: "UTC" });
  assert.equal(r.status, 422);
  assert.match(r.html, /Every weekday at 9:00 AM/);
  const sheet = sheetOf(r.html);
  assert.equal((sheet.match(/<ol class="sc-next">[\s\S]*?<\/ol>/)[0].match(/<li>/g) || []).length, 3, "the next 3 runs");
  assert.equal((await sched(id)).cron_expression, "0 9 * * *", "nothing was saved");
});

test("editing is the owner's own session: no session, an SSO session and a cross-host call change nothing", async () => {
  const id = await seed("reminder:x", "0 9 * * *", iso(Date.now() + HOUR));
  for (const session of [null, SSO_SESSION, "not-a-session"]) {
    const r = await post({ action: "edit", id: String(id), text: "hijack", when: "every day at 9", tz: "UTC" }, { session });
    assert.equal(r.status, 403, String(session));
  }
  assert.equal((await sched(id)).task, "reminder:x", "nothing was written");
  assert.equal(await isOwnerRequest(fromLaptop({ dashboardSession: SESSION, crossHostAuth: true })), false);
  assert.equal(await isOwnerRequest(fromLaptop({ dashboardSession: SESSION })), true);
  assert.equal((await post({ action: "edit", id: String(id), text: "x", when: "every day at 9", tz: "UTC" })).status, 303,
    "the local password session may write");
});

test("the REAL CSRF rail refuses an edit without the token and lets one through with it", async () => {
  const id = await seed("reminder:x", "0 9 * * *", iso(Date.now() + HOUR));
  const body = { action: "edit", id: String(id), text: "x", when: "every day at 10", tz: "UTC" };

  const bare = realReq({ ...body });
  const refused = resStub();
  let nexted = false;
  csrfMiddleware(bare, refused.res, () => { nexted = true; });
  assert.equal(nexted, false, "no token: refused before the panel");
  assert.equal(refused.status, 403);
  assert.equal((await sched(id)).cron_expression, "0 9 * * *");

  const token = csrfTokenForSession(SESSION);
  assert.ok(token, "the session has a token");
  const good = realReq({ ...body }, { token });
  const passed = resStub();
  let through = false;
  csrfMiddleware(good, passed.res, () => { through = true; });
  assert.equal(through, true, "the same request with the token proceeds");
  assert.equal(good.csrfToken, token);
  await panel.handler(good, passed.res, { db, layout: (o) => o.content, lang: "en" });
  assert.equal(passed.status, 303);
  assert.equal((await sched(id)).cron_expression, "0 10 * * *", "the panel saved it behind the rail");
});

test("a non-reminder row's edit is refused by the panel with the plain bad-request answer", async () => {
  await db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('lab-triage', 'Lab triage', '{}', 1)", args: [] });
  const id = await seed("pipeline:botcron:lab-triage", "0 9 * * *", iso(Date.now() + HOUR), { description: JSON.stringify({ goal: "triage" }) });
  const r = await post({ action: "edit", id: String(id), text: "hijack", when: "every day at 9", tz: "UTC" });
  assert.equal(r.status, 303);
  assert.match(r.location, /error=bad-request/);
  assert.equal((await sched(id)).task, "pipeline:botcron:lab-triage");
});

test("an edit of a row that is gone sends the page back with not-found", async () => {
  const r = await post({ action: "edit", id: "999999", text: "x", when: "every day at 9", tz: "UTC" });
  assert.equal(r.status, 303);
  assert.equal(r.location, "/dashboard/schedule?error=not-found");
});

/** A real (fake-express) request from the owner's laptop, carrying the session cookie. */
function realReq(body, { token } = {}) {
  return fromLaptop({
    method: "POST",
    query: {},
    body,
    dashboardSession: SESSION,
    headers: { cookie: `crow_session=${SESSION}`, ...(token ? { "x-crow-csrf": token } : {}) },
  });
}
function resStub() {
  const out = { status: 200, location: null, headersSent: false };
  out.res = {
    status(n) { out.status = n; return this; },
    set() { return this; },
    setHeader() { return this; },
    type() { return this; },
    send() { out.headersSent = true; return this; },
    json() { out.headersSent = true; return this; },
    redirect(a, b) { out.status = typeof a === "number" ? a : 302; out.location = typeof a === "number" ? b : a; out.headersSent = true; },
    redirectAfterPost(url) { out.status = 303; out.location = url; out.headersSent = true; },
  };
  return out;
}

test("the panel's client script binds the Edit sheet, stays ES5 and has no innerHTML", async () => {
  const js = scheduleClientJs();
  assert.ok(js.includes("data-sc-edit"), "the Edit link opens the sheet");
  assert.ok(js.includes("sc-edit"), "the edit sheet is a dialog like the create one");
  assert.equal(js.includes("innerHTML"), false, "no innerHTML sink");
  const code = js.slice(js.indexOf("<script>") + 8, js.lastIndexOf("</script>"));
  assert.doesNotThrow(() => new Function(code), "the generated client parses (one stray backtick breaks the page)");
});

/**
 * The emitted client script, run for real (linkedom + node:vm) over the page's own sheet markup. The
 * preview's 250 ms debounce fires at once, so the request a keystroke produced is visible to a test.
 * `fetchImpl` answers the requests (the default refuses, as an offline page would); every URL the
 * script asked for is in `sent`, in order.
 */
function clientRig(html, fetchImpl) {
  const js = scheduleClientJs();
  const code = js.slice(js.indexOf("<script>") + 8, js.lastIndexOf("</script>"));
  const { document, window } = parseHTML(`<!doctype html><html><body>${html}</body></html>`);
  const sent = [];
  const answer = fetchImpl || (() => Promise.resolve({ ok: true, json: async () => ({ ok: false, hint: "x" }) }));
  const ctx = vm.createContext({
    document, window, location: { hash: "" }, console, Intl, Math, URL, encodeURIComponent,
    setTimeout: (fn) => { fn(); return 0; },
    clearTimeout: () => {},
    fetch: (u) => { sent.push(u); return answer(u); },
  });
  vm.runInContext(code, ctx);
  return { document, window, sent };
}

/** Let the rig's promise chain (fetch → json → render) settle before a test reads its answer. */
const flush = () => new Promise((r) => setTimeout(r, 20));

test("the edit sheet's client clears the prefilled cron field when the owner types a When (create's keeps it)", async () => {
  const id = await seed("reminder:rent", "0 9 1,15 * *", iso(Date.now() + HOUR));
  const page = await call({ query: { id: `crow:${id}`, edit: "1" } });
  const rig = clientRig(`<div class="sc-page">${createSheetOf(page.html)}${sheetOf(page.html)}</div>`);
  const editWhen = rig.document.querySelector("#sc-edit [name=when]");
  const editCron = rig.document.querySelector("#sc-edit [name=cron]");
  assert.equal(editWhen.value, "", "describeCron cannot word it: When starts empty");
  assert.equal(editCron.value, "0 9 1,15 * *", "the expression sits in the cron field");

  editWhen.value = "every thursday at 8";
  editWhen.dispatchEvent(new rig.window.Event("input", { bubbles: true }));
  assert.equal(editCron.value, "", "the typed words clear the stale expression, so only they can be saved");
  assert.equal(rig.sent.length, 1, "the live preview asked the parser");
  assert.match(rig.sent[0], /when=every%20thursday%20at%208/, "about the typed words");
  assert.match(rig.sent[0], /cron=&/, "and not about the expression it just cleared");

  // Create is unchanged: there the advanced cron is the field that wins, and typing in When clears nothing.
  const createWhen = rig.document.querySelector("#sc-create [name=when]");
  const createCron = rig.document.querySelector("#sc-create [name=cron]");
  createCron.value = "0 9 * * *";
  createWhen.value = "every day at 8";
  createWhen.dispatchEvent(new rig.window.Event("input", { bubbles: true }));
  assert.equal(createCron.value, "0 9 * * *", "create keeps its rule");
});

/* ───────────────────────────── the live preview's rule ───────────────────────────── */

/**
 * clientRig over a page whose live-preview requests are answered by the panel's REAL GET route
 * (schedulePreview), so what a test reads back is exactly the answer the sheet's user would see.
 */
function previewRig(html) {
  const seen = [];
  const rig = clientRig(html, (u) => {
    const query = Object.fromEntries(new URL(u, "http://preview.test").searchParams);
    let body = null;
    const res = { set() {}, json(v) { body = v; } };
    return schedulePreview({ query }, res, db).then(() => {
      seen.push(body);
      return { ok: true, json: async () => body };
    });
  });
  return {
    ...rig,
    /** The answer the sheet's box was handed (the chain settles inside one flush). */
    async answer() { const end = Date.now() + 2000; while (!seen.length && Date.now() < end) await flush(); return seen.at(-1); },
  };
}

/** Fill BOTH of a sheet's fields and fire the preview from the LAST one (the cron field). */
function typeBoth(rig, sheetSel, { when, cron }) {
  const sheet = rig.document.querySelector(sheetSel);
  const tz = sheet.querySelector("[data-sc-tz]");
  if (tz) tz.value = "UTC";
  sheet.querySelector("[name=when]").value = when;
  const cronInput = sheet.querySelector("[name=cron]");
  cronInput.value = cron;
  cronInput.dispatchEvent(new rig.window.Event("input", { bubbles: true }));
  return sheet;
}

test("the edit sheet's LIVE preview answers with the When its Save stores (a custom cron, then a When, then a cron again)", async () => {
  const id = await seed("reminder:rent", "0 9 1,15 * *", iso(Date.now() + HOUR));
  const page = await call({ query: { id: `crow:${id}`, edit: "1" } });
  const rig = previewRig(`<div class="sc-page">${createSheetOf(page.html)}${sheetOf(page.html)}</div>`);
  const sheet = typeBoth(rig, "#sc-edit", { when: "every day at 8", cron: "0 9 1,15 * *" });
  assert.match(rig.sent[0], /mode=edit/, "the edit sheet's live preview asks under the edit rule");
  const live = await rig.answer();
  assert.equal(live.ok, true);

  // What Save stores for the very same two fields — one rule decides both.
  const saved = await editReminder(db, id, { text: "rent", when: "every day at 8", cron: "0 9 1,15 * *", tz: "UTC", lang: "en" });
  assert.equal(saved.ok, true);
  assert.equal(saved.words.cron, "0 8 * * *", "Save stored the typed When");
  assert.equal(live.summary, saved.words.summary, "the live preview reads back what Save stores");
  assert.equal(live.summary, "Every day at 8:00 AM");
  assert.deepEqual(live.next3, saved.words.next3, "the same three next runs");
  assert.equal(live.zone, "UTC");
  assert.equal(sheet.querySelector(".sc-preview-sum b").textContent, live.summary, "and the box shows it");
});

test("the create sheet's LIVE preview is unchanged: with both fields filled the cron wins, exactly as its Save", async () => {
  const page = await call({ query: {} });
  const rig = previewRig(`<div class="sc-page">${createSheetOf(page.html)}</div>`);
  typeBoth(rig, "#sc-create", { when: "every day at 8", cron: "0 9 1,15 * *" });
  assert.equal(/[?&]mode=/.test(rig.sent[0]), false, "no mode: the create form keeps its own rule");
  const live = await rig.answer();
  assert.equal(live.ok, true);

  const saved = await createReminder(db, { text: "rent", when: "every day at 8", cron: "0 9 1,15 * *", tz: "UTC", lang: "en" });
  assert.equal(saved.ok, true);
  assert.equal(saved.words.cron, "0 9 1,15 * *", "create's Save still follows the cron field");
  assert.equal(live.summary, saved.words.summary, "the create live preview still agrees with its own Save");
  assert.notEqual(live.summary, "Every day at 8:00 AM", "the typed When is not what the create sheet reads");
});

/* ───────────────────────────── the approved copy ───────────────────────────── */

const COPY = {
  "schedule.edit": { en: "Edit", es: "Editar" },
  "schedule.editTitle": { en: "Edit reminder", es: "Editar recordatorio" },
  "schedule.toast.edited": { en: "Saved. Its next run is shown below.", es: "Guardado. Su próxima ejecución aparece abajo." },
  "schedule.toast.editedPaused": { en: "Saved. It stays paused.", es: "Guardado. Sigue en pausa." },
};

test("every edit key is in en and es with the approved words, byte for byte", () => {
  for (const [key, copy] of Object.entries(COPY)) {
    assert.ok(translations[key], `${key} exists`);
    assert.deepEqual(Object.keys(translations[key]).sort(), ["en", "es"], `${key}: exactly en and es`);
    for (const lang of ["en", "es"]) {
      assert.equal(translations[key][lang], copy[lang], `${key} [${lang}]`);
      assert.equal(t(key, lang), copy[lang], `${key} [${lang}] through t()`);
    }
  }
});