/**
 * The bell's reminder buttons: **Done** and **Stop reminding** on a fired reminder row
 * (`type = 'reminder' AND source = 'scheduler'` with a `schedule_id`) — never on a missed/failed
 * notice (`source = 'scheduler:missed'`, whose acknowledgement drives the Schedule problems strip).
 *
 *   POST /dashboard/reminders/:notificationId/done   dismiss the notification (the bell's dismiss)
 *   POST /dashboard/reminders/:notificationId/stop   pause the reminder's schedule, then dismiss
 *
 * MOUNT: inside dashboard/index.js after dashboardAuth and the real csrfMiddleware (the voice-handoffs
 * slot), and the router installs dashboardAuth on its own prefix too, so it is closed wherever it is
 * mounted. Both answer JSON: `{ ok, key, text }`, where `key` is the approved i18n key of the toast and
 * `text` its words in this dashboard's language (R3 after Done, R4 after Stop, R8 when Stop is refused).
 *
 * WHO MAY ACT: the owner at this instance's own sign-in — the same rule the Schedule panel's writes use
 * (`isLocalPasswordSessionOn`, local-session.js: never a peer-signed call, a session a peer's SSO minted,
 * or a request from this machine itself). `dashboardAuth` alone also admits SSO sessions, so each route
 * asks again for itself FIRST — before the language setting is read or the id is validated, so a
 * non-owner always gets the same 403 `not_owner` whatever the id in the path looks like.
 *
 * STOP decides from the CURRENT rows, never from what the page showed: the notification must still be a
 * fired reminder, its schedule must still exist and still be a reminder, and it must be recurring
 * (`cron_expression != '@once'`). Anything else is R8 — the reminder changed under the page. A schedule
 * that is already paused SUCCEEDS (pauseSchedule is idempotent: same result, same toast).
 */
import { Router } from "express";
import { createDbClient } from "../../db.js";
import { pauseSchedule } from "../schedule-actions.js";
import { isLocalPasswordSessionOn } from "../dashboard/local-session.js";
import { readSetting } from "../dashboard/settings/registry.js";
import { t, SUPPORTED_LANGS } from "../dashboard/shared/i18n.js";
import { ONCE, scheduleKind } from "../../shared/schedule-core.js";
import { isFiredReminder } from "./notifications.js";

const P = "/dashboard/reminders";

/** The words each answer carries. Approved copy (the private engineering notes, #72 R3/R4/R8). */
const DONE_KEY = "notif.reminderDoneToast";
const STOPPED_KEY = "notif.reminderStoppedToast";
const REFUSED_KEY = "notif.reminderStopRefused";

/** The dashboard's language, "en" when the setting is unset or unknown. */
async function pageLang(db) {
  let lang = null;
  try { lang = await readSetting(db, "language"); } catch { lang = null; }
  return SUPPORTED_LANGS.includes(lang) ? lang : "en";
}

/** A positive integer notification id from the path, or null. */
function idOf(raw) {
  return typeof raw === "string" && /^\d{1,12}$/.test(raw) ? Number(raw) : null;
}

/** `{ ok, key, text }` in the dashboard's language. */
const answer = (lang, key, extra = {}) => ({ ok: true, key, text: t(key, lang), ...extra });

export function remindersRouter(dashboardAuth, { openDb = () => createDbClient() } = {}) {
  const router = Router();
  router.use(P, dashboardAuth);

  /** The owner's own turn, before anything is read. */
  const ownerOnly = async (db, req, res) => {
    if (await isLocalPasswordSessionOn(db, req)) return false;
    res.status(403).json({ ok: false, error: "not_owner" });
    return true;
  };

  /** The notification row, read fresh: { id, type, source, schedule_id } or null. */
  const notificationOf = async (db, id) => {
    const { rows } = await db.execute({
      sql: "SELECT id, type, source, schedule_id FROM notifications WHERE id = ?",
      args: [id],
    });
    return rows[0] || null;
  };

  /** Dismiss: exactly what the bell's dismiss does (routes/notifications.js). */
  const dismiss = (db, id) =>
    db.execute({ sql: "UPDATE notifications SET is_dismissed = 1, updated_at = datetime('now') WHERE id = ?", args: [id] });

  router.post(`${P}/:notificationId/done`, async (req, res) => {
    const db = openDb();
    try {
      if (await ownerOnly(db, req, res)) return undefined;
      const lang = await pageLang(db);
      const id = idOf(String(req.params.notificationId));
      if (!id) return res.status(404).json({ ok: false, error: "not_found" });
      const row = await notificationOf(db, id);
      // Only a fired reminder row reaches this verb (it is the only row the bell offers it on): a
      // missed/failed notice is acknowledged from the Schedule problems strip, not from here.
      if (!isFiredReminder(row)) return res.status(404).json({ ok: false, error: "not_found" });
      // Done dismisses only: a recurring reminder KEEPS its schedule (Stop is the other button).
      await dismiss(db, id);
      return res.json(answer(lang, DONE_KEY));
    } catch (err) {
      console.warn(`[reminders] done: ${err?.message || err}`);
      return res.status(500).json({ ok: false, error: "internal" });
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  router.post(`${P}/:notificationId/stop`, async (req, res) => {
    const db = openDb();
    try {
      if (await ownerOnly(db, req, res)) return undefined;
      const lang = await pageLang(db);
      const refused = () => res.status(409).json({ ok: false, error: "changed", key: REFUSED_KEY, text: t(REFUSED_KEY, lang) });
      const id = idOf(String(req.params.notificationId));
      if (!id) return refused();
      const row = await notificationOf(db, id);
      if (!isFiredReminder(row)) return refused();
      const scheduleId = Number(row.schedule_id);
      const changes = await db.execute({
        sql: "SELECT id, task, cron_expression FROM schedules WHERE id = ?",
        args: [scheduleId],
      });
      const schedule = changes.rows[0] || null;
      // Gone, no longer a reminder, or a one-off (nothing repeats, so there is nothing to stop): R8.
      if (!schedule || scheduleKind(schedule.task) !== "reminder" || schedule.cron_expression === ONCE) return refused();
      // pauseSchedule re-reads the row itself and decides from its CURRENT task; an already-paused
      // schedule is a success (the same UPDATE, the same answer). A refusal means the row changed
      // between the two reads, or it is owned elsewhere now (News, a report): R8.
      const paused = await pauseSchedule(db, scheduleId);
      if (!paused.ok) return refused();
      await dismiss(db, id);
      return res.json(answer(lang, STOPPED_KEY));
    } catch (err) {
      console.warn(`[reminders] stop: ${err?.message || err}`);
      return res.status(500).json({ ok: false, error: "internal" });
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  return router;
}

export default remindersRouter;